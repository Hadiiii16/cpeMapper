"""Send a (component, candidate-list) pair to Gemini and parse the Top-10 ranking.

Why HTTP, not gemini-cli?
-------------------------
Gemini CLI's `--prompt` headless mode hangs without producing stdout in this
WSL2 + nvm + OAuth environment (verified across NO_RELAUNCH, GEMINI.md
neutralization, HOME isolation, PTY wrapping, stdin and stream-json variants).
A direct HTTP call to Gemini works in <2s per call. The model and prompt are
unchanged.

Two backends are supported and chosen automatically:

1. **GEMINI_API_KEY** (recommended) — Google AI Studio API key. Free tier with
   generous limits (15 RPM / 1500 RPD on flash). https://aistudio.google.com/apikey

2. **OAuth via ~/.gemini/oauth_creds.json** (the same path gemini-cli uses).
   Reuses the existing personal-account login. The Code Assist endpoint has a
   much tighter free-tier rate limit (~1 RPM seen in practice) so this path is
   only useful if the API-key route is unavailable.

Schema we ask the model for:
    {"ranked": [{"cpe": "cpe:2.3:...", "score": 0.0..1.0, "rationale": "..."}]}
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from pre_filter import Candidate, Component


# --- Generative Language API (preferred backend) ---------------------------------
GEN_LANG_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta"

# --- Code Assist API (OAuth backend, mirrors gemini-cli) -------------------------
# gemini-cli's published OAuth client (read out of its bundle).
OAUTH_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
OAUTH_CLIENT_SECRET = "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"
OAUTH_TOKEN_URI = "https://oauth2.googleapis.com/token"
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com/v1internal"
DEFAULT_CREDS_PATH = Path(os.environ.get("GEMINI_OAUTH_CREDS", "/home/ktdevice/.gemini/oauth_creds.json"))

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
DEFAULT_TIMEOUT_SEC = 120
RETRY_BACKOFF_SEC = (3, 8, 20)

# Round-robin starting offset across threads so concurrent calls hit different models.
_ROTATION_LOCK = threading.Lock()
_rotation_counter = 0


def _parse_models(model: str | Sequence[str]) -> list[str]:
    if isinstance(model, str):
        models = [m.strip() for m in model.split(",") if m.strip()]
    else:
        models = [m for m in model if m]
    return models or [DEFAULT_MODEL]


def _ordered_models(models: list[str]) -> list[str]:
    """Return models rotated so each caller starts at a different index."""
    global _rotation_counter
    if len(models) <= 1:
        return list(models)
    with _ROTATION_LOCK:
        start = _rotation_counter
        _rotation_counter += 1
    return [models[(start + i) % len(models)] for i in range(len(models))]


def _backend() -> str:
    if os.environ.get("GEMINI_API_KEY"):
        return "api_key"
    if DEFAULT_CREDS_PATH.exists():
        return "oauth"
    raise RuntimeError(
        "No Gemini auth available. Set GEMINI_API_KEY (free at https://aistudio.google.com/apikey) "
        f"or run gemini-cli once to populate {DEFAULT_CREDS_PATH}."
    )


class RateLimitedError(Exception):
    """Raised when the Code Assist API returns 429. Carries a suggested wait."""
    def __init__(self, msg: str, wait: float = 60.0):
        super().__init__(msg)
        self.wait = wait


@dataclass
class Ranked:
    cpe: str
    score: float
    rationale: str


# ---------- prompt construction ------------------------------------------------------------

PROMPT_HEADER = """You are a CPE mapping expert. Given an SBOM component and a list of \
candidate CPEs from the NVD CPE Dictionary, return the 10 most likely matches \
ranked by likelihood. Reasoning order: vendor match > product match > version match. \
Prefer non-deprecated CPEs over deprecated ones unless the deprecated one is the \
clearer match.

Output **JSON only**, no surrounding prose, no markdown fences. Schema:
{
  "ranked": [
    {"cpe": "cpe:2.3:...", "score": 0.0, "rationale": "<= 80 chars"},
    ... exactly 10 entries, ordered best -> worst
  ]
}
If fewer than 10 plausible candidates exist, fill the remaining slots with score=0 and \
rationale="no good match"; do NOT invent CPE strings outside the candidate list. Every \
"cpe" value MUST come verbatim from the candidate list below.
"""


def build_prompt(comp: Component, candidates: Sequence[Candidate]) -> str:
    sup = comp.supplier or "(unknown)"
    desc = (comp.description or "")[:300].replace("\n", " ")
    cand_lines = []
    for i, c in enumerate(candidates, 1):
        flag = " (DEPRECATED)" if c.deprecated else ""
        title = (c.title or "").replace("\n", " ")
        cand_lines.append(f"{i:>2}. {c.cpe_name}{flag} | title: {title}")
    cand_block = "\n".join(cand_lines) if cand_lines else "(none)"
    return (
        PROMPT_HEADER
        + "\n# SBOM Component\n"
        + f"- name        : {comp.name}\n"
        + f"- version     : {comp.version or ''}\n"
        + f"- group       : {comp.group or ''}\n"
        + f"- emba_cpe    : {comp.cpe or ''}\n"
        + f"- supplier    : {sup}\n"
        + f"- purl        : {comp.purl or ''}\n"
        + f"- description : {desc}\n"
        + f"\n# Candidate CPEs ({len(candidates)})\n"
        + cand_block
        + "\n\nReturn the JSON now."
    )


# ---------- credential / project caching ---------------------------------------------------

_CREDS_LOCK = threading.Lock()
_PROJECT_LOCK = threading.Lock()
_creds: Credentials | None = None
_project: str | None = None


def _load_creds() -> Credentials:
    global _creds
    with _CREDS_LOCK:
        if _creds is not None and _creds.valid:
            return _creds
        raw = json.loads(DEFAULT_CREDS_PATH.read_text())
        c = Credentials(
            token=None,  # force refresh on first use; the stored access_token may be days old
            refresh_token=raw["refresh_token"],
            client_id=OAUTH_CLIENT_ID,
            client_secret=OAUTH_CLIENT_SECRET,
            token_uri=OAUTH_TOKEN_URI,
            scopes=raw.get("scope", "").split() or ["https://www.googleapis.com/auth/cloud-platform"],
        )
        if not c.valid:
            c.refresh(Request())
        _creds = c
        return _creds


def _discover_project(creds: Credentials) -> str:
    global _project
    with _PROJECT_LOCK:
        if _project:
            return _project
        url = f"{CODE_ASSIST_ENDPOINT}:loadCodeAssist"
        headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
        body = {
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
                "duetProject": "default",
            }
        }
        r = requests.post(url, headers=headers, json=body, timeout=30)
        r.raise_for_status()
        data = r.json()
        proj = data.get("cloudaicompanionProject")
        if not proj:
            tier = data.get("currentTier") or {}
            proj = tier.get("name") or "default"
        _project = proj
        return _project


# ---------- API call ------------------------------------------------------------------------

def _check_status(r: requests.Response) -> dict:
    if r.status_code == 429:
        retry_after = r.headers.get("Retry-After")
        wait = float(retry_after) if (retry_after and retry_after.replace(".", "").isdigit()) else 60.0
        raise RateLimitedError(f"429 rate-limited; suggested wait {wait}s", wait=wait)
    r.raise_for_status()
    return r.json()


def _post_generate_api_key(prompt: str, model: str, timeout: int) -> str:
    """Call generativelanguage.googleapis.com :generateContent with API key (recommended)."""
    api_key = os.environ["GEMINI_API_KEY"]
    url = f"{GEN_LANG_ENDPOINT}/models/{model}:generateContent?key={api_key}"
    body = {
        "contents": [{"parts": [{"text": prompt}], "role": "user"}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 2048,
            "responseMimeType": "application/json",
        },
    }
    r = requests.post(url, json=body, timeout=timeout)
    data = _check_status(r)
    candidates = data.get("candidates") or []
    if not candidates:
        raise ValueError(f"no candidates in response: {json.dumps(data)[:500]}")
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(p.get("text", "") for p in parts)
    if not text:
        raise ValueError(f"empty text in response: {json.dumps(data)[:500]}")
    return text


def _post_generate_oauth(prompt: str, model: str, timeout: int) -> str:
    """Call cloudcode-pa.googleapis.com :generateContent with OAuth (mirrors gemini-cli)."""
    creds = _load_creds()
    if not creds.valid:
        creds.refresh(Request())
    project = _discover_project(creds)
    url = f"{CODE_ASSIST_ENDPOINT}:generateContent"
    headers = {"Authorization": f"Bearer {creds.token}", "Content-Type": "application/json"}
    body = {
        "model": model,
        "project": project,
        "user_prompt_id": f"cpe-rank-{int(time.time()*1000)}",
        "request": {
            "contents": [{"parts": [{"text": prompt}], "role": "user"}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
            },
        },
    }
    r = requests.post(url, headers=headers, json=body, timeout=timeout)
    if r.status_code == 401:
        creds.refresh(Request())
        headers["Authorization"] = f"Bearer {creds.token}"
        r = requests.post(url, headers=headers, json=body, timeout=timeout)
    data = _check_status(r)
    candidates = (data.get("response") or {}).get("candidates") or []
    if not candidates:
        raise ValueError(f"no candidates in response: {json.dumps(data)[:500]}")
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(p.get("text", "") for p in parts)
    if not text:
        raise ValueError(f"empty text in response: {json.dumps(data)[:500]}")
    return text


def _post_generate(prompt: str, model: str, timeout: int) -> str:
    backend = _backend()
    if backend == "api_key":
        return _post_generate_api_key(prompt, model, timeout)
    return _post_generate_oauth(prompt, model, timeout)


# ---------- output parsing -----------------------------------------------------------------

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)


def _strip_fence(text: str) -> str:
    m = _FENCE_RE.match(text)
    return m.group(1) if m else text.strip()


def _parse_ranked(text: str) -> list[Ranked]:
    text = _strip_fence(text)
    obj = None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        for m in re.finditer(r"\{.*\}", text, re.DOTALL):
            try:
                obj = json.loads(m.group(0))
                break
            except json.JSONDecodeError:
                continue
    if not isinstance(obj, dict):
        raise ValueError(f"could not parse JSON from response: {text[:300]!r}")
    ranked = obj.get("ranked")
    if not isinstance(ranked, list):
        raise ValueError("response missing 'ranked' list")
    out: list[Ranked] = []
    for item in ranked:
        if not isinstance(item, dict):
            continue
        cpe = item.get("cpe") or ""
        try:
            score = float(item.get("score", 0))
        except (TypeError, ValueError):
            score = 0.0
        rationale = (item.get("rationale") or "")[:120]
        if isinstance(cpe, str):
            out.append(Ranked(cpe=cpe, score=score, rationale=rationale))
    if not out:
        raise ValueError("ranked list was empty")
    return out


def _validate_ranked(ranked: list[Ranked], allowed: set[str]) -> list[Ranked]:
    cleaned: list[Ranked] = []
    seen: set[str] = set()
    for r in ranked:
        if r.cpe in seen:
            continue
        if r.cpe and r.cpe not in allowed:
            continue
        seen.add(r.cpe)
        cleaned.append(r)
    while len(cleaned) < 10:
        cleaned.append(Ranked(cpe="", score=0.0, rationale="no good match"))
    return cleaned[:10]


# ---------- public entrypoint --------------------------------------------------------------

def rank_with_gemini(
    comp: Component,
    candidates: Sequence[Candidate],
    *,
    model: str | Sequence[str] = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    max_attempts: int = 3,
) -> tuple[list[Ranked], dict]:
    """Rank candidates with Gemini.

    `model` may be a single name or a comma-separated list ("a,b,c") / sequence.
    With multiple models, calls round-robin across them and rotate on rate-limit
    instead of sleeping, multiplying effective throughput.
    """
    models = _parse_models(model)
    if not candidates:
        return (
            [Ranked(cpe="", score=0.0, rationale="no candidates") for _ in range(10)],
            {"source": "no_candidates", "model": models[0], "elapsed_sec": 0.0, "fallback": True},
        )

    allowed = {c.cpe_name for c in candidates}
    prompt = build_prompt(comp, candidates)

    last_err: Exception | None = None
    last_model: str = models[0]
    started = time.time()
    rate_limited: set[str] = set()
    strict_mode = False

    # Outer loop = retry passes. Inner loop = walk all models once per pass.
    for outer in range(max_attempts):
        ordered = _ordered_models(models)
        had_rate_limit_this_pass = False
        for current_model in ordered:
            if current_model in rate_limited:
                continue
            last_model = current_model
            try:
                attempt_prompt = prompt
                if strict_mode:
                    attempt_prompt = (
                        "STRICT MODE: previous attempt failed schema validation. "
                        "Output ONLY a single JSON object with key 'ranked'. No prose. "
                        "No markdown fences. Use exactly the cpe strings from the candidate list verbatim.\n\n"
                        + prompt
                    )
                response_text = _post_generate(attempt_prompt, model=current_model, timeout=timeout)
                ranked = _parse_ranked(response_text)
                validated = _validate_ranked(ranked, allowed)
                elapsed = time.time() - started
                return validated, {
                    "source": "gemini",
                    "model": current_model,
                    "elapsed_sec": round(elapsed, 2),
                    "fallback": False,
                    "attempt": outer + 1,
                    "rate_limited_models": sorted(rate_limited) or None,
                }
            except RateLimitedError as e:
                last_err = e
                rate_limited.add(current_model)
                had_rate_limit_this_pass = True
                # Don't sleep — try next model immediately.
                continue
            except Exception as e:
                last_err = e
                strict_mode = True
                # Schema/parse error: a different model is unlikely to help differently
                # without prompt tightening, so break to outer-loop sleep + strict retry.
                break
        # End of inner pass.
        if had_rate_limit_this_pass and len(rate_limited) >= len(models):
            # All models rate-limited; sleep using the most recent server hint.
            wait = last_err.wait if isinstance(last_err, RateLimitedError) else 30.0
            time.sleep(min(wait, 60.0))
            rate_limited.clear()
        elif not had_rate_limit_this_pass:
            # Schema/parse failure path — back off then retry.
            wait = RETRY_BACKOFF_SEC[min(outer, len(RETRY_BACKOFF_SEC) - 1)]
            time.sleep(wait)

    # Fallback to retrieval order so the pipeline never stalls.
    fallback = []
    for c in list(candidates)[:10]:
        fallback.append(Ranked(
            cpe=c.cpe_name,
            score=round(min(1.0, c.score / 10.0), 3),
            rationale=f"fallback (retrieval pass={c.pass_id})",
        ))
    while len(fallback) < 10:
        fallback.append(Ranked(cpe="", score=0.0, rationale="no good match"))
    elapsed = time.time() - started
    return fallback, {
        "source": "fallback",
        "model": last_model,
        "elapsed_sec": round(elapsed, 2),
        "fallback": True,
        "error": str(last_err)[:200] if last_err else None,
        "rate_limited_models": sorted(rate_limited) or None,
    }


# ---------- CLI for spot-testing -----------------------------------------------------------

def main() -> None:
    import argparse
    import sqlite3
    from pre_filter import find_candidates, _component_from_sbom_entry

    p = argparse.ArgumentParser(description="Smoke-test Gemini ranking on one SBOM component")
    p.add_argument("--db", default="data/nvd_cpe.sqlite")
    p.add_argument("--sbom", default="EMBA_cyclonedx_sbom.json")
    p.add_argument("--name", required=True, help="Component name (first match wins)")
    p.add_argument("--top", type=int, default=50)
    p.add_argument("--model", default=DEFAULT_MODEL)
    args = p.parse_args()

    sbom = json.loads(Path(args.sbom).read_text())
    target = next((c for c in sbom["components"] if c.get("name") == args.name), None)
    if not target:
        raise SystemExit(f"no component named {args.name!r}")

    comp = _component_from_sbom_entry(target)
    conn = sqlite3.connect(args.db)
    _, candidates = find_candidates(conn, comp, top_n=args.top)
    print(f"retrieved {len(candidates)} candidates; calling Gemini ({args.model})...")
    ranked, meta = rank_with_gemini(comp, candidates, model=args.model)
    print(json.dumps({"meta": meta, "ranked": [asdict(r) for r in ranked]}, indent=2))


if __name__ == "__main__":
    main()
