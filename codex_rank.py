"""Send a (component, candidate-list) pair to OpenAI Codex CLI and parse the Top-10 ranking.

Why subprocess instead of a direct HTTP call?
---------------------------------------------
Codex CLI authenticates via ChatGPT Plus / Pro subscription (`auth_mode: chatgpt`
in `~/.codex/auth.json`). The subscription endpoint is `chatgpt.com/backend-api/...`,
which is internal — there is no public REST surface we can hit directly. Reusing
the CLI keeps us on a supported path.

Two gotchas we hit and worked around:

1. `codex exec "<prompt>"` reads from stdin even when a prompt is given as an
   argument ("Reading additional input from stdin..."). When invoked from a
   pipeline or background shell with stdin attached, it hangs forever. We pass
   ``stdin=DEVNULL`` to close stdin explicitly.

2. ``--output-schema`` requires the OpenAI Structured Outputs format: every
   ``object`` must declare ``additionalProperties: false`` AND list every key in
   ``required``. The schema generated below conforms.

Tunables surfaced via env vars:
- ``CODEX_MODEL``     -> ``-m`` flag (default: codex CLI default model)
- ``CODEX_TIMEOUT``   -> per-call subprocess timeout in seconds (default 180)
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from pre_filter import Candidate, Component


DEFAULT_MODEL = os.environ.get("CODEX_MODEL", "")  # empty -> let codex pick
DEFAULT_TIMEOUT_SEC = int(os.environ.get("CODEX_TIMEOUT", "180"))
CODEX_BIN = os.environ.get("CODEX_BIN", "codex")
RETRY_BACKOFF_SEC = (5, 15, 30)


class RateLimitedError(Exception):
    def __init__(self, msg: str, wait: float = 60.0):
        super().__init__(msg)
        self.wait = wait


@dataclass
class Ranked:
    cpe: str
    score: float
    rationale: str


# ---------- prompt + schema ----------------------------------------------------------------

PROMPT_HEADER = """You are a CPE mapping expert. Given an SBOM component and a list of \
candidate CPEs from the NVD CPE Dictionary, return the 10 most likely matches \
ranked by likelihood. Reasoning order: vendor match > product match > version match. \
Prefer non-deprecated CPEs over deprecated ones unless the deprecated one is the \
clearer match.

Return ONLY a JSON object matching the supplied schema. Every "cpe" string MUST \
come verbatim from the candidate list below. If fewer than 10 plausible candidates \
exist, fill remaining slots with cpe="" and rationale="no good match" (score 0).
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


def build_output_schema() -> dict:
    """OpenAI Structured Outputs schema for the Top-10 response."""
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "ranked": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "cpe": {"type": "string"},
                        "score": {"type": "number"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["cpe", "score", "rationale"],
                },
            }
        },
        "required": ["ranked"],
    }


# ---------- subprocess invocation ----------------------------------------------------------

def _invoke_codex(prompt: str, schema: dict, *, model: str, timeout: int) -> str:
    """Run `codex exec` once, return the contents of --output-last-message file."""
    with tempfile.TemporaryDirectory(prefix="codex_rank_") as tmp:
        schema_path = Path(tmp) / "schema.json"
        out_path = Path(tmp) / "out.txt"
        schema_path.write_text(json.dumps(schema))

        cmd = [
            CODEX_BIN, "exec",
            "--skip-git-repo-check",
            "--output-schema", str(schema_path),
            "--output-last-message", str(out_path),
        ]
        if model:
            cmd.extend(["-m", model])
        cmd.append(prompt)

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,           # critical: codex exec reads stdin even with prompt arg
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            tail = proc.stdout.decode("utf-8", errors="replace")[-1500:]
            # Cheap rate-limit detection on subscription tier.
            low = tail.lower()
            if "rate limit" in low or "429" in low or "quota" in low or "too many" in low:
                raise RateLimitedError(f"codex returned non-zero with rate-limit signal:\n{tail}", wait=60.0)
            raise RuntimeError(f"codex exec failed (rc={proc.returncode}):\n{tail}")

        if not out_path.exists():
            raise RuntimeError(
                f"codex exec wrote no output file. stdout tail:\n"
                + proc.stdout.decode("utf-8", errors="replace")[-1500:]
            )
        return out_path.read_text(encoding="utf-8")


# ---------- output parsing -----------------------------------------------------------------

def _parse_ranked(text: str) -> list[Ranked]:
    text = text.strip()
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError(f"expected object, got {type(obj).__name__}: {text[:200]!r}")
    ranked = obj.get("ranked")
    if not isinstance(ranked, list):
        raise ValueError(f"missing 'ranked' list: {text[:200]!r}")
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

def rank_with_codex(
    comp: Component,
    candidates: Sequence[Candidate],
    *,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT_SEC,
    max_attempts: int = 3,
) -> tuple[list[Ranked], dict]:
    if not candidates:
        return (
            [Ranked(cpe="", score=0.0, rationale="no candidates") for _ in range(10)],
            {"source": "no_candidates", "model": model or "codex-default", "elapsed_sec": 0.0, "fallback": True},
        )

    allowed = {c.cpe_name for c in candidates}
    schema = build_output_schema()
    prompt = build_prompt(comp, candidates)

    last_err: Exception | None = None
    started = time.time()
    for attempt in range(max_attempts):
        try:
            response_text = _invoke_codex(prompt, schema, model=model, timeout=timeout)
            ranked = _parse_ranked(response_text)
            validated = _validate_ranked(ranked, allowed)
            elapsed = time.time() - started
            return validated, {
                "source": "codex",
                "model": model or "codex-default",
                "elapsed_sec": round(elapsed, 2),
                "fallback": False,
                "attempt": attempt + 1,
            }
        except RateLimitedError as e:
            last_err = e
            time.sleep(e.wait)
        except Exception as e:
            last_err = e
            wait = RETRY_BACKOFF_SEC[min(attempt, len(RETRY_BACKOFF_SEC) - 1)]
            time.sleep(wait)
            if attempt + 1 < max_attempts:
                prompt = (
                    "STRICT MODE: previous attempt failed validation. "
                    "Output only the JSON object matching the schema. "
                    "Use cpe strings verbatim from the candidate list.\n\n"
                    + prompt
                )

    fallback: list[Ranked] = []
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
        "model": model or "codex-default",
        "elapsed_sec": round(elapsed, 2),
        "fallback": True,
        "error": str(last_err)[:200] if last_err else None,
    }


# ---------- CLI smoke-test -----------------------------------------------------------------

def main() -> None:
    import argparse
    import sqlite3
    from dataclasses import asdict
    from pre_filter import _component_from_sbom_entry, find_candidates

    p = argparse.ArgumentParser(description="Smoke-test Codex ranking on one SBOM component")
    p.add_argument("--db", default="data/nvd_cpe.sqlite")
    p.add_argument("--sbom", default="EMBA_cyclonedx_sbom.json")
    p.add_argument("--name", required=True)
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
    print(f"retrieved {len(candidates)} candidates; calling Codex (model={args.model or 'default'})...")
    ranked, meta = rank_with_codex(comp, candidates, model=args.model)
    print(json.dumps({"meta": meta, "ranked": [asdict(r) for r in ranked]}, indent=2))


if __name__ == "__main__":
    main()
