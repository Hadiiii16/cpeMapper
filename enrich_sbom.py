"""Main orchestrator: read SBOM, attach Top-10 NVD CPE candidates to each component.

Pipeline per component:
    1. Build a Component dataclass from the SBOM entry.
    2. Look up cached result in run_cache.sqlite. Skip work if hit.
    3. Otherwise: pre_filter.find_candidates -> gemini_rank.rank_with_gemini.
    4. Persist result in cache.
    5. Append properties to the component.

Annotated SBOM is written next to the input as <input>.enriched.json (configurable).
The original `cpe` field on each component is left untouched.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv
from tqdm import tqdm

from pre_filter import (
    Candidate,
    Component,
    _component_from_sbom_entry,
    find_candidates,
)
from gemini_rank import DEFAULT_MODEL as GEMINI_DEFAULT_MODEL, Ranked, rank_with_gemini
from codex_rank import DEFAULT_MODEL as CODEX_DEFAULT_MODEL, rank_with_codex


# ---------- deterministic ranker -----------------------------------------------------------

def rank_deterministic(comp: Component, candidates: list[Candidate]) -> tuple[list[Ranked], dict]:
    """Pick the Top-10 directly from pre_filter scores.

    No LLM call. Score components are already baked into Candidate.score:
        retrieval pass base + version bonus * deprecation penalty + CVE attribution bonus.

    The caller assumes `candidates` is already sorted by score descending
    (find_candidates -> select_topn does this).

    Score normalization for the public Ranked.score: a Top-50 candidate's raw
    score lives in roughly [0, 14] (Pass 1 base 3 + version exact 5 + CVE bonus 3
    + a few minor signals). We map to [0, 1] with a soft compression so 0.85+
    correlates with "exact version + canonical (vendor, product) + ≥10 CVEs".
    """
    if not candidates:
        return (
            [Ranked(cpe="", score=0.0, rationale="no candidates") for _ in range(10)],
            {"source": "no_candidates", "model": "deterministic", "elapsed_sec": 0.0, "fallback": False,
             "top_raw_score": 0.0},
        )

    raw_max = 12.0  # rough upper bound; clamp+normalize below
    ranked: list[Ranked] = []
    for c in candidates[:10]:
        norm = max(0.0, min(1.0, c.score / raw_max))
        rationale = c.rationale or f"pass {c.pass_id} retrieval"
        ranked.append(Ranked(cpe=c.cpe_name, score=round(norm, 3), rationale=rationale[:120]))
    while len(ranked) < 10:
        ranked.append(Ranked(cpe="", score=0.0, rationale="no good match"))
    return ranked, {
        "source": "deterministic",
        "model": "deterministic",
        "elapsed_sec": 0.0,
        "fallback": False,
        "candidates_considered": len(candidates),
        "top_raw_score": round(candidates[0].score, 3) if candidates else 0.0,
    }


CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    bom_ref     TEXT NOT NULL,
    input_hash  TEXT NOT NULL,
    result_json TEXT NOT NULL,
    meta_json   TEXT NOT NULL,
    model       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (bom_ref, input_hash)
);
"""

# Single shared sqlite3.Connection across worker threads needs a lock — concurrent
# implicit-BEGIN inserts otherwise raise "cannot start a transaction within a transaction".
_CACHE_LOCK = threading.Lock()

UPSTREAM_PREFIX = "EMBA:cpe_upstream:"
UPSTREAM_CPE_KEY       = f"{UPSTREAM_PREFIX}cpe"
UPSTREAM_SCORE_KEY     = f"{UPSTREAM_PREFIX}score"
UPSTREAM_STATUS_KEY    = f"{UPSTREAM_PREFIX}status"
UPSTREAM_SOURCE_KEY    = f"{UPSTREAM_PREFIX}source"
UPSTREAM_RATIONALE_KEY = f"{UPSTREAM_PREFIX}rationale"

# Legacy Top-10 candidates prefix retained only to strip old annotations on re-run.
CANDIDATE_PREFIX = "EMBA:cpe_candidates:"

# Raw-score cutoff below which Top-1 is marked low_confidence. 8.0 corresponds
# roughly to "exact (vendor, product) + EXACT version + at least one CVE
# attribution" — i.e. the minimum for trusting Top-1 without human review.
# Empirically this filters out substring/version-coincidence false positives
# (e.g. alsa-lib -> libpng:libpng:1.0.28, breakpad-wrapper -> jenkins:vboxwrapper)
# while keeping all known-correct upstream picks (busybox, openssl, dropbear,
# gnutls, dnsmasq) safely above the threshold.
LOW_CONFIDENCE_RAW = 8.0


# ---------- cache ---------------------------------------------------------------------------

def open_cache(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.executescript(CACHE_SCHEMA)
    return conn


def _input_hash(comp: Component, candidates: list[Candidate], model: str) -> str:
    payload = {
        "name": comp.name,
        "version": comp.version,
        "group": comp.group,
        "cpe": comp.cpe,
        "purl": comp.purl,
        "supplier": comp.supplier,
        "candidates": [c.cpe_name for c in candidates],
        "model": model,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def cache_lookup(
    cache: sqlite3.Connection, bom_ref: str, input_hash: str
) -> tuple[list[Ranked], dict] | None:
    with _CACHE_LOCK:
        row = cache.execute(
            "SELECT result_json, meta_json FROM results WHERE bom_ref=? AND input_hash=?",
            (bom_ref, input_hash),
        ).fetchone()
    if not row:
        return None
    try:
        ranked = [Ranked(**r) for r in json.loads(row[0])]
        meta = json.loads(row[1])
    except Exception:
        return None
    return ranked, meta


def cache_store(
    cache: sqlite3.Connection,
    bom_ref: str,
    input_hash: str,
    ranked: list[Ranked],
    meta: dict,
    model: str,
) -> None:
    with _CACHE_LOCK:
        cache.execute(
            "INSERT OR REPLACE INTO results(bom_ref, input_hash, result_json, meta_json, model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                bom_ref,
                input_hash,
                json.dumps([asdict(r) for r in ranked], ensure_ascii=False),
                json.dumps(meta, ensure_ascii=False),
                model,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        cache.commit()


# ---------- per-component processing -------------------------------------------------------

def process_one(
    entry: dict,
    nvd_conn: sqlite3.Connection,
    cache_conn: sqlite3.Connection,
    *,
    top: int,
    model: str,
    timeout: int,
    backend: str = "gemini",
) -> dict:
    """Returns a dict with keys: bom_ref, name, status, ranked (list of Ranked dicts), meta."""
    comp = _component_from_sbom_entry(entry)
    bom_ref = comp.bom_ref or comp.name

    _, candidates = find_candidates(nvd_conn, comp, top_n=top)
    # Cache key includes backend so switching backends doesn't reuse old answers.
    in_hash = _input_hash(comp, candidates, f"{backend}:{model}")

    cached = cache_lookup(cache_conn, bom_ref, in_hash)
    if cached:
        ranked, meta = cached
        meta = {**meta, "from_cache": True}
        status = "cached"
    else:
        if not candidates:
            ranked = [Ranked(cpe="", score=0.0, rationale="no candidates") for _ in range(10)]
            meta = {"source": "no_candidates", "model": model, "fallback": True, "elapsed_sec": 0.0}
            status = "no_candidates"
        else:
            if backend == "deterministic":
                ranked, meta = rank_deterministic(comp, candidates)
            elif backend == "codex":
                ranked, meta = rank_with_codex(comp, candidates, model=model, timeout=timeout)
            else:
                ranked, meta = rank_with_gemini(comp, candidates, model=model, timeout=timeout)
            status = meta.get("source", "unknown")
        cache_store(cache_conn, bom_ref, in_hash, ranked, meta, f"{backend}:{model}")

    return {
        "bom_ref": bom_ref,
        "name": comp.name,
        "status": status,
        "ranked": [asdict(r) for r in ranked],
        "meta": meta,
        "candidate_count": len(candidates),
    }


# ---------- annotation ----------------------------------------------------------------------

def _strip_old_props(props: list[dict]) -> list[dict]:
    """Remove any prior EMBA annotations and the matching syft:cpe23 property we own.

    We strip exactly the syft:cpe23 entry whose value equals the previously stored
    EMBA:cpe_upstream:cpe, so re-runs replace our annotation without disturbing
    any other syft:cpe23 entries (e.g. ones Syft itself may have produced).
    """
    prior_upstream_cpe = next(
        (p.get("value") for p in props
         if isinstance(p, dict) and p.get("name") == UPSTREAM_CPE_KEY),
        "",
    )
    keep: list[dict] = []
    for p in props:
        if not isinstance(p, dict):
            keep.append(p)
            continue
        name = p.get("name") or ""
        if name.startswith(CANDIDATE_PREFIX) or name.startswith(UPSTREAM_PREFIX):
            continue
        if name == "syft:cpe23" and prior_upstream_cpe and p.get("value") == prior_upstream_cpe:
            continue
        keep.append(p)
    return keep


def annotate_entry(entry: dict, ranked: list[dict], status: str, meta: dict) -> None:
    """Attach a single upstream-CPE annotation derived from Top-1 of `ranked`.

    Reads:
      * ranked[0] — the highest-scoring candidate (or empty cpe if none)
      * meta["top_raw_score"] — pre-normalization score used to decide low_confidence
      * meta["model"], meta["source"] — for provenance

    Writes (preserves the original `cpe` field on the component):
      EMBA:cpe_upstream:cpe        canonical CPE pick
      EMBA:cpe_upstream:score      normalized [0..1]
      EMBA:cpe_upstream:status     deterministic | low_confidence | no_candidates
      EMBA:cpe_upstream:source     "<model>@<date> via <source>"
      EMBA:cpe_upstream:rationale  score reasoning text (<=120 chars)
    """
    props = entry.get("properties")
    if not isinstance(props, list):
        props = []
    props = _strip_old_props(props)

    top = ranked[0] if ranked else {"cpe": "", "score": 0.0, "rationale": ""}
    cpe = top.get("cpe", "") or ""
    try:
        score = float(top.get("score", 0.0))
    except (TypeError, ValueError):
        score = 0.0
    rationale = (top.get("rationale", "") or "")[:120]
    raw_score = float(meta.get("top_raw_score", 0.0) or 0.0)

    # Promote status to low_confidence when raw_score is below the cutoff and we
    # did produce a CPE. no_candidates / fallback statuses pass through unchanged.
    final_status = status
    if status == "deterministic" and cpe and raw_score < LOW_CONFIDENCE_RAW:
        final_status = "low_confidence"

    src_label = (
        f"{meta.get('model', '')}@{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        f" via {meta.get('source', 'unknown')}"
    )

    props.append({"name": UPSTREAM_CPE_KEY,       "value": cpe})
    props.append({"name": UPSTREAM_SCORE_KEY,     "value": f"{score:.3f}"})
    props.append({"name": UPSTREAM_STATUS_KEY,    "value": final_status})
    props.append({"name": UPSTREAM_SOURCE_KEY,    "value": src_label})
    props.append({"name": UPSTREAM_RATIONALE_KEY, "value": rationale})

    # Mirror the canonical CPE into Syft's convention. Grype's CycloneDX adapter
    # reads syft:cpe23 properties and includes them in its CPE matcher set when
    # the SBOM is produced by Syft (see metadata.tools registration in run()).
    #
    # Emission rules:
    #   1. status must be "deterministic" — low_confidence picks are too often
    #      wrong (e.g. kmod-* -> qualcomm/libmikmod/oracle) and would inflate
    #      grype with vendor-wide CVE noise.
    #   2. cpe must differ from the existing component cpe (avoid dup).
    #   3. The component must not be a kernel module package (kmod-*). On OpenWrt
    #      every kernel module ships as a separate package, but they all share
    #      the same linux:linux_kernel CPE. Emitting that CPE on every one
    #      causes the kernel's full CVE set to be duplicated across dozens of
    #      "components" downstream. The main 'kernel' component carries the
    #      kernel CPE; modules ride along with it.
    name = (entry.get("name") or "").lower()
    is_kernel_module = name.startswith("kmod-")
    if (final_status == "deterministic"
            and cpe
            and cpe != (entry.get("cpe") or "")
            and not is_kernel_module):
        props.append({"name": "syft:cpe23", "value": cpe})

    entry["properties"] = props


# ---------- driver --------------------------------------------------------------------------

def run(
    sbom_path: Path,
    output_path: Path,
    nvd_db: Path,
    cache_db: Path,
    *,
    top: int,
    model: str,
    concurrency: int,
    timeout: int,
    limit: int | None,
    name_filter: str | None,
    log_path: Path,
    backend: str = "gemini",
) -> None:
    if not nvd_db.exists():
        print(f"NVD CPE DB not found at {nvd_db}. Run download_nvd_cpe.py first.", file=sys.stderr)
        sys.exit(2)

    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("starting enrich; sbom=%s output=%s top=%d backend=%s model=%s concurrency=%d",
                 sbom_path, output_path, top, backend, model, concurrency)

    sbom = json.loads(sbom_path.read_text())
    components = sbom.get("components", [])
    if name_filter:
        components_to_process = [c for c in components if c.get("name") == name_filter]
    elif limit:
        components_to_process = components[:limit]
    else:
        components_to_process = components

    nvd_conn = sqlite3.connect(nvd_db, check_same_thread=False)
    nvd_conn.execute("PRAGMA query_only = ON;")
    cache_conn = open_cache(cache_db)

    results_by_ref: dict[str, dict] = {}
    failures: list[dict] = []

    pbar = tqdm(total=len(components_to_process), unit="comp", desc="enrich")
    interrupted = {"flag": False}

    def _on_sigint(signum, frame):
        interrupted["flag"] = True
        print("\n[interrupt] finishing in-flight tasks...", file=sys.stderr)
    signal.signal(signal.SIGINT, _on_sigint)

    if concurrency <= 1:
        for entry in components_to_process:
            if interrupted["flag"]:
                break
            try:
                r = process_one(entry, nvd_conn, cache_conn,
                                top=top, model=model, timeout=timeout, backend=backend)
                results_by_ref[r["bom_ref"]] = r
                logging.info("ok bom_ref=%s status=%s cands=%d",
                             r["bom_ref"], r["status"], r["candidate_count"])
            except Exception as e:
                failures.append({"name": entry.get("name"), "error": str(e)[:300]})
                logging.exception("fail bom_ref=%s", entry.get("bom-ref"))
            pbar.update(1)
    else:
        # ThreadPoolExecutor: subprocess + I/O bound, GIL is fine here.
        with cf.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(process_one, entry, nvd_conn, cache_conn,
                            top=top, model=model, timeout=timeout, backend=backend): entry
                for entry in components_to_process
            }
            for fut in cf.as_completed(futures):
                if interrupted["flag"]:
                    fut.cancel()
                    continue
                entry = futures[fut]
                try:
                    r = fut.result()
                    results_by_ref[r["bom_ref"]] = r
                    logging.info("ok bom_ref=%s status=%s cands=%d",
                                 r["bom_ref"], r["status"], r["candidate_count"])
                except Exception as e:
                    failures.append({"name": entry.get("name"), "error": str(e)[:300]})
                    logging.exception("fail bom_ref=%s", entry.get("bom-ref"))
                pbar.update(1)
    pbar.close()
    nvd_conn.close()
    cache_conn.close()

    # Apply annotations into the SBOM (operate on the full component list, not just processed subset)
    for entry in components:
        ref = entry.get("bom-ref") or entry.get("name")
        r = results_by_ref.get(ref)
        if not r:
            continue  # not processed in this run; leave as-is
        annotate_entry(entry, r["ranked"], r["status"], r["meta"])

    # Register Syft as a producing tool. Grype's CycloneDX adapter routes the
    # parse through its Syft decoder when this is present, which is the path
    # that reads the syft:cpe23 properties we wrote during annotation.
    _ensure_syft_metadata_tool(sbom)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2))

    print(f"\nWrote {output_path} ({len(results_by_ref)} components annotated; {len(failures)} failures)")
    if failures:
        print(f"  See {log_path} for details. First 5 failures:")
        for f in failures[:5]:
            print("   -", f)


def _ensure_syft_metadata_tool(sbom: dict) -> None:
    """Ensure metadata.tools lists Syft so grype routes through its Syft adapter.

    CycloneDX 1.5 allows tools as either an array (older shape) or an object
    with `components`/`services` arrays (newer shape). We handle both.
    """
    entry_legacy = {"vendor": "anchore", "name": "syft", "version": "cpe-mapper"}
    entry_modern = {"type": "application", "author": "anchore", "name": "syft", "version": "cpe-mapper"}
    md = sbom.setdefault("metadata", {})
    tools = md.get("tools")
    if isinstance(tools, list):
        if not any(isinstance(t, dict) and t.get("name") == "syft" for t in tools):
            tools.append(entry_legacy)
    elif isinstance(tools, dict):
        comps = tools.setdefault("components", [])
        if not any(isinstance(t, dict) and t.get("name") == "syft" for t in comps):
            comps.append(entry_modern)
    else:
        md["tools"] = [entry_legacy]


def cmd_reannotate(input_path: Path, output_path: Path, cache_db: Path, backend: str) -> None:
    """Fast path: re-emit annotations from cached results without running pre_filter.

    Use when only the annotation schema or the LOW_CONFIDENCE_RAW threshold has
    changed and the underlying (component -> candidates -> ranked) work in the
    cache is still valid. Skips the 1-2s/component SQL+rapidfuzz work that
    `run()` does even on cache hits.
    """
    if not cache_db.exists():
        raise SystemExit(f"cache DB not found: {cache_db}")
    sbom = json.loads(input_path.read_text())
    cache = sqlite3.connect(cache_db)

    annotated = 0
    skipped = 0
    for entry in sbom.get("components", []):
        ref = entry.get("bom-ref") or entry.get("name")
        if not ref:
            skipped += 1
            continue
        row = cache.execute(
            "SELECT result_json, meta_json FROM results "
            "WHERE bom_ref=? AND model LIKE ? "
            "ORDER BY created_at DESC LIMIT 1",
            (ref, f"{backend}:%"),
        ).fetchone()
        if not row:
            skipped += 1
            continue
        ranked = json.loads(row[0])
        meta = json.loads(row[1])
        status = meta.get("source", "unknown")
        annotate_entry(entry, ranked, status, meta)
        annotated += 1
    cache.close()

    _ensure_syft_metadata_tool(sbom)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2))
    print(f"reannotated {annotated} components; skipped {skipped}; wrote {output_path}")


def cmd_validate(output_path: Path) -> None:
    sbom = json.loads(output_path.read_text())
    comps = sbom.get("components", [])
    total = len(comps)
    annotated = 0
    status_counts: dict[str, int] = {}
    bad: list = []
    for c in comps:
        props = c.get("properties") or []
        prop_map = {p.get("name"): p.get("value") for p in props if isinstance(p, dict)}
        if UPSTREAM_STATUS_KEY in prop_map:
            annotated += 1
            status_counts[prop_map[UPSTREAM_STATUS_KEY]] = status_counts.get(prop_map[UPSTREAM_STATUS_KEY], 0) + 1
        cpe = prop_map.get(UPSTREAM_CPE_KEY, "")
        if cpe and not cpe.startswith("cpe:2.3:"):
            bad.append((c.get("name"), UPSTREAM_CPE_KEY, cpe))
    print(f"components       : {total}")
    print(f"annotated        : {annotated}")
    print(f"status histogram :")
    for k, n in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f"  {k:18s} {n}")
    print(f"bad cpe values   : {len(bad)}")
    for b in bad[:10]:
        print("  ", b)
    if total != annotated:
        print(f"  WARN: {total - annotated} components without upstream annotations")


def main() -> None:
    p = argparse.ArgumentParser(description="Enrich a CycloneDX SBOM with Top-10 NVD CPE candidates")
    p.add_argument("--input", default="EMBA_cyclonedx_sbom.json")
    p.add_argument("--output", default="EMBA_cyclonedx_sbom.enriched.json")
    p.add_argument("--nvd-db", default="data/nvd_cpe.sqlite")
    p.add_argument("--cache-db", default="data/run_cache.sqlite")
    p.add_argument("--top", type=int, default=50, help="candidates passed to the ranker")
    p.add_argument("--backend", choices=["deterministic", "gemini", "codex"], default="deterministic",
                   help="ranking backend: 'deterministic' (no LLM, scores from pre_filter + CVE attribution) "
                        "or 'gemini'/'codex' (LLM-ranked)")
    p.add_argument("--model", default=None,
                   help="override model (gemini/codex backends only); defaults: gemini=$GEMINI_MODEL, codex=$CODEX_MODEL")
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--limit", type=int, default=None, help="process only the first N components")
    p.add_argument("--name", default=None, help="process only the component(s) with this name")
    p.add_argument("--log", default="run.log")
    p.add_argument("--validate", action="store_true",
                   help="validate an already-enriched output file and exit")
    p.add_argument("--reannotate", action="store_true",
                   help="rebuild annotations from cached results (skip pre_filter / LLM)")
    args = p.parse_args()

    load_dotenv()

    if args.validate:
        cmd_validate(Path(args.output))
        return

    if args.reannotate:
        cmd_reannotate(Path(args.input), Path(args.output), Path(args.cache_db), args.backend)
        return

    model = args.model
    if model is None:
        if args.backend == "codex":
            model = CODEX_DEFAULT_MODEL
        elif args.backend == "gemini":
            model = GEMINI_DEFAULT_MODEL
        else:
            model = "deterministic"

    run(
        sbom_path=Path(args.input),
        output_path=Path(args.output),
        nvd_db=Path(args.nvd_db),
        cache_db=Path(args.cache_db),
        top=args.top,
        model=model,
        concurrency=args.concurrency,
        timeout=args.timeout,
        limit=args.limit,
        name_filter=args.name,
        log_path=Path(args.log),
        backend=args.backend,
    )


if __name__ == "__main__":
    main()
