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
from gemini_rank import DEFAULT_MODEL, Ranked, rank_with_gemini


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

CANDIDATE_SOURCE_KEY = "EMBA:cpe_candidates:source"
CANDIDATE_STATUS_KEY = "EMBA:cpe_candidates:status"
CANDIDATE_PREFIX = "EMBA:cpe_candidates:"


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
) -> dict:
    """Returns a dict with keys: bom_ref, name, status, ranked (list of Ranked dicts), meta."""
    comp = _component_from_sbom_entry(entry)
    bom_ref = comp.bom_ref or comp.name

    _, candidates = find_candidates(nvd_conn, comp, top_n=top)
    in_hash = _input_hash(comp, candidates, model)

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
            ranked, meta = rank_with_gemini(comp, candidates, model=model, timeout=timeout)
            status = meta.get("source", "unknown")
        cache_store(cache_conn, bom_ref, in_hash, ranked, meta, model)

    return {
        "bom_ref": bom_ref,
        "name": comp.name,
        "status": status,
        "ranked": [asdict(r) for r in ranked],
        "meta": meta,
        "candidate_count": len(candidates),
    }


# ---------- annotation ----------------------------------------------------------------------

def _strip_old_candidate_props(props: list[dict]) -> list[dict]:
    return [p for p in props if not (isinstance(p, dict) and (p.get("name") or "").startswith(CANDIDATE_PREFIX))]


def annotate_entry(entry: dict, ranked: list[dict], status: str, meta: dict) -> None:
    props = entry.get("properties")
    if not isinstance(props, list):
        props = []
    props = _strip_old_candidate_props(props)

    src_label = (
        f"{meta.get('model', '')}@{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        f" via {meta.get('source', 'unknown')}"
    )
    props.append({"name": CANDIDATE_SOURCE_KEY, "value": src_label})
    props.append({"name": CANDIDATE_STATUS_KEY, "value": status})

    for i, r in enumerate(ranked, 1):
        cpe = r.get("cpe", "")
        if not cpe:
            # still record the slot so downstream can see we tried 10 ranks
            props.append({"name": f"{CANDIDATE_PREFIX}{i}:cpe", "value": ""})
            props.append({"name": f"{CANDIDATE_PREFIX}{i}:score", "value": "0"})
            props.append({"name": f"{CANDIDATE_PREFIX}{i}:rationale", "value": r.get("rationale", "")[:120]})
            continue
        props.append({"name": f"{CANDIDATE_PREFIX}{i}:cpe", "value": cpe})
        props.append({"name": f"{CANDIDATE_PREFIX}{i}:score", "value": f"{float(r.get('score', 0)):.3f}"})
        props.append({"name": f"{CANDIDATE_PREFIX}{i}:rationale", "value": (r.get("rationale", "") or "")[:120]})

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
) -> None:
    if not nvd_db.exists():
        print(f"NVD CPE DB not found at {nvd_db}. Run download_nvd_cpe.py first.", file=sys.stderr)
        sys.exit(2)

    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("starting enrich; sbom=%s output=%s top=%d model=%s concurrency=%d",
                 sbom_path, output_path, top, model, concurrency)

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
                                top=top, model=model, timeout=timeout)
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
                            top=top, model=model, timeout=timeout): entry
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

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2))

    print(f"\nWrote {output_path} ({len(results_by_ref)} components annotated; {len(failures)} failures)")
    if failures:
        print(f"  See {log_path} for details. First 5 failures:")
        for f in failures[:5]:
            print("   -", f)


def cmd_validate(output_path: Path) -> None:
    sbom = json.loads(output_path.read_text())
    comps = sbom.get("components", [])
    total = len(comps)
    annotated = 0
    bad = []
    for c in comps:
        props = c.get("properties") or []
        names = {p.get("name") for p in props if isinstance(p, dict)}
        if any(n and n.startswith(CANDIDATE_PREFIX) for n in names):
            annotated += 1
        # Sanity-check candidate cpe values
        for p in props:
            if not isinstance(p, dict):
                continue
            n = p.get("name", "")
            if n.endswith(":cpe") and n.startswith(CANDIDATE_PREFIX):
                v = p.get("value", "")
                if v and not v.startswith("cpe:2.3:"):
                    bad.append((c.get("name"), n, v))
    print(f"components: {total}")
    print(f"annotated : {annotated}")
    print(f"bad cpe values: {len(bad)}")
    for b in bad[:10]:
        print("  ", b)
    if total != annotated:
        print(f"  WARN: {total - annotated} components without candidate annotations")


def main() -> None:
    p = argparse.ArgumentParser(description="Enrich a CycloneDX SBOM with Top-10 NVD CPE candidates")
    p.add_argument("--input", default="EMBA_cyclonedx_sbom.json")
    p.add_argument("--output", default="EMBA_cyclonedx_sbom.enriched.json")
    p.add_argument("--nvd-db", default="data/nvd_cpe.sqlite")
    p.add_argument("--cache-db", default="data/run_cache.sqlite")
    p.add_argument("--top", type=int, default=50, help="candidates passed to Gemini")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--limit", type=int, default=None, help="process only the first N components")
    p.add_argument("--name", default=None, help="process only the component(s) with this name")
    p.add_argument("--log", default="run.log")
    p.add_argument("--validate", action="store_true",
                   help="validate an already-enriched output file and exit")
    args = p.parse_args()

    load_dotenv()

    if args.validate:
        cmd_validate(Path(args.output))
        return

    run(
        sbom_path=Path(args.input),
        output_path=Path(args.output),
        nvd_db=Path(args.nvd_db),
        cache_db=Path(args.cache_db),
        top=args.top,
        model=args.model,
        concurrency=args.concurrency,
        timeout=args.timeout,
        limit=args.limit,
        name_filter=args.name,
        log_path=Path(args.log),
    )


if __name__ == "__main__":
    main()
