"""Build a (vendor, product) -> CVE count index from the NVD CVE 2.0 API.

Why we need this
----------------
The NVD CPE Dictionary contains many alias / orphan / distributor-aliased CPE
entries for the same upstream product. Most of them are NEVER referenced by an
actual CVE configuration — only one canonical (vendor, product) pair gets the
attributions.

We can decide which (vendor, product) pair is canonical empirically by
counting how often each pair appears in cpeMatch entries across all CVEs.

Pre-built once into data/nvd_cve_attribution.sqlite, this index becomes a
deterministic signal pre_filter uses to upgrade candidates that NVD actually
indexes against.

Performance
-----------
Each CVE 2.0 page fetch takes ~120 s server-side because pages are large
(2000 CVEs ≈ 30 MB). Sequentially that's ~6 hours for ~350k CVEs. Workers
fetch pages in parallel; the API rate limit (50 req / 30 s with key) is
respected via a global semaphore, but since each page is dominated by network
wait the rate limit is rarely the bottleneck. Concurrency 8 brings wall time
down to ~30-40 minutes.

Persistence is incremental: every BATCH_PERSIST pages we flush the in-memory
counter to SQLite so a crash / Ctrl-C only loses the last batch.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import requests
from dotenv import load_dotenv
from tqdm import tqdm


CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # API max; we send fewer requests with key
BATCH_PERSIST = 16       # flush counter to DB every N pages

# NVD API quotas: 50 req / 30 s with key, 5 req / 30 s without.
# We approximate by spacing out requests; the semaphore guarantees no burst.
QUOTA_WITH_KEY = (50, 30.0)
QUOTA_NO_KEY   = (5, 30.0)

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_attribution (
    vendor    TEXT NOT NULL,
    product   TEXT NOT NULL,
    cve_count INTEGER NOT NULL,
    PRIMARY KEY (vendor, product)
);
CREATE INDEX IF NOT EXISTS idx_attr_product ON cve_attribution(product);
CREATE INDEX IF NOT EXISTS idx_attr_vendor  ON cve_attribution(vendor);

CREATE TABLE IF NOT EXISTS pages_done (
    start_index INTEGER PRIMARY KEY,
    completed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.executescript(SCHEMA)
    return conn


# ---------- Sliding-window rate limiter ---------------------------------------------------

class WindowRateLimiter:
    """Allow up to `n` calls per `window` seconds across all threads."""

    def __init__(self, n: int, window: float):
        self.n = n
        self.window = window
        self.lock = threading.Lock()
        self.calls: list[float] = []

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.time()
                # drop calls older than window
                self.calls = [t for t in self.calls if now - t < self.window]
                if len(self.calls) < self.n:
                    self.calls.append(now)
                    return
                wait = self.window - (now - self.calls[0]) + 0.05
            time.sleep(max(wait, 0.05))


# ---------- CPE parsing -------------------------------------------------------------------

def split_cpe(cpe_uri: str) -> tuple[str, str, str] | None:
    """cpe:2.3:<part>:<vendor>:<product>:..."""
    if not cpe_uri.startswith("cpe:2.3:"):
        return None
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return None
    return parts[2], parts[3], parts[4]


def tally_cve_pairs(cve_obj: dict) -> Iterable[tuple[str, str]]:
    """Unique (vendor, product) pairs cited in this CVE's configurations.

    A CVE listing 12 versions of openssl:openssl is one attribution of that
    pair, not 12 — otherwise products with many version rows look artificially
    canonical.
    """
    seen: set[tuple[str, str]] = set()
    cve = cve_obj.get("cve") or {}
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                tup = split_cpe(m.get("criteria") or "")
                if not tup:
                    continue
                part, vendor, product = tup
                if part not in ("a", "o"):
                    continue  # hardware CPEs rarely matter for SBOM matching
                if not vendor or vendor == "*" or not product or product == "*":
                    continue
                seen.add((vendor, product))
    return seen


# ---------- worker -----------------------------------------------------------------------

def fetch_page(session: requests.Session, start_index: int, headers: dict, limiter: WindowRateLimiter) -> dict:
    params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
    for attempt in range(4):
        limiter.acquire()
        try:
            r = session.get(CVE_ENDPOINT, params=params, headers=headers, timeout=180)
        except requests.RequestException as e:
            wait = min(60.0, 5.0 * (attempt + 1))
            print(f"[warn] network error at startIndex={start_index} attempt={attempt+1}: {e}; sleep {wait}s",
                  file=sys.stderr)
            time.sleep(wait)
            continue
        if r.status_code == 200:
            return r.json()
        wait = max(5.0, float(r.headers.get("Retry-After") or 30))
        print(f"[warn] HTTP {r.status_code} at startIndex={start_index} attempt={attempt+1}; sleep {wait}s",
              file=sys.stderr)
        time.sleep(wait)
    raise RuntimeError(f"giving up on startIndex={start_index}")


def parse_page(page: dict) -> Counter:
    counts: Counter[tuple[str, str]] = Counter()
    for v in page.get("vulnerabilities", []):
        for pair in tally_cve_pairs(v):
            counts[pair] += 1
    return counts


# ---------- driver -----------------------------------------------------------------------

def persist_counts(conn: sqlite3.Connection, counts: Counter, total_cves: int, total_pairs: int) -> None:
    """Atomically replace the cve_attribution table with the current counts."""
    with conn:
        conn.execute("DELETE FROM cve_attribution")
        conn.executemany(
            "INSERT INTO cve_attribution(vendor, product, cve_count) VALUES (?, ?, ?)",
            [(v, p, n) for (v, p), n in counts.items()],
        )
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('updated_at', ?)",
                     (datetime.now(timezone.utc).isoformat(),))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('cves_seen', ?)", (str(total_cves),))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('pairs', ?)", (str(total_pairs),))


def run(db_path: Path, api_key: str | None, concurrency: int) -> None:
    headers = {"apiKey": api_key} if api_key else {}
    quota = QUOTA_WITH_KEY if api_key else QUOTA_NO_KEY
    limiter = WindowRateLimiter(*quota)

    conn = open_db(db_path)
    counts: Counter[tuple[str, str]] = Counter()
    # seed from DB if a previous run partially persisted
    for vendor, product, n in conn.execute("SELECT vendor, product, cve_count FROM cve_attribution"):
        counts[(vendor, product)] = int(n)
    done_indexes = {row[0] for row in conn.execute("SELECT start_index FROM pages_done")}

    # Probe page 0 just to learn totalResults.
    session = requests.Session()
    print("[info] probing total CVE count...", file=sys.stderr)
    page0 = fetch_page(session, 0, headers, limiter)
    total = int(page0.get("totalResults", 0))
    print(f"[info] total CVEs reported: {total}", file=sys.stderr)
    counts.update(parse_page(page0))
    cves_processed_now = len(page0.get("vulnerabilities", []))
    if 0 not in done_indexes:
        with conn:
            conn.execute("INSERT OR REPLACE INTO pages_done(start_index, completed_at) VALUES (0, ?)",
                         (datetime.now(timezone.utc).isoformat(),))
        done_indexes.add(0)

    # Build the work list: every 2000-aligned start_index up to total, minus done ones.
    pending = [s for s in range(RESULTS_PER_PAGE, total, RESULTS_PER_PAGE) if s not in done_indexes]
    if not pending:
        print("[info] all pages already done; just rewriting counts.", file=sys.stderr)
        persist_counts(conn, counts, total, len(counts))
        conn.close()
        return

    print(f"[info] {len(done_indexes)} pages cached, {len(pending)} to fetch with concurrency={concurrency}",
          file=sys.stderr)

    pbar = tqdm(total=total, initial=len(done_indexes) * RESULTS_PER_PAGE, unit="cve", desc="cve pages")
    counter_lock = threading.Lock()
    persisted_since = 0

    def work(start: int) -> tuple[int, Counter]:
        page = fetch_page(session, start, headers, limiter)
        return start, parse_page(page), len(page.get("vulnerabilities", []))

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(work, s): s for s in pending}
            for fut in as_completed(futures):
                start = futures[fut]
                try:
                    _, page_counts, n_cves = fut.result()
                except Exception as e:
                    print(f"[err] startIndex={start} -> {e}", file=sys.stderr)
                    continue
                with counter_lock:
                    counts.update(page_counts)
                    cves_processed_now += n_cves
                    persisted_since += 1
                    with conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO pages_done(start_index, completed_at) VALUES (?, ?)",
                            (start, datetime.now(timezone.utc).isoformat()),
                        )
                    if persisted_since >= BATCH_PERSIST:
                        persist_counts(conn, counts, cves_processed_now, len(counts))
                        persisted_since = 0
                pbar.update(n_cves)
        # final flush
        persist_counts(conn, counts, cves_processed_now, len(counts))
        print(f"\nbuilt {len(counts)} (vendor, product) pairs from ~{cves_processed_now} CVEs",
              file=sys.stderr)
    finally:
        pbar.close()
        conn.close()


def main() -> None:
    p = argparse.ArgumentParser(description="Download NVD CVEs and build (vendor,product) attribution index")
    p.add_argument("--db", default="data/nvd_cve_attribution.sqlite")
    p.add_argument("--concurrency", type=int, default=8)
    args = p.parse_args()

    load_dotenv()
    api_key = os.environ.get("NVD_API_KEY") or None
    if not api_key:
        print("[warn] NVD_API_KEY not set; download will be ~10x slower (5 req/30s).", file=sys.stderr)

    run(Path(args.db), api_key, args.concurrency)


if __name__ == "__main__":
    main()
