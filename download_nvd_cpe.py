"""Download the NVD CPE Dictionary via API 2.0 into a local SQLite cache.

Usage:
    python download_nvd_cpe.py                     # full download (resumable)
    python download_nvd_cpe.py --update            # incremental (uses lastModStartDate)
    python download_nvd_cpe.py --db data/foo.sqlite

The NVD free API is rate-limited:
    - without API key: 5 requests / 30s
    - with API key   : 50 requests / 30s
We respect a per-request sleep tuned to whichever budget is in effect.

A checkpoint file (data/nvd_cpe.checkpoint.json) records the last successfully
ingested startIndex so the run is resumable across crashes / Ctrl-C.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from tqdm import tqdm


NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 10000  # API hard max
MAX_RETRIES = 5
RETRY_BACKOFF_SEC = (5, 10, 20, 40, 80)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cpe (
    cpe_name      TEXT PRIMARY KEY,
    part          TEXT NOT NULL,
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    version       TEXT NOT NULL,
    update_field  TEXT NOT NULL,
    edition       TEXT NOT NULL,
    deprecated    INTEGER NOT NULL DEFAULT 0,
    title         TEXT,
    last_modified TEXT
);
CREATE INDEX IF NOT EXISTS idx_vendor   ON cpe(vendor);
CREATE INDEX IF NOT EXISTS idx_product  ON cpe(product);
CREATE INDEX IF NOT EXISTS idx_vp       ON cpe(vendor, product);
CREATE INDEX IF NOT EXISTS idx_part     ON cpe(part);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def split_cpe(cpe: str) -> list[str] | None:
    """Split a CPE 2.3 formatted string into its 11 components, honoring backslash escapes.

    Returns None on malformed input.
    """
    if not cpe.startswith("cpe:2.3:"):
        return None
    rest = cpe[len("cpe:2.3:"):]
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == "\\" and i + 1 < len(rest):
            cur.append(c + rest[i + 1])
            i += 2
            continue
        if c == ":":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    if len(parts) != 11:
        return None
    return parts


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def upsert_cpes(conn: sqlite3.Connection, products: list[dict]) -> int:
    rows = []
    for entry in products:
        cpe = entry.get("cpe") or {}
        cpe_name = cpe.get("cpeName")
        if not cpe_name:
            continue
        parts = split_cpe(cpe_name)
        if parts is None:
            continue
        # parts: part, vendor, product, version, update, edition, lang, sw_edition, target_sw, target_hw, other
        part, vendor, product, version, update_f, edition = parts[0:6]
        deprecated = 1 if cpe.get("deprecated") else 0
        title = ""
        for t in cpe.get("titles") or []:
            if t.get("lang") == "en":
                title = t.get("title") or ""
                break
        last_mod = cpe.get("lastModified") or ""
        rows.append(
            (
                cpe_name, part, vendor, product, version, update_f, edition,
                deprecated, title, last_mod,
            )
        )
    if not rows:
        return 0
    conn.executemany(
        """
        INSERT INTO cpe (cpe_name, part, vendor, product, version, update_field, edition,
                         deprecated, title, last_modified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cpe_name) DO UPDATE SET
            part=excluded.part,
            vendor=excluded.vendor,
            product=excluded.product,
            version=excluded.version,
            update_field=excluded.update_field,
            edition=excluded.edition,
            deprecated=excluded.deprecated,
            title=excluded.title,
            last_modified=excluded.last_modified
        """,
        rows,
    )
    conn.commit()
    return len(rows)


def fetch_page(
    session: requests.Session, params: dict, headers: dict, sleep_sec: float
) -> dict:
    """Fetch one page with retries. Sleeps `sleep_sec` AFTER a successful call to respect rate-limit."""
    last_err: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            r = session.get(NVD_CPE_API, params=params, headers=headers, timeout=60)
            if r.status_code == 200:
                time.sleep(sleep_sec)
                return r.json()
            if r.status_code == 403 and "rate" in r.text.lower():
                # NVD also returns 403 on rate-limit
                wait = RETRY_BACKOFF_SEC[min(attempt, len(RETRY_BACKOFF_SEC) - 1)]
                print(f"[warn] 403 rate-limited; sleeping {wait}s (attempt {attempt+1})", file=sys.stderr)
                time.sleep(wait)
                continue
            if r.status_code in (500, 502, 503, 504):
                wait = RETRY_BACKOFF_SEC[min(attempt, len(RETRY_BACKOFF_SEC) - 1)]
                print(f"[warn] {r.status_code} server error; sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            r.raise_for_status()
        except requests.RequestException as e:
            last_err = e
            wait = RETRY_BACKOFF_SEC[min(attempt, len(RETRY_BACKOFF_SEC) - 1)]
            print(f"[warn] {type(e).__name__}: {e}; sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue
    raise RuntimeError(f"failed after {MAX_RETRIES} attempts: {last_err}")


def load_checkpoint(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def save_checkpoint(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def run_full(db_path: Path, checkpoint_path: Path, api_key: str | None) -> None:
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)

    headers = {"User-Agent": "cpe-mapper/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    # 30s window: 50 req with key, 5 req without. Use slightly safer pacing.
    sleep_sec = 0.6 if api_key else 6.0

    ckpt = load_checkpoint(checkpoint_path)
    start_index = int(ckpt.get("start_index", 0))
    total = ckpt.get("total_results")

    session = requests.Session()
    pbar = None
    try:
        while True:
            params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
            page = fetch_page(session, params, headers, sleep_sec)
            if total is None:
                total = int(page.get("totalResults", 0))
                pbar = tqdm(total=total, unit="cpe", desc="NVD CPE")
                pbar.update(start_index)
            products = page.get("products") or []
            if not products and start_index >= (total or 0):
                break
            n = upsert_cpes(conn, products)
            if pbar is not None:
                pbar.update(len(products))
            received = page.get("resultsPerPage", len(products))
            start_index += received
            ckpt = {
                "start_index": start_index,
                "total_results": total,
                "updated": datetime.now(timezone.utc).isoformat(),
                "rows_inserted_or_updated_last_page": n,
            }
            save_checkpoint(checkpoint_path, ckpt)
            if start_index >= (total or 0) or not products:
                break
    finally:
        if pbar is not None:
            pbar.close()
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('last_full_download', ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.commit()
        conn.close()


def run_update(db_path: Path, api_key: str | None, since_iso: str | None) -> None:
    """Incremental update via lastModStartDate. The window is at most 120 days per NVD docs."""
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)

    if since_iso is None:
        cur = conn.execute("SELECT value FROM meta WHERE key='last_full_download'")
        row = cur.fetchone()
        since_iso = row[0] if row else None
    if since_iso is None:
        print("no prior download timestamp found; run full download first", file=sys.stderr)
        sys.exit(2)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    headers = {"User-Agent": "cpe-mapper/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    sleep_sec = 0.6 if api_key else 6.0

    start_index = 0
    total: int | None = None
    session = requests.Session()
    pbar = None
    try:
        while True:
            params = {
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
                "lastModStartDate": since_iso,
                "lastModEndDate": now_iso,
            }
            page = fetch_page(session, params, headers, sleep_sec)
            if total is None:
                total = int(page.get("totalResults", 0))
                pbar = tqdm(total=total, unit="cpe", desc="NVD CPE update")
            products = page.get("products") or []
            upsert_cpes(conn, products)
            if pbar is not None:
                pbar.update(len(products))
            received = page.get("resultsPerPage", len(products))
            start_index += received
            if start_index >= (total or 0) or not products:
                break
    finally:
        if pbar is not None:
            pbar.close()
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('last_full_download', ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.commit()
        conn.close()


def main() -> None:
    p = argparse.ArgumentParser(description="Download NVD CPE Dictionary into SQLite")
    p.add_argument("--db", default="data/nvd_cpe.sqlite", help="SQLite output path")
    p.add_argument("--checkpoint", default="data/nvd_cpe.checkpoint.json")
    p.add_argument("--update", action="store_true", help="Incremental update only")
    p.add_argument("--since", default=None, help="ISO timestamp for --update window start")
    args = p.parse_args()

    load_dotenv()
    api_key = os.environ.get("NVD_API_KEY") or None

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    ckpt_path = Path(args.checkpoint)

    if args.update:
        run_update(db_path, api_key, args.since)
    else:
        run_full(db_path, ckpt_path, api_key)

    # Final summary
    conn = sqlite3.connect(db_path)
    total_rows = conn.execute("SELECT COUNT(*) FROM cpe").fetchone()[0]
    deprecated_rows = conn.execute("SELECT COUNT(*) FROM cpe WHERE deprecated=1").fetchone()[0]
    print(f"\nDone. Total CPEs: {total_rows} (deprecated: {deprecated_rows})")
    if total_rows < 100_000:
        print("[warn] dataset looks small; rerun if interrupted", file=sys.stderr)
    conn.close()


if __name__ == "__main__":
    main()
