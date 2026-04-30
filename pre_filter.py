"""Candidate retrieval: narrow the NVD CPE Dictionary to ~50 plausible matches per SBOM component.

Strategy is a 3-pass funnel:
    Pass 1 (exact)  : (vendor, product) tuples literally found in the dict
    Pass 2 (product): rows whose product matches any product-token (= or LIKE)
    Pass 3 (fuzzy)  : rapidfuzz score over the unioned pool against a synthetic query string

Anything Gemini would consider lives in this output set, so we err toward recall and
let Gemini do the precision work.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from rapidfuzz import fuzz


# Heuristics derived from inspecting the EMBA SBOM. Add to as new packages turn up.
PREFIXES_TO_DROP = (
    "kmod-", "lib", "python3-", "python-", "node-", "perl-", "ruby-",
)
SUFFIXES_TO_DROP = (
    "-utils", "-tools", "-cli", "-mod", "-dev", "-doc", "-bin", "-common",
)

# Group -> forced product candidates. EMBA tags kernel-module rows with group=linux_kernel+module
# but names like kmod-fs-msdos have nothing to do with the NVD product name; we route them to the kernel.
# A *very* limited set of group-driven hints. We deliberately do NOT inject 'openwrt' for the
# OpenWRT group: that would shove every OpenWRT-distributed package toward the openwrt CPE
# even though each package has its own upstream NVD entry (busybox, openssl, dropbear, ...).
GROUP_PRODUCT_HINTS: dict[str, tuple[str, ...]] = {
    "linux_kernel+module": ("linux_kernel",),
    "static_distri_analysis": (),
    "static_bin_analysis": (),
    "OpenWRT": (),
    "unhandled_file": (),
}

# When the SBOM component name does not match the NVD product name (very common in
# OpenWRT-style packaging), inject the canonical NVD product names too. Keyed by the
# normalized component name.
PRODUCT_ALIASES: dict[str, tuple[str, ...]] = {
    "dropbear": ("dropbear_ssh_server", "dropbear_ssh", "dropbear"),
    "libopenssl": ("openssl",),
    "libgcrypt": ("libgcrypt",),
    "libgnutls": ("gnutls",),
    "libxml2": ("libxml2",),
    "libpcap": ("libpcap",),
    "libnl": ("libnl",),
    "libcap": ("libcap",),
    "libffi": ("libffi",),
    "libpng": ("libpng",),
    "libcurl": ("libcurl", "curl"),
    "openvpn-openssl": ("openvpn",),
    "ppp": ("paul_mackerras_ppp", "ppp"),
    "ip6tables": ("iptables",),
    "iptables": ("iptables", "netfilter_iptables"),
    "isc-dhcp-relay-ipv6": ("dhcp", "isc_dhcp"),
    "ddns-scripts": ("dynamic_dns_clients",),
    "miniupnpd": ("miniupnpd",),
    "tcpdump": ("tcpdump",),
    "openswan": ("openswan",),
    "ntfs-3g": ("ntfs-3g", "ntfs_3g"),
    "lua": ("lua",),
    "iperf3": ("iperf3", "iperf"),
    "wpa_supplicant": ("wpa_supplicant", "wpa-supplicant"),
    "linux_kernel": ("linux_kernel", "kernel"),
}


# Vendor aliases EMBA gets wrong (vendor==product is the most common pattern). When
# we see one of these as the EMBA-reported vendor, also try the right one.
VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "busybox": ("busybox", "busybox_project"),
    "openssl": ("openssl", "openssl_project"),
    "libopenssl": ("openssl",),
    "dropbear": ("matt_johnston", "dropbear_ssh_project"),
    "ppp": ("ppp_project", "samba"),
    "miniupnpd": ("miniupnp_project", "miniupnp"),
    "openvpn-openssl": ("openvpn",),
    "openvpn": ("openvpn",),
    "ip6tables": ("netfilter_core_team",),
    "iptables": ("netfilter_core_team", "netfilter"),
    "lldpd": ("lldpd_project", "vincent_bernat"),
    "tcpdump": ("tcpdump",),
    "openswan": ("openswan", "xelerance"),
    "ntfs-3g": ("tuxera", "ntfs-3g"),
    "lua": ("lua",),
    "iperf3": ("iperf_project", "iperf"),
    "expat": ("libexpat_project", "expat"),
    "zlib": ("zlib", "gnu"),
    "ncurses": ("gnu",),
    "libxml2": ("xmlsoft", "gnome", "libxml2_project"),
    "uClibc": ("uclibc",),
    "wpa_supplicant": ("w1.fi", "wpa_supplicant_project"),
    "linux_kernel": ("linux", "linux_kernel"),
}


@dataclass
class Component:
    bom_ref: str
    name: str
    version: str | None = None
    group: str | None = None
    cpe: str | None = None
    purl: str | None = None
    supplier: str | None = None
    description: str | None = None


@dataclass
class Candidate:
    cpe_name: str
    part: str
    vendor: str
    product: str
    version: str
    deprecated: int
    title: str
    score: float = 0.0
    pass_id: int = 0  # 1, 2, or 3
    rationale: str = ""


# ---------- input parsing -------------------------------------------------------------------

def split_cpe(cpe: str) -> list[str] | None:
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
    return parts if len(parts) == 11 else None


def parse_purl(purl: str) -> dict:
    # pkg:opkg/openwrt/busybox@1.30.1-5&distro=openwrt
    out: dict[str, str] = {"type": "", "namespace": "", "name": "", "version": ""}
    if not purl or not purl.startswith("pkg:"):
        return out
    body = purl[4:]
    if "@" in body:
        body, _, ver = body.partition("@")
        out["version"] = ver.split("?", 1)[0].split("&", 1)[0]
    type_part, _, rest = body.partition("/")
    out["type"] = type_part
    if "/" in rest:
        ns, _, name = rest.rpartition("/")
        out["namespace"] = ns
        out["name"] = name
    else:
        out["name"] = rest
    return out


# ---------- normalization -------------------------------------------------------------------

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def norm_token(s: str) -> str:
    if not s:
        return ""
    s = s.lower().strip()
    s = _NON_ALNUM.sub("_", s)
    return s.strip("_")


def strip_pkg_decoration(name: str) -> str:
    """Remove common packaging prefixes/suffixes that hide the real product name."""
    s = name.lower()
    changed = True
    while changed:
        changed = False
        for p in PREFIXES_TO_DROP:
            if s.startswith(p) and len(s) > len(p):
                s = s[len(p):]
                changed = True
                break
        for q in SUFFIXES_TO_DROP:
            if s.endswith(q) and len(s) > len(q):
                s = s[: -len(q)]
                changed = True
                break
    return s


def normalize_version(v: str | None) -> str:
    """Strip OpenWRT/distro packaging revisions while preserving upstream suffixes.

    Examples (input -> output):
        1.30.1-5            -> 1.30.1
        1.1.1g-1            -> 1.1.1g          (the 'g' is part of the OpenSSL version)
        2019.78-2           -> 2019.78
        g5da56622b3-dirty-1 -> g5da56622b3     (git-like, won't match anything in NVD anyway)
        4.4.60              -> 4.4.60
        2015-11-08-...      -> 2015-11-08-...  (left as-is; date-stamped; will fall through to fuzzy)
    """
    if not v:
        return ""
    v = v.strip()
    # Drop a trailing "-N(.N)*" packaging revision. This keeps things like "1.1.1g" intact while
    # cleaning up "1.1.1g-1".
    v = re.sub(r"-\d+(?:\.\d+)*$", "", v)
    # Drop "-dirty" suffix common in git-described versions
    v = re.sub(r"-dirty$", "", v)
    return v


# ---------- query generation ----------------------------------------------------------------

@dataclass
class Query:
    raw_name: str
    raw_supplier: str
    vendors: list[str] = field(default_factory=list)   # ordered, deduped
    products: list[str] = field(default_factory=list)
    version_norm: str = ""
    full_text: str = ""  # for fuzzy matching


def build_query(comp: Component) -> Query:
    q = Query(raw_name=comp.name or "", raw_supplier=comp.supplier or "")

    # 1) From CPE field
    cpe_vendor = cpe_product = cpe_version = None
    if comp.cpe:
        parts = split_cpe(comp.cpe)
        if parts:
            cpe_vendor, cpe_product, cpe_version = parts[1], parts[2], parts[3]

    # 2) From purl
    purl = parse_purl(comp.purl or "")

    # 3) Stripped name
    name_stripped = strip_pkg_decoration(comp.name or "")

    # 4) Version: prefer explicit component version, fallback CPE/purl
    raw_version = comp.version or cpe_version or purl.get("version") or ""
    q.version_norm = normalize_version(raw_version)

    # vendor candidates (ordered by trust)
    vendors: list[str] = []
    def add_v(v: str | None) -> None:
        if not v:
            return
        n = norm_token(v)
        if n and n not in vendors and n != "*" and n != "_":
            vendors.append(n)

    add_v(cpe_vendor)
    add_v(purl.get("namespace"))
    add_v(comp.supplier)
    add_v(name_stripped)
    # group hints
    for hint in GROUP_PRODUCT_HINTS.get(comp.group or "", ()):
        add_v(hint)
    # vendor aliases (use the raw component name AND the cpe vendor as keys)
    for key in (norm_token(comp.name or ""), norm_token(cpe_vendor or ""), norm_token(name_stripped)):
        for alias in VENDOR_ALIASES.get(key, ()):
            add_v(alias)
    q.vendors = vendors

    # product candidates
    products: list[str] = []
    def add_p(p: str | None) -> None:
        if not p:
            return
        n = norm_token(p)
        if n and n not in products and n != "*" and n != "_":
            products.append(n)

    add_p(cpe_product)
    add_p(name_stripped)
    add_p(comp.name)
    add_p(purl.get("name"))
    for hint in GROUP_PRODUCT_HINTS.get(comp.group or "", ()):
        add_p(hint)
    # Curated aliases keyed by component name and stripped name
    for key in (norm_token(comp.name or ""), norm_token(name_stripped)):
        for alias in PRODUCT_ALIASES.get(key, ()):
            add_p(alias)
    # also try splitting on common delimiters (e.g. "openvpn-openssl" -> "openvpn", "openssl")
    for src in (comp.name or "", name_stripped):
        for piece in re.split(r"[-_. ]+", src.lower()):
            if len(piece) >= 3 and not piece.isdigit():
                add_p(piece)
    q.products = products

    q.full_text = " ".join(filter(None, [
        comp.name, name_stripped, cpe_vendor, cpe_product, comp.supplier, comp.description or "",
    ])).lower()

    return q


# ---------- DB passes -----------------------------------------------------------------------

def _row_to_candidate(row: tuple, pass_id: int, base_score: float, rationale: str) -> Candidate:
    cpe_name, part, vendor, product, version, deprecated, title = row
    return Candidate(
        cpe_name=cpe_name, part=part, vendor=vendor, product=product, version=version,
        deprecated=deprecated, title=title or "",
        score=base_score, pass_id=pass_id, rationale=rationale,
    )


def _select_columns() -> str:
    return "cpe_name, part, vendor, product, version, deprecated, COALESCE(title, '')"


def pass1_exact(conn: sqlite3.Connection, q: Query, limit: int = 5000) -> list[Candidate]:
    if not q.vendors or not q.products:
        return []
    placeholders_v = ",".join("?" * len(q.vendors))
    placeholders_p = ",".join("?" * len(q.products))
    sql = (
        f"SELECT {_select_columns()} FROM cpe "
        f"WHERE vendor IN ({placeholders_v}) AND product IN ({placeholders_p}) "
        f"LIMIT {limit}"
    )
    rows = conn.execute(sql, [*q.vendors, *q.products]).fetchall()
    return [_row_to_candidate(r, pass_id=1, base_score=3.0, rationale="exact vendor/product") for r in rows]


def pass2_product(conn: sqlite3.Connection, q: Query, limit: int = 4000) -> list[Candidate]:
    if not q.products:
        return []
    out: list[Candidate] = []
    seen: set[str] = set()
    for p in q.products:
        if not p:
            continue
        rows = conn.execute(
            f"SELECT {_select_columns()} FROM cpe "
            f"WHERE product = ? OR product LIKE ? OR product LIKE ? OR product LIKE ? "
            f"LIMIT ?",
            (p, f"{p}_%", f"%_{p}", f"%_{p}_%", limit),
        ).fetchall()
        for r in rows:
            if r[0] in seen:
                continue
            seen.add(r[0])
            out.append(_row_to_candidate(r, pass_id=2, base_score=2.0, rationale=f"product token '{p}'"))
        if len(out) >= limit:
            break
    return out


def pass3_fuzzy(
    conn: sqlite3.Connection,
    q: Query,
    pool: list[Candidate],
    pool_extra_per_token: int = 200,
) -> list[Candidate]:
    """Score the existing pool with rapidfuzz, optionally widening it via title LIKE searches."""
    seen = {c.cpe_name for c in pool}

    # Widen with title-based matches for any product token (catches cases like
    # name='Dropbear SSH Server' with NVD product='dropbear_ssh_server' but also entries that
    # don't share token segmentation).
    for p in q.products[:5]:
        if not p or len(p) < 4:
            continue
        rows = conn.execute(
            f"SELECT {_select_columns()} FROM cpe WHERE title LIKE ? LIMIT ?",
            (f"%{p.replace('_', ' ')}%", pool_extra_per_token),
        ).fetchall()
        for r in rows:
            if r[0] in seen:
                continue
            seen.add(r[0])
            pool.append(_row_to_candidate(r, pass_id=3, base_score=1.0, rationale="title match"))

    # Add a fuzzy bonus *additively* on top of the pass base score. We never want fuzzy alone
    # to overtake an exact vendor+product hit, but a strong textual match should still pull a
    # candidate up within its tier.
    query_str = q.full_text or " ".join(q.products + q.vendors)
    products_joined = " ".join(q.products)
    for c in pool:
        target = f"{c.vendor} {c.product} {c.title}".lower()
        s1 = fuzz.token_set_ratio(query_str, target) / 100.0
        s2 = fuzz.partial_ratio(c.product, products_joined) / 100.0 if products_joined else 0.0
        fuzzy = max(s1, s2)
        c.score += 0.5 * fuzzy
    return pool


def _version_proximity(cv: str, qv: str) -> float:
    """Score how close a candidate version `cv` is to query `qv`. Returns 0..1; only used as a tiebreak."""
    if not cv or cv in ("*", "-") or not qv:
        return 0.0
    cv_parts = cv.split(".")
    qv_parts = qv.split(".")
    common = 0
    for a, b in zip(cv_parts, qv_parts):
        if a == b:
            common += 1
        else:
            break
    if common == 0:
        return 0.0
    return common / max(len(cv_parts), len(qv_parts))


def apply_version_bonus(pool: list[Candidate], q: Query) -> None:
    """Boost candidates whose `version` field matches our query version. Exact match >> any other signal
    so the right CPE row bubbles to the top even when 100s of versioned siblings exist."""
    qv = q.version_norm
    for c in pool:
        cv = (c.version or "").strip()
        if not qv:
            # No query version -> mild preference for `*` (any) entries since they tend to be
            # the canonical "all versions" CPE row used when the user picks via Gemini.
            if cv in ("*", "-"):
                c.score += 0.2
                c.rationale = f"{c.rationale}; wildcard version"
            continue
        if cv == qv:
            c.score += 5.0
            c.rationale = f"{c.rationale}; EXACT version"
            continue
        if cv in ("*", "-"):
            # The `*` / `-` rows let CVE configs apply across all versions. Useful but not as
            # strong as an exact version hit.
            c.score += 0.6
            c.rationale = f"{c.rationale}; wildcard version"
            continue
        prox = _version_proximity(cv, qv)
        if prox > 0:
            c.score += 1.5 * prox  # near-version siblings (e.g. 1.30.0 when query is 1.30.1)
            c.rationale = f"{c.rationale}; version~{prox:.2f}"


def apply_deprecation_penalty(pool: list[Candidate]) -> None:
    for c in pool:
        if c.deprecated:
            c.score *= 0.85


def select_topn(pool: list[Candidate], n: int = 50) -> list[Candidate]:
    # dedupe by cpe_name keeping highest score
    best: dict[str, Candidate] = {}
    for c in pool:
        prev = best.get(c.cpe_name)
        if prev is None or c.score > prev.score:
            best[c.cpe_name] = c
    items = list(best.values())
    items.sort(key=lambda x: (-x.score, x.deprecated, x.cpe_name))
    return items[:n]


# ---------- public API ----------------------------------------------------------------------

def find_candidates(conn: sqlite3.Connection, comp: Component, top_n: int = 50) -> tuple[Query, list[Candidate]]:
    q = build_query(comp)
    pool: list[Candidate] = []
    pool.extend(pass1_exact(conn, q))
    pool.extend(pass2_product(conn, q))
    pool = pass3_fuzzy(conn, q, pool)
    apply_version_bonus(pool, q)
    apply_deprecation_penalty(pool)
    return q, select_topn(pool, top_n)


# ---------- CLI -----------------------------------------------------------------------------

def _component_from_sbom_entry(entry: dict) -> Component:
    supplier = ""
    sup = entry.get("supplier") or {}
    if isinstance(sup, dict):
        supplier = sup.get("name", "") or ""
    return Component(
        bom_ref=entry.get("bom-ref") or "",
        name=entry.get("name") or "",
        version=entry.get("version") or "",
        group=entry.get("group") or "",
        cpe=entry.get("cpe") or "",
        purl=entry.get("purl") or "",
        supplier=supplier,
        description=entry.get("description") or "",
    )


def main() -> None:
    p = argparse.ArgumentParser(description="Per-component CPE candidate retrieval")
    p.add_argument("--db", default="data/nvd_cpe.sqlite")
    p.add_argument("--sbom", default="EMBA_cyclonedx_sbom.json")
    p.add_argument("--bom-ref", help="Filter to a single component by bom-ref")
    p.add_argument("--name", help="Filter to a single component by name (first match)")
    p.add_argument("--top", type=int, default=50)
    p.add_argument("--show", type=int, default=20, help="Number of rows to print")
    args = p.parse_args()

    sbom = json.loads(Path(args.sbom).read_text())
    comps = sbom["components"]
    targets: list[dict] = []
    if args.bom_ref:
        targets = [c for c in comps if c.get("bom-ref") == args.bom_ref]
    elif args.name:
        targets = [c for c in comps if c.get("name") == args.name][:1]
    else:
        targets = comps[:1]
    if not targets:
        print("no matching component", flush=True)
        return

    conn = sqlite3.connect(args.db)
    for entry in targets:
        comp = _component_from_sbom_entry(entry)
        q, cands = find_candidates(conn, comp, top_n=args.top)
        print(f"=== {comp.bom_ref} | {comp.name} {comp.version} (group={comp.group}) ===")
        print(f"  vendors  : {q.vendors}")
        print(f"  products : {q.products[:10]}{'...' if len(q.products)>10 else ''}")
        print(f"  version  : {q.version_norm}")
        print(f"  candidates returned: {len(cands)}")
        for i, c in enumerate(cands[: args.show], 1):
            print(f"  {i:2d}. score={c.score:.3f} pass={c.pass_id} dep={c.deprecated}  {c.cpe_name}")
            if c.title:
                print(f"        title: {c.title[:100]}")


if __name__ == "__main__":
    main()
