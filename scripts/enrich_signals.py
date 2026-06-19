#!/usr/bin/env python3
"""
Operational-signal enrichment: weaponization (public-exploit availability) and
CISA remediation urgency. Adds to each CVE in kev_edge_enriched.json:

  - in_exploitdb            bool  -- a curated Exploit-DB entry references the CVE
  - has_nuclei_template     bool  -- a ProjectDiscovery nuclei template exists
  - public_exploit          bool  -- in_exploitdb OR has_nuclei_template
  - remediation_window_days int   -- CISA kev_due_date - kev_date_added (or null)
  - cisa_emergency          bool  -- remediation window <= 7 days (urgent directive)

Weaponization uses CURATED indices ONLY (Exploit-DB, nuclei-templates), not raw
GitHub "PoC" scraper repos -- 2026 has an explosion of AI-generated low-quality
PoCs, so we deliberately avoid them. This is a heuristic *accessibility* signal,
not a guarantee that a reliable working exploit exists.

ACCURACY GUARD: if a weaponization source cannot be fetched, the script ABORTS
without writing, rather than recording a misleading "False" (= "not found") when
the truth is "could not check". Sources actually used are recorded in _metadata.

Sources (fetched live):
  Exploit-DB:  https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
  nuclei:      https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json

Usage:
  python3 scripts/enrich_signals.py            # fetch + enrich in place
  python3 scripts/enrich_signals.py --dry-run  # report only, no write
"""
import argparse
import csv
import io
import json
import os
import re
import sys
import tempfile
import urllib.request
from datetime import date, datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
NUCLEI_CVES = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "edge-sec-ground-truth"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def exploitdb_cves():
    """Set of CVE IDs referenced by any Exploit-DB entry (the 'codes' column)."""
    text = fetch(EXPLOITDB_CSV)
    out = set()
    reader = csv.DictReader(io.StringIO(text))
    col = "codes" if reader.fieldnames and "codes" in reader.fieldnames else None
    for row in reader:
        blob = row.get(col, "") if col else ",".join(row.values())
        for m in CVE_RE.findall(blob or ""):
            out.add(m.upper())
    if not out:
        raise RuntimeError("Exploit-DB parse yielded 0 CVEs (format changed?)")
    return out


def nuclei_cves():
    """Set of CVE IDs that have a ProjectDiscovery nuclei template."""
    text = fetch(NUCLEI_CVES)
    out = set(m.upper() for m in CVE_RE.findall(text))
    # cves.json is newline-delimited JSON objects each with an "ID" field; the
    # regex above captures every CVE-ID regardless of exact shape.
    if not out:
        raise RuntimeError("nuclei cves.json yielded 0 CVEs (format changed?)")
    return out


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    d = json.load(open(ENRICHED))
    vendors = [v for v in d if v != "_metadata"]
    all_cves = {c for v in vendors for c in d[v]}

    # --- weaponization sources (abort if a source is unreachable) ---
    try:
        edb = exploitdb_cves()
        print(f"# Exploit-DB: {len(edb)} CVEs indexed", file=sys.stderr)
    except Exception as e:
        sys.exit(f"ABORT: Exploit-DB unavailable ({e}); not writing inaccurate flags.")
    try:
        nuc = nuclei_cves()
        print(f"# nuclei-templates: {len(nuc)} CVEs indexed", file=sys.stderr)
    except Exception as e:
        sys.exit(f"ABORT: nuclei-templates unavailable ({e}); not writing inaccurate flags.")

    stats = {"in_exploitdb": 0, "has_nuclei_template": 0, "public_exploit": 0,
             "cisa_emergency": 0, "remediation_window_present": 0}
    for v in vendors:
        for c, e in d[v].items():
            cu = c.upper()
            in_edb = cu in edb
            in_nuc = cu in nuc
            pub = in_edb or in_nuc
            added = parse_date(e.get("kev_date_added"))
            due = parse_date(e.get("kev_due_date"))
            window = (due - added).days if (added and due) else None
            emergency = window is not None and window <= 7
            if not args.dry_run:
                e["in_exploitdb"] = in_edb
                e["has_nuclei_template"] = in_nuc
                e["public_exploit"] = pub
                e["remediation_window_days"] = window
                e["cisa_emergency"] = emergency
            stats["in_exploitdb"] += in_edb
            stats["has_nuclei_template"] += in_nuc
            stats["public_exploit"] += pub
            stats["cisa_emergency"] += emergency
            stats["remediation_window_present"] += window is not None

    n = len(all_cves)
    print(f"# {n} edge CVEs | public_exploit: {stats['public_exploit']} "
          f"({100*stats['public_exploit']//n}%) | Exploit-DB: {stats['in_exploitdb']} | "
          f"nuclei: {stats['has_nuclei_template']} | CISA emergency (<=7d): "
          f"{stats['cisa_emergency']} | remediation window present: "
          f"{stats['remediation_window_present']}")

    if args.dry_run:
        print("# dry-run: no write")
        return

    meta = d.setdefault("_metadata", {})
    meta["signal_sources"] = {
        "weaponization": ["exploit-db (gitlab files_exploits.csv)",
                          "nuclei-templates (cves.json)"],
        "note": "curated indices only; heuristic accessibility signal, not a working-exploit guarantee",
    }
    fd, tmp = tempfile.mkstemp(dir=SCRIPT_DIR, suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, ENRICHED)
    print(f"# wrote {ENRICHED}")


if __name__ == "__main__":
    main()
