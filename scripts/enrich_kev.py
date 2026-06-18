#!/usr/bin/env python3
"""
KEV metadata enrichment for kev_edge_enriched.json.

Reads scripts/kev_edge_enriched.json, fetches the live CISA KEV catalog, and
merges three fields into every CVE entry:
  - kev_date_added   (from CISA KEV dateAdded)
  - kev_due_date     (from CISA KEV dueDate)
  - ransomware       (from CISA KEV knownRansomwareCampaignUse)

CVEs not found in the KEV catalog receive None for all three fields.

Output convention (matches enrich_epss.py): enriched JSON printed to stdout;
progress / summary to stderr.  Writes nothing to disk — pipe to a file if needed.

Usage:
  python3 scripts/enrich_kev.py > scripts/kev_edge_enriched.json
  python3 scripts/enrich_kev.py --input path/to/custom.json
"""
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_INPUT = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_enriched(path):
    """Load kev_edge_enriched.json; return the full dict including _metadata."""
    with open(path) as fh:
        return json.load(fh)


def fetch_kev_catalog(url=KEV_URL):
    """Fetch CISA KEV catalog; return {cve_id: {kev_date_added, kev_due_date, ransomware}}."""
    print(f"  Fetching CISA KEV catalog from {url} ...", file=sys.stderr)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    catalog = {}
    for entry in body.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "")
        if cve_id:
            catalog[cve_id] = {
                "kev_date_added": entry.get("dateAdded"),
                "kev_due_date": entry.get("dueDate"),
                "ransomware": entry.get("knownRansomwareCampaignUse"),
            }
    print(f"  Loaded {len(catalog)} entries from KEV catalog.", file=sys.stderr)
    return catalog


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def merge_kev_fields(data, catalog):
    """
    Return a copy of *data* with kev_date_added / kev_due_date / ransomware
    merged into every CVE dict.  _metadata key is preserved and updated.
    """
    enriched = {}
    total_cves = 0
    kev_found = 0
    kev_missing = 0

    for vendor, cves in data.items():
        if vendor.startswith("_"):
            continue
        vendor_data = {}
        for cve_id, fields in cves.items():
            total_cves += 1
            kev_info = catalog.get(cve_id)
            if kev_info:
                kev_found += 1
            else:
                kev_missing += 1
                kev_info = {
                    "kev_date_added": None,
                    "kev_due_date": None,
                    "ransomware": None,
                }
            # Merge: existing fields + new KEV fields (new fields appended)
            merged = dict(fields)
            merged["kev_date_added"] = kev_info["kev_date_added"]
            merged["kev_due_date"] = kev_info["kev_due_date"]
            merged["ransomware"] = kev_info["ransomware"]
            vendor_data[cve_id] = merged
        enriched[vendor] = vendor_data

    # Carry forward existing _metadata and add KEV enrichment stats
    meta = dict(data.get("_metadata", {}))
    meta["kev_enriched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta["kev_source"] = KEV_URL
    meta["kev_total_cves"] = total_cves
    meta["kev_found"] = kev_found
    meta["kev_missing"] = kev_missing
    enriched["_metadata"] = meta

    return enriched, kev_found, kev_missing


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(enriched, kev_found, kev_missing):
    print(file=sys.stderr)
    print(f"{'Vendor':<22} {'CVEs':>5}  {'KEV hits':>8}  {'Ransomware':>10}",
          file=sys.stderr)
    print("-" * 58, file=sys.stderr)
    for vendor, cves in sorted(enriched.items()):
        if vendor.startswith("_"):
            continue
        count = len(cves)
        hits = sum(1 for v in cves.values() if v.get("kev_date_added") is not None)
        ransom = sum(
            1 for v in cves.values()
            if v.get("ransomware") and v["ransomware"].lower() not in ("unknown", "no")
        )
        print(f"{vendor:<22} {count:>5}  {hits:>8}  {ransom:>10}", file=sys.stderr)
    print("-" * 58, file=sys.stderr)
    print(f"Total: {kev_found + kev_missing} CVEs, "
          f"{kev_found} in KEV, {kev_missing} not in KEV",
          file=sys.stderr)
    print(file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Merge CISA KEV metadata into kev_edge_enriched.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", "-i",
        default=DEFAULT_INPUT,
        help=f"Input JSON (default: {DEFAULT_INPUT})",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"# KEV enrichment: reading {args.input}", file=sys.stderr)
    data = load_enriched(args.input)

    vendor_count = sum(1 for k in data if not k.startswith("_"))
    cve_count = sum(len(v) for k, v in data.items() if not k.startswith("_"))
    print(f"# {vendor_count} vendors, {cve_count} CVEs to enrich", file=sys.stderr)

    catalog = fetch_kev_catalog()

    enriched, kev_found, kev_missing = merge_kev_fields(data, catalog)

    print_summary(enriched, kev_found, kev_missing)

    # Output enriched JSON to stdout
    json.dump(enriched, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
