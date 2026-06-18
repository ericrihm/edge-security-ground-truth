#!/usr/bin/env python3
"""
Export edge-security-ground-truth dataset to CSV.

Reads scripts/kev_edge_enriched.json (primary) and scripts/kev_edge_counts.json
(vendor-to-CVE mapping / ordering reference) and writes
scripts/edge_kev_dataset.csv with one row per CVE.

Columns (in order):
  vendor, cve, kev_date_added, kev_due_date, published,
  tte_days, cvss, cvss_severity, cwe, cwe_name, epss, percentile, ransomware

tte_days = kev_date_added - published (integer days).
           Left blank when either date is missing.

Usage:
  python3 scripts/export_dataset.py
  python3 scripts/export_dataset.py --out /path/to/output.csv
  python3 scripts/export_dataset.py --verify   # print row count then exit 0
"""
import argparse
import csv
import json
import os
import sys
from datetime import date

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")
COUNTS_PATH   = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
DEFAULT_OUT   = os.path.join(SCRIPT_DIR, "edge_kev_dataset.csv")

FIELDNAMES = [
    "vendor",
    "cve",
    "kev_date_added",
    "kev_due_date",
    "published",
    "tte_days",
    "cvss",
    "cvss_severity",
    "cwe",
    "cwe_name",
    "epss",
    "percentile",
    "ransomware",
]


def parse_date(s):
    """Parse YYYY-MM-DD string; return date or None."""
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def compute_tte(kev_date_added, published):
    """Return integer TTE days (may be negative for zero-days), or None."""
    d_kev = parse_date(kev_date_added)
    d_pub = parse_date(published)
    if d_kev is None or d_pub is None:
        return None
    return (d_kev - d_pub).days


def load_data():
    """Load both JSON source files; return (enriched_dict, counts_dict)."""
    if not os.path.isfile(ENRICHED_PATH):
        sys.exit(f"ERROR: enriched file not found: {ENRICHED_PATH}")
    if not os.path.isfile(COUNTS_PATH):
        sys.exit(f"ERROR: counts file not found: {COUNTS_PATH}")

    with open(ENRICHED_PATH, encoding="utf-8") as fh:
        enriched = json.load(fh)
    with open(COUNTS_PATH, encoding="utf-8") as fh:
        counts = json.load(fh)
    return enriched, counts


def build_rows(enriched, counts):
    """
    Yield one dict per CVE in vendor-alphabetical order, then CVE-ID order
    within each vendor.

    counts = {vendor: [cve_id, ...]}  (lists; order is original build order)
    enriched = {vendor: {cve_id: {...fields}}, "_metadata": {...}}
    """
    # Determine canonical vendor order: use counts.keys() order (alphabetical
    # in the generated file), but include any vendor present only in enriched.
    vendor_order = list(counts.keys())
    for vendor in enriched:
        if vendor != "_metadata" and vendor not in vendor_order:
            vendor_order.append(vendor)

    for vendor in vendor_order:
        if vendor == "_metadata":
            continue
        # CVE ordering: use the counts list if available, else enriched keys
        cve_list = counts.get(vendor) or list(enriched.get(vendor, {}).keys())
        vendor_enriched = enriched.get(vendor, {})

        for cve_id in cve_list:
            fields = vendor_enriched.get(cve_id, {})

            kev_date_added = fields.get("kev_date_added") or ""
            kev_due_date   = fields.get("kev_due_date")   or ""
            published      = fields.get("published")       or ""

            tte_raw = compute_tte(kev_date_added, published)
            tte_str = "" if tte_raw is None else str(tte_raw)

            cvss      = fields.get("cvss")
            cvss_str  = "" if cvss is None else str(cvss)
            cvss_sev  = fields.get("cvss_severity") or ""

            cwe      = fields.get("cwe")       or ""
            cwe_name = fields.get("cwe_name")  or ""

            epss       = fields.get("epss")
            epss_str   = "" if epss is None else str(epss)
            percentile = fields.get("percentile")
            pct_str    = "" if percentile is None else str(percentile)

            ransomware = fields.get("ransomware") or ""

            yield {
                "vendor":        vendor,
                "cve":           cve_id,
                "kev_date_added": kev_date_added,
                "kev_due_date":  kev_due_date,
                "published":     published,
                "tte_days":      tte_str,
                "cvss":          cvss_str,
                "cvss_severity": cvss_sev,
                "cwe":           cwe,
                "cwe_name":      cwe_name,
                "epss":          epss_str,
                "percentile":    pct_str,
                "ransomware":    ransomware,
            }


def write_csv(rows, out_path):
    """Write rows to CSV; return count of data rows written."""
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        count = 0
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def verify_csv(csv_path):
    """Re-read CSV with csv.reader; return (header, row_count)."""
    with open(csv_path, encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        row_count = sum(1 for _ in reader)
    return header, row_count


def main():
    parser = argparse.ArgumentParser(
        description="Export edge-security-ground-truth dataset to CSV."
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help=f"Output CSV path (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After writing, verify row count and print summary, then exit 0.",
    )
    args = parser.parse_args()

    enriched, counts = load_data()
    rows = list(build_rows(enriched, counts))
    n = write_csv(rows, args.out)

    header, verified_rows = verify_csv(args.out)

    print(f"Wrote {n} data rows + 1 header row to {args.out}")
    print(f"Verified (csv.reader): {verified_rows} data rows, {len(header)} columns")
    print(f"Columns: {', '.join(header)}")

    if verified_rows != n:
        sys.exit(f"ERROR: row count mismatch: wrote {n}, verified {verified_rows}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
