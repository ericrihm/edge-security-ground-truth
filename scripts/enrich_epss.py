#!/usr/bin/env python3
"""
EPSS enrichment for edge-KEV CVE list.

Reads kev_edge_counts.json (vendor → [CVE-ID, ...]), batch-fetches EPSS scores
from the FIRST EPSS API, and writes an enriched JSON keyed by vendor → CVE → {epss, percentile}.

Usage:
  python3 scripts/enrich_epss.py                          # defaults
  python3 scripts/enrich_epss.py --input custom.json      # custom input
  python3 scripts/enrich_epss.py --dry-run                # show plan, no fetch
"""
import argparse, json, os, sys, time, urllib.request, urllib.parse
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EPSS_API = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # API limit per request


def load_input(path):
    """Load kev_edge_counts.json and return {vendor: [cve, ...]} without _metadata."""
    with open(path) as f:
        data = json.load(f)
    vendors = {}
    for key, val in data.items():
        if key.startswith("_"):
            continue
        if isinstance(val, list):
            vendors[key] = val
    return vendors


def collect_cves(vendors):
    """Flatten all CVE IDs, deduplicated, preserving order."""
    seen = set()
    cves = []
    for vendor, ids in vendors.items():
        for cve in ids:
            if cve not in seen:
                seen.add(cve)
                cves.append(cve)
    return cves


def fetch_epss_batch(cve_batch):
    """Fetch EPSS for a batch of up to 100 CVEs. Returns {cve_id: {epss, percentile}}."""
    params = urllib.parse.urlencode({"cve": ",".join(cve_batch)})
    url = f"{EPSS_API}?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    results = {}
    for entry in body.get("data", []):
        results[entry["cve"]] = {
            "epss": float(entry["epss"]),
            "percentile": float(entry["percentile"]),
        }
    return results


def fetch_all_epss(cves):
    """Batch-fetch EPSS for all CVEs, respecting batch size and rate limits."""
    all_scores = {}
    batches = [cves[i:i + BATCH_SIZE] for i in range(0, len(cves), BATCH_SIZE)]
    for i, batch in enumerate(batches):
        if i > 0:
            time.sleep(1)  # polite rate limit
        print(f"  Fetching batch {i + 1}/{len(batches)} ({len(batch)} CVEs) ...",
              file=sys.stderr)
        scores = fetch_epss_batch(batch)
        all_scores.update(scores)
    return all_scores


def build_enriched(vendors, epss_scores):
    """Build enriched output: {vendor: {cve: {epss, percentile}}, ..., _metadata: {...}}."""
    enriched = {}
    total_found = 0
    total_missing = 0
    for vendor, cves in vendors.items():
        vendor_data = {}
        for cve in cves:
            if cve in epss_scores:
                vendor_data[cve] = epss_scores[cve]
                total_found += 1
            else:
                vendor_data[cve] = {"epss": None, "percentile": None}
                total_missing += 1
        enriched[vendor] = vendor_data
    enriched["_metadata"] = {
        "source": "https://api.first.org/data/v1/epss",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cves": total_found + total_missing,
        "epss_found": total_found,
        "epss_missing": total_missing,
    }
    return enriched


def print_summary(enriched):
    """Print per-vendor summary table."""
    print()
    print(f"{'Vendor':<22} {'Count':>5}  {'Avg EPSS':>8}  {'Max EPSS':>8}  Max CVE")
    print("-" * 80)
    for vendor, cves in sorted(enriched.items()):
        if vendor.startswith("_"):
            continue
        scores = [v["epss"] for v in cves.values() if v["epss"] is not None]
        count = len(cves)
        if scores:
            avg = sum(scores) / len(scores)
            max_score = max(scores)
            max_cve = max(
                ((cve, v["epss"]) for cve, v in cves.items() if v["epss"] is not None),
                key=lambda x: x[1],
            )[0]
            print(f"{vendor:<22} {count:>5}  {avg:>8.4f}  {max_score:>8.4f}  {max_cve}")
        else:
            print(f"{vendor:<22} {count:>5}  {'N/A':>8}  {'N/A':>8}  -")
    meta = enriched.get("_metadata", {})
    print("-" * 80)
    print(f"Total: {meta.get('total_cves', '?')} CVEs, "
          f"{meta.get('epss_found', '?')} with EPSS, "
          f"{meta.get('epss_missing', '?')} missing")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="EPSS enrichment for edge-KEV CVE list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i",
                        default=os.path.join(SCRIPT_DIR, "kev_edge_counts.json"),
                        help="Input JSON (default: scripts/kev_edge_counts.json)")
    parser.add_argument("--output", "-o",
                        default=os.path.join(SCRIPT_DIR, "kev_edge_enriched.json"),
                        help="Output JSON (default: scripts/kev_edge_enriched.json)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without fetching EPSS data")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    vendors = load_input(args.input)
    all_cves = collect_cves(vendors)
    total_vendors = len(vendors)
    total_cves = len(all_cves)
    batches_needed = (total_cves + BATCH_SIZE - 1) // BATCH_SIZE

    print(f"# EPSS enrichment for {total_vendors} vendors, {total_cves} unique CVEs "
          f"({batches_needed} API batch{'es' if batches_needed != 1 else ''})",
          file=sys.stderr)

    if args.dry_run:
        print("\n[DRY RUN] Would fetch EPSS for these CVEs:\n")
        for vendor, cves in vendors.items():
            print(f"  {vendor}: {len(cves)} CVEs")
            for cve in cves:
                print(f"    {cve}")
        print(f"\n  Total unique: {total_cves}")
        print(f"  API batches:  {batches_needed}")
        print(f"  Output:       {args.output}")
        return

    epss_scores = fetch_all_epss(all_cves)
    enriched = build_enriched(vendors, epss_scores)

    with open(args.output, "w") as f:
        json.dump(enriched, f, indent=2)
    print(f"# Wrote {args.output}", file=sys.stderr)

    print_summary(enriched)


if __name__ == "__main__":
    main()
