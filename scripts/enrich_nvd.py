#!/usr/bin/env python3
"""
NVD enrichment for edge-KEV CVE list.

Reads kev_edge_counts.json (vendor -> [CVE-ID, ...]), fetches CVSS/CWE/date data
from NVD API 2.0 one CVE at a time (rate-limited), and merges into the enriched
JSON alongside existing EPSS data.

Usage:
  python3 scripts/enrich_nvd.py                    # full run
  python3 scripts/enrich_nvd.py --skip-existing     # resume: skip already-enriched CVEs
  python3 scripts/enrich_nvd.py --dry-run            # show plan, no fetch
"""
import argparse, json, os, socket, sys, time
import urllib.request, urllib.error
from collections import Counter
from datetime import datetime, timezone

# Force IPv4 — NVD API returns 503 over IPv6 as of 2026-06
# getaddrinfo signature: (host, port, family=0, type=0, proto=0, flags=0)
# family is the 3rd positional arg (index 2), so we must handle both cases.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_only(host, port, family=0, *args, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)
socket.getaddrinfo = _ipv4_only

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_API = "https://cveawg.mitre.org/api/cve"
RATE_LIMIT_SECS = 2.0  # MITRE API is generous; NVD fallback uses 6.5s internally


# ---- Well-known CWE names (top ~80 covers vast majority of CVEs) ----
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-59": "Improper Link Resolution Before File Access",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-94": "Improper Control of Generation of Code",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-22": "Path Traversal",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path or Channel",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-436": "Interpretation Conflict",
    "CWE-444": "HTTP Request/Response Smuggling",
    "CWE-459": "Incomplete Cleanup",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-669": "Incorrect Resource Transfer Between Spheres",
    "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-776": "Improper Restriction of Recursive Entity References in DTDs",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-843": "Access of Resource Using Incompatible Type",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-912": "Hidden Functionality",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-924": "Improper Enforcement of Message Integrity During Transmission",
    "CWE-1287": "Improper Validation of Specified Type of Input",
    "CWE-1390": "Weak Authentication",
    "NVD-CWE-noinfo": "Insufficient Information",
    "NVD-CWE-Other": "Other",
}


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


def load_existing_enriched(path):
    """Load existing enriched JSON if present, returning {vendor: {cve: {...}}}."""
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


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


def cve_has_nvd_data(existing, cve_id):
    """Check if a CVE already has NVD data in the enriched file."""
    for vendor_key, vendor_data in existing.items():
        if vendor_key.startswith("_"):
            continue
        if not isinstance(vendor_data, dict):
            continue
        if cve_id in vendor_data:
            entry = vendor_data[cve_id]
            # Has NVD data if cvss field is present (even if None for not-found)
            if "cvss" in entry:
                return True
    return False


def _http_fetch(url, timeout=20, retries=2):
    """Fetch JSON from a URL with retries. Returns parsed dict or None."""
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "edge-security-ground-truth/1.0",
    })
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < retries:
                wait = 6 * (attempt + 1)
                print(f"    HTTP {e.code} — retry in {wait}s ...", file=sys.stderr)
                time.sleep(wait)
                continue
            return None
        except Exception as e:
            if attempt < retries:
                wait = 4 * (attempt + 1)
                print(f"    Timeout (attempt {attempt+1}), retry in {wait}s ...",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            return None
    return None


def _parse_nvd_response(body):
    """Parse NVD API 2.0 JSON response into our enriched fields."""
    vulns = body.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})
    result = {}

    published = cve_data.get("published", "")
    if published:
        result["published"] = published[:10]

    cvss31 = None
    metrics = cve_data.get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            for m in metric_list:
                if m.get("type") == "Primary":
                    cvss31 = m.get("cvssData", {})
                    break
            if not cvss31:
                cvss31 = metric_list[0].get("cvssData", {})
            if cvss31:
                break

    if cvss31:
        result["cvss"] = cvss31.get("baseScore")
        result["cvss_severity"] = cvss31.get("baseSeverity")
        result["cvss_vector"] = cvss31.get("vectorString")
    else:
        result["cvss"] = None
        result["cvss_severity"] = None
        result["cvss_vector"] = None

    weaknesses = cve_data.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and val not in cwe_ids:
                cwe_ids.append(val)

    if cwe_ids:
        result["cwe"] = cwe_ids[0]
        result["cwe_name"] = CWE_NAMES.get(cwe_ids[0], cwe_ids[0])
        if len(cwe_ids) > 1:
            result["cwe_secondary"] = cwe_ids[1:]
    else:
        result["cwe"] = None
        result["cwe_name"] = None

    return result


def _parse_mitre_response(body):
    """Parse MITRE CVE Services API (cveawg) response into our enriched fields."""
    result = {}

    # Published date from metadata
    meta = body.get("cveMetadata", {})
    published = meta.get("datePublished", "")
    if published:
        result["published"] = published[:10]

    # Search CNA container first, then ADP containers for CVSS
    cna = body.get("containers", {}).get("cna", {})
    adp_list = body.get("containers", {}).get("adp", [])

    cvss = None
    # CNA metrics
    for m in cna.get("metrics", []):
        cvss = m.get("cvssV3_1") or m.get("cvssV3_0")
        if cvss:
            break
    # ADP metrics (often NVD-provided scores)
    if not cvss:
        for adp in adp_list:
            for m in adp.get("metrics", []):
                cvss = m.get("cvssV3_1") or m.get("cvssV3_0")
                if cvss:
                    break
            if cvss:
                break

    if cvss:
        result["cvss"] = cvss.get("baseScore")
        result["cvss_severity"] = cvss.get("baseSeverity")
        result["cvss_vector"] = cvss.get("vectorString")
    else:
        result["cvss"] = None
        result["cvss_severity"] = None
        result["cvss_vector"] = None

    # CWEs from CNA problemTypes, then ADP
    cwe_ids = []
    for source in [cna] + adp_list:
        for pt in source.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)

    if cwe_ids:
        result["cwe"] = cwe_ids[0]
        result["cwe_name"] = CWE_NAMES.get(cwe_ids[0], cwe_ids[0])
        if len(cwe_ids) > 1:
            result["cwe_secondary"] = cwe_ids[1:]
    else:
        result["cwe"] = None
        result["cwe_name"] = None

    return result


def fetch_nvd_cve(cve_id):
    """Fetch CVE data. Tries MITRE CVE API first (fast), NVD API as fallback."""
    # Primary: MITRE CVE Services API (no rate limit issues, fast)
    mitre_url = f"{MITRE_API}/{cve_id}"
    body = _http_fetch(mitre_url, timeout=20, retries=1)
    if body:
        result = _parse_mitre_response(body)
        if result:
            result["_source"] = "mitre"
            return result

    # Fallback: NVD API 2.0 (slower, rate-limited, currently 503-prone)
    nvd_url = f"{NVD_API}?cveId={cve_id}"
    body = _http_fetch(nvd_url, timeout=30, retries=2)
    if body:
        result = _parse_nvd_response(body)
        if result:
            result["_source"] = "nvd"
            return result

    return None


def merge_enriched(vendors, existing, nvd_data):
    """Merge NVD data into enriched structure, preserving EPSS data."""
    enriched = {}
    for vendor, cves in vendors.items():
        vendor_existing = {}
        if vendor in existing and isinstance(existing[vendor], dict):
            vendor_existing = existing[vendor]

        vendor_out = {}
        for cve in cves:
            entry = {}
            # Preserve existing EPSS data
            if cve in vendor_existing:
                old = vendor_existing[cve]
                if "epss" in old:
                    entry["epss"] = old["epss"]
                if "percentile" in old:
                    entry["percentile"] = old["percentile"]

            # Add NVD data (from fresh fetch or from existing)
            if cve in nvd_data:
                entry.update(nvd_data[cve])
            elif cve in vendor_existing:
                # Preserve existing NVD data if we didn't re-fetch
                old = vendor_existing[cve]
                for key in ("cvss", "cvss_severity", "cvss_vector", "cwe",
                            "cwe_name", "cwe_secondary", "published"):
                    if key in old:
                        entry[key] = old[key]

            vendor_out[cve] = entry
        enriched[vendor] = vendor_out

    return enriched


def print_summary(enriched):
    """Print CVSS distribution, CWE distribution, and per-vendor summary."""
    all_entries = []
    for vendor, cves in enriched.items():
        if vendor.startswith("_"):
            continue
        if not isinstance(cves, dict):
            continue
        for cve_id, data in cves.items():
            all_entries.append((vendor, cve_id, data))

    # CVSS distribution
    severity_counts = Counter()
    cvss_scores = []
    for vendor, cve_id, data in all_entries:
        sev = data.get("cvss_severity")
        if sev:
            severity_counts[sev] += 1
        score = data.get("cvss")
        if score is not None:
            cvss_scores.append(score)

    print("\n" + "=" * 70)
    print("NVD ENRICHMENT SUMMARY")
    print("=" * 70)

    total = len(all_entries)
    with_cvss = len(cvss_scores)
    with_cwe = sum(1 for _, _, d in all_entries if d.get("cwe") and d["cwe"] != "NVD-CWE-noinfo")
    with_nvd = sum(1 for _, _, d in all_entries if "cvss" in d)
    print(f"\nTotal CVEs: {total}")
    print(f"  With NVD data:  {with_nvd}")
    print(f"  With CVSS:      {with_cvss}")
    print(f"  With CWE:       {with_cwe}")

    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        print(f"\nCVSS Score Stats:")
        print(f"  Average:  {avg_cvss:.1f}")
        print(f"  Min:      {min(cvss_scores)}")
        print(f"  Max:      {max(cvss_scores)}")
        print(f"  Median:   {sorted(cvss_scores)[len(cvss_scores)//2]}")

    if severity_counts:
        print(f"\nCVSS Severity Distribution:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            bar = "#" * count
            if count:
                print(f"  {sev:<10} {count:>3}  {bar}")

    # CWE distribution
    cwe_counts = Counter()
    for _, _, data in all_entries:
        cwe = data.get("cwe")
        if cwe:
            cwe_counts[cwe] += 1

    if cwe_counts:
        print(f"\nTop CWEs:")
        for cwe, count in cwe_counts.most_common(15):
            name = CWE_NAMES.get(cwe, cwe)
            # Truncate long names
            if len(name) > 45:
                name = name[:42] + "..."
            print(f"  {cwe:<20} {count:>3}  {name}")

    # Per-vendor table
    print(f"\n{'Vendor':<22} {'CVEs':>5}  {'Avg CVSS':>8}  {'CRITs':>5}  {'HIGHs':>5}")
    print("-" * 60)
    for vendor, cves in sorted(enriched.items()):
        if vendor.startswith("_"):
            continue
        if not isinstance(cves, dict):
            continue
        scores = [v.get("cvss") for v in cves.values() if v.get("cvss") is not None]
        count = len(cves)
        crits = sum(1 for v in cves.values() if v.get("cvss_severity") == "CRITICAL")
        highs = sum(1 for v in cves.values() if v.get("cvss_severity") == "HIGH")
        if scores:
            avg = sum(scores) / len(scores)
            print(f"{vendor:<22} {count:>5}  {avg:>8.1f}  {crits:>5}  {highs:>5}")
        else:
            print(f"{vendor:<22} {count:>5}  {'N/A':>8}  {crits:>5}  {highs:>5}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NVD enrichment for edge-KEV CVE list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i",
                        default=os.path.join(SCRIPT_DIR, "kev_edge_counts.json"),
                        help="Input JSON (default: scripts/kev_edge_counts.json)")
    parser.add_argument("--output", "-o",
                        default=os.path.join(SCRIPT_DIR, "kev_edge_enriched.json"),
                        help="Output JSON (default: scripts/kev_edge_enriched.json)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip CVEs that already have NVD data in the enriched file")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plan without fetching NVD data")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    vendors = load_input(args.input)
    all_cves = collect_cves(vendors)
    existing = load_existing_enriched(args.output)

    # Determine which CVEs to fetch
    if args.skip_existing:
        to_fetch = [c for c in all_cves if not cve_has_nvd_data(existing, c)]
    else:
        to_fetch = list(all_cves)

    total_vendors = len(vendors)
    total_cves = len(all_cves)
    fetch_count = len(to_fetch)
    est_time = fetch_count * RATE_LIMIT_SECS

    print(f"# NVD enrichment for {total_vendors} vendors, {total_cves} unique CVEs",
          file=sys.stderr)
    print(f"# Will fetch: {fetch_count} CVEs "
          f"(skipping {total_cves - fetch_count} already enriched)",
          file=sys.stderr)
    print(f"# Estimated time: {est_time:.0f}s ({est_time/60:.1f} min) "
          f"at {RATE_LIMIT_SECS}s rate limit",
          file=sys.stderr)

    if args.dry_run:
        print("\n[DRY RUN] Would fetch NVD data for these CVEs:\n")
        for i, cve in enumerate(to_fetch, 1):
            print(f"  {i:>3}. {cve}")
        print(f"\n  Total to fetch:    {fetch_count}")
        print(f"  Already enriched:  {total_cves - fetch_count}")
        print(f"  Estimated time:    {est_time:.0f}s ({est_time/60:.1f} min)")
        print(f"  Output:            {args.output}")
        return

    # Fetch NVD data — saves incrementally after every CVE
    nvd_data = {}
    fetched = 0
    errors = 0
    start_time = time.time()

    def save_progress():
        """Merge and write current state to disk."""
        enriched = merge_enriched(vendors, existing, nvd_data)
        enriched["_metadata"] = {
            "sources": [
                "https://api.first.org/data/v1/epss",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
            ],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_cves": total_cves,
            "nvd_fetched": fetched,
            "nvd_errors": errors,
            "nvd_skipped": total_cves - fetch_count,
        }
        if "_metadata" in existing:
            old_meta = existing["_metadata"]
            if "epss_found" in old_meta:
                enriched["_metadata"]["epss_found"] = old_meta["epss_found"]
            if "epss_missing" in old_meta:
                enriched["_metadata"]["epss_missing"] = old_meta["epss_missing"]
        with open(args.output, "w") as f:
            json.dump(enriched, f, indent=2)
        return enriched

    for i, cve_id in enumerate(to_fetch, 1):
        if i > 1:
            time.sleep(RATE_LIMIT_SECS)

        elapsed = time.time() - start_time
        remaining = (fetch_count - i) * RATE_LIMIT_SECS
        print(f"  Fetching {i}/{fetch_count}: {cve_id} "
              f"[{elapsed:.0f}s elapsed, ~{remaining:.0f}s remaining] ...",
              file=sys.stderr)

        result = fetch_nvd_cve(cve_id)
        if result:
            nvd_data[cve_id] = result
            fetched += 1
            sev = result.get("cvss_severity", "?")
            score = result.get("cvss", "?")
            cwe = result.get("cwe", "?")
            print(f"    -> CVSS {score} ({sev}), {cwe}", file=sys.stderr)
        else:
            errors += 1
            print(f"    -> No data found", file=sys.stderr)

        # Save after every CVE so progress is never lost
        save_progress()

    elapsed_total = time.time() - start_time
    print(f"\n# Fetched {fetched}/{fetch_count} CVEs in {elapsed_total:.0f}s "
          f"({errors} errors)", file=sys.stderr)

    enriched = save_progress()
    print(f"# Wrote {args.output}", file=sys.stderr)

    print_summary(enriched)


if __name__ == "__main__":
    main()
