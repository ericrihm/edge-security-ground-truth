#!/usr/bin/env python3
"""
Reproducible edge-KEV counter.

Counts CISA KEV entries for each vendor's INTERNET-FACING EDGE APPLIANCE
(firewall / SSL-VPN / remote-access gateway) only, by KEV dateAdded within the
scope window. This script IS the methodology for the `KEV (edge)` column —
re-run it against the live feed to reproduce or update every count.

Usage:
  python3 scripts/build_kev_counts.py                   # auto-fetch live CISA feed
  python3 scripts/build_kev_counts.py kev.json           # use local file
  python3 scripts/build_kev_counts.py --vendor Fortinet   # single vendor
  python3 scripts/build_kev_counts.py --format csv        # CSV output
  python3 scripts/build_kev_counts.py --as-of 2026-06-16  # reproducible snapshot
"""
import argparse, csv, io, json, os, re, sys, tempfile, urllib.request
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_WINDOW = ("2020-01-01", "2026-12-31")

# Per-vendor edge-product scope. include = regex that the `product` field must match;
# exclude = regex that disqualifies it. Scope = firewall + SSL-VPN/remote-access gateway ONLY.
SCOPE = {
    "SonicWall":            dict(include=r"SonicOS|SMA|SSLVPN|SSL[- ]?VPN|Secure Remote Access|SRA",
                                 exclude=r"Email Security"),
    "Ivanti":               dict(include=r"Connect Secure|Pulse Connect Secure|Policy Secure",
                                 exclude=r"MobileIron|Endpoint Manager|EPMM|EPM|Sentry|Cloud Services Appliance|Virtual Traffic Manager"),
    "Juniper":              dict(include=r"Junos OS|ScreenOS",
                                 exclude=r""),
    "Cisco":                dict(include=r"Adaptive Security Appliance|ASA|Firepower Threat Defense|FTD|Secure Firewall",
                                 exclude=r"Management Center|FMC"),
    "Palo Alto Networks":   dict(include=r"PAN-OS",
                                 exclude=r"Expedition"),
    "Fortinet":             dict(include=r"FortiOS|FortiProxy",
                                 exclude=r"FortiClient|FortiManager|FortiWeb|FortiMail|FortiVoice|FortiNDR"),
    "Check Point":          dict(include=r"Quantum|CloudGuard|Security Gateway|Gaia",
                                 exclude=r"Endpoint|Harmony|SmartConsole|ZoneAlarm"),
    "Citrix":               dict(include=r"NetScaler ADC|NetScaler Gateway|Citrix ADC|Citrix Gateway|Application Delivery Controller|^NetScaler$",
                                 exclude=r"Workspace|XenApp|XenDesktop|ShareFile|Endpoint Management"),
    "F5":                   dict(include=r"BIG-IP",
                                 exclude=r"BIG-IQ|NGINX"),
    "Zyxel":                dict(include=r"Multiple Firewalls|USG|ATP|ZyWALL|VPN|FLEX",
                                 exclude=r"NAS|Network-Attached Storage|Router|CPE|DSL|Access Point"),
    "Sophos":               dict(include=r"Firewall|XG Firewall|SG UTM|SFOS|CyberoamOS",
                                 exclude=r"Web Appliance|Intercept X|Central|Endpoint|Email"),
    # SSL-VPN / firewall appliances added 2026-06-18 (audit GAP-01/02): both have
    # qualifying in-window edge KEV entries; their prior absence falsified the
    # "no qualifying vendor excluded" invariant in METHODOLOGY.md.
    "WatchGuard":           dict(include=r"Firebox|XTM|Fireware",
                                 exclude=r"AuthPoint"),
    "Array Networks":       dict(include=r"ArrayOS|vxAG",
                                 exclude=r""),
}

def in_window(d, window):
    return window[0] <= d <= window[1]

def fetch_kev(path=None):
    """Fetch KEV catalog from a local path or the live CISA feed."""
    if path and os.path.isfile(path):
        with open(path) as f:
            return json.load(f)
    print(f"# Fetching live CISA KEV feed from {KEV_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
        return json.loads(resp.read())

def run(kev_data, window, vendor_filter=None):
    vulns = kev_data.get("vulnerabilities", [])
    results = {}
    for vendor, rule in SCOPE.items():
        if vendor_filter and vendor.lower() != vendor_filter.lower():
            continue
        inc = re.compile(rule["include"], re.I)
        exc = re.compile(rule["exclude"], re.I) if rule["exclude"] else None
        rows = []
        for v in vulns:
            if v.get("vendorProject", "").strip().lower() != vendor.lower():
                continue
            prod = v.get("product", "")
            desc = v.get("shortDescription", "")
            hay = prod if "multiple" not in prod.lower() else prod + " " + desc
            if not inc.search(hay):
                continue
            if exc and exc.search(prod):
                continue
            if not in_window(v.get("dateAdded", ""), window):
                continue
            rows.append({
                "cve": v["cveID"],
                "product": prod,
                "dateAdded": v["dateAdded"],
                "description": desc,
            })
        rows.sort(key=lambda r: r["dateAdded"])
        results[vendor] = rows
    return results

def print_table(results, catalog_version, window):
    total_vulns = sum(len(r) for r in results.values())
    print(f"# CISA KEV catalog {catalog_version}")
    print(f"# Scope: internet-facing edge appliance (firewall / SSL-VPN / remote-access)")
    print(f"# Window: {window[0]} .. {window[1]}  |  {len(results)} vendors  |  {total_vulns} edge CVEs\n")
    for vendor, rows in sorted(results.items(), key=lambda x: -len(x[1])):
        print(f"## {vendor}: {len(rows)} edge-KEV entries")
        for r in rows:
            print(f"   {r['cve']:18} {r['dateAdded']}  {r['product']}")
        print()

def write_json(results, output_path, catalog_version, window):
    counts = {v: [r["cve"] for r in rows] for v, rows in results.items()}
    counts["_metadata"] = {
        "catalog_version": catalog_version,
        "window": list(window),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_rules": {v: SCOPE[v] for v in results},
        "counts": {v: len(rows) for v, rows in results.items()},
    }
    # Write atomically: build the full dict in memory, write to a temp file in
    # the same dir, then os.replace() so an interrupted run can never leave a
    # partial / single-vendor counts file on disk (REPRO-002).
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(output_path) or ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(counts, f, indent=2)
        os.replace(tmp, output_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f"# wrote {output_path}  |  counts: {counts['_metadata']['counts']}")

def write_csv(results, output):
    w = csv.writer(output)
    w.writerow(["vendor", "cve", "product", "dateAdded", "description"])
    for vendor, rows in sorted(results.items(), key=lambda x: -len(x[1])):
        for r in rows:
            w.writerow([vendor, r["cve"], r["product"], r["dateAdded"], r["description"]])

def main():
    parser = argparse.ArgumentParser(
        description="Reproducible edge-KEV counter — counts CISA KEV entries per vendor's edge appliance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("kev_file", nargs="?", default=None,
                        help="Path to local KEV JSON (default: auto-fetch live CISA feed)")
    parser.add_argument("--vendor", "-v", default=None,
                        help="Filter to a single vendor (e.g. Fortinet, 'Check Point')")
    parser.add_argument("--format", "-f", choices=["table", "json", "csv"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output file path (default: scripts/kev_edge_counts.json for JSON)")
    parser.add_argument("--as-of", default=None,
                        help="Cap dateAdded at this date for reproducible historical snapshots (YYYY-MM-DD)")
    parser.add_argument("--window-start", default=DEFAULT_WINDOW[0],
                        help=f"Window start date (default: {DEFAULT_WINDOW[0]})")
    args = parser.parse_args()

    window_end = args.as_of if args.as_of else DEFAULT_WINDOW[1]
    window = (args.window_start, window_end)

    kev_data = fetch_kev(args.kev_file)
    catalog_version = kev_data.get("catalogVersion", "unknown")
    results = run(kev_data, window, args.vendor)

    if args.format == "table":
        print_table(results, catalog_version, window)
        output_path = args.output or os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
        write_json(results, output_path, catalog_version, window)
    elif args.format == "json":
        output_path = args.output or os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
        write_json(results, output_path, catalog_version, window)
    elif args.format == "csv":
        if args.output:
            with open(args.output, "w", newline="") as f:
                write_csv(results, f)
            print(f"# wrote {args.output}", file=sys.stderr)
        else:
            write_csv(results, sys.stdout)

if __name__ == "__main__":
    main()
