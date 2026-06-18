#!/usr/bin/env python3
"""
Time-to-exploit (TTE) analysis for edge-security-ground-truth.

TTE = CISA KEV dateAdded - NVD publishedDate (in days).

This measures how quickly CISA confirmed active exploitation after public
disclosure.  Negative values mean the CVE was added to KEV *before* its NVD
publication date -- a strong signal of true zero-day exploitation in the wild.

Data sources:
  - kev_edge_enriched.json  (NVD published dates, EPSS, CVSS, CWE)
  - Live CISA KEV feed       (dateAdded for each CVE)
  - kev_edge_counts.json    (vendor -> CVE-ID lists, used as scope filter)

Usage:
  python3 scripts/analyze_tte.py                       # table output
  python3 scripts/analyze_tte.py --format markdown     # markdown tables
  python3 scripts/analyze_tte.py --format json         # machine-readable
  python3 scripts/analyze_tte.py --no-fetch            # skip live KEV fetch
"""
import argparse
import collections
import json
import os
import sys
import urllib.request
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Histogram bucket boundaries (in days)
BUCKETS = [
    ("negative (< 0)", lambda d: d < 0),
    ("0-7 days",       lambda d: 0 <= d <= 7),
    ("8-30 days",      lambda d: 8 <= d <= 30),
    ("31-90 days",     lambda d: 31 <= d <= 90),
    ("91-365 days",    lambda d: 91 <= d <= 365),
    ("365+ days",      lambda d: d > 365),
]

# Known zero-days with attribution context.  These were exploited in the wild
# before the vendor released a patch (confirmed by incident reports, not just
# TTE arithmetic).
KNOWN_ZERO_DAYS = {
    "CVE-2022-40684": {"vendor": "Fortinet", "days_before_patch": "8",
                       "source": "Private customer notification Oct 3, KEV Oct 11 2022 (pre-PoC)"},
    "CVE-2021-44168": {"vendor": "Fortinet", "days_before_patch": "unknown",
                       "source": "KEV dateAdded precedes NVD publication (negative TTE)"},
    "CVE-2022-42475": {"vendor": "Fortinet", "days_before_patch": "unknown",
                       "source": "Mandiant/UNC3886"},
    "CVE-2023-27997": {"vendor": "Fortinet", "days_before_patch": "3-4",
                       "source": "watchTowr/Lexfo (silent patch)"},
    "CVE-2024-21762": {"vendor": "Fortinet", "days_before_patch": "0-1",
                       "source": "CISA KEV day after advisory"},
    "CVE-2024-55591": {"vendor": "Fortinet", "days_before_patch": "0",
                       "source": "Arctic Wolf (auth bypass, KEV same-day)"},
    "CVE-2026-24858": {"vendor": "Fortinet", "days_before_patch": "13",
                       "source": "Arctic Wolf (Jan 15 exploit, Jan 28 patch)"},
    "CVE-2023-46805": {"vendor": "Ivanti", "days_before_patch": "weeks",
                       "source": "Mandiant/UNC5221"},
    "CVE-2024-21887": {"vendor": "Ivanti", "days_before_patch": "weeks",
                       "source": "Mandiant/UNC5221 (chained with 46805)"},
    "CVE-2025-0282":  {"vendor": "Ivanti", "days_before_patch": "unknown",
                       "source": "CISA KEV / Mandiant"},
    "CVE-2025-22457": {"vendor": "Ivanti", "days_before_patch": "unknown",
                       "source": "Mandiant/UNC5221 (Connect Secure RCE)"},
    "CVE-2024-20353": {"vendor": "Cisco", "days_before_patch": "unknown",
                       "source": "Talos/ArcaneDoor (UAT4356)"},
    "CVE-2024-20359": {"vendor": "Cisco", "days_before_patch": "unknown",
                       "source": "Talos/ArcaneDoor (UAT4356)"},
    "CVE-2024-3400":  {"vendor": "Palo Alto Networks", "days_before_patch": "19",
                       "source": "Volexity/UTA0218"},
    "CVE-2019-19781": {"vendor": "Citrix", "days_before_patch": "unknown",
                       "source": "Mitigation-only for weeks; patch delayed"},
    "CVE-2023-3519":  {"vendor": "Citrix", "days_before_patch": "unknown",
                       "source": "CISA advisory AA23-201A"},
    "CVE-2023-4966":  {"vendor": "Citrix", "days_before_patch": "unknown",
                       "source": "Citrix Bleed / Mandiant"},
    "CVE-2020-5902":  {"vendor": "F5", "days_before_patch": "0-1",
                       "source": "Mass scanning within hours of disclosure"},
    "CVE-2020-12271": {"vendor": "Sophos", "days_before_patch": "unknown",
                       "source": "Sophos/Pacific Rim (Asnarok)"},
    "CVE-2022-1040":  {"vendor": "Sophos", "days_before_patch": "unknown",
                       "source": "Sophos/Pacific Rim"},
    "CVE-2021-20016": {"vendor": "SonicWall", "days_before_patch": "unknown",
                       "source": "SonicWall advisory"},
    "CVE-2019-11510": {"vendor": "Ivanti", "days_before_patch": "unknown",
                       "source": "Mass exploitation Aug 2019 (Pulse Secure)"},
    "CVE-2015-7755":  {"vendor": "Juniper", "days_before_patch": "years",
                       "source": "ScreenOS backdoor (discovered Dec 2015)"},
    "CVE-2024-24919": {"vendor": "Check Point", "days_before_patch": "0",
                       "source": "mnemonic.io (exploitation before advisory)"},
}


def parse_date(s):
    """Parse YYYY-MM-DD string to datetime, return None on failure."""
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def fetch_kev_catalog():
    """Fetch the live CISA KEV JSON feed. Returns dict keyed by CVE ID."""
    print("# Fetching live CISA KEV catalog ...", file=sys.stderr)
    req = urllib.request.Request(KEV_URL,
                                headers={"User-Agent": "edge-sec-gt/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        kev = json.loads(resp.read())
    return {v["cveID"]: v for v in kev["vulnerabilities"]}


def load_data(enriched_path, counts_path, kev_lookup):
    """Load enriched + counts JSON, merge with KEV catalog data.

    Returns list of dicts, one per CVE, with vendor, published date,
    kev_date_added, tte_days, and metadata.
    """
    with open(enriched_path) as f:
        enriched = json.load(f)
    with open(counts_path) as f:
        counts = json.load(f)

    entries = []
    for vendor, cve_list in counts.items():
        if vendor.startswith("_"):
            continue
        if not isinstance(cve_list, list):
            continue

        vendor_enriched = enriched.get(vendor, {})

        for cve_id in cve_list:
            cve_data = vendor_enriched.get(cve_id, {})
            kev_entry = kev_lookup.get(cve_id, {})

            pub_date_str = cve_data.get("published")
            # Fall back to the enriched JSON so the documented offline path
            # (--no-fetch) reproduces the full dataset instead of emitting zeros.
            kev_date_str = kev_entry.get("dateAdded") or cve_data.get("kev_date_added")
            pub_date = parse_date(pub_date_str)
            kev_date = parse_date(kev_date_str)
            due_date = parse_date(kev_entry.get("dueDate") or cve_data.get("kev_due_date"))

            tte_days = None
            if kev_date and pub_date:
                tte_days = (kev_date - pub_date).days

            remediation_window = None
            if kev_date and due_date:
                remediation_window = (due_date - kev_date).days

            is_confirmed_zeroday = cve_id in KNOWN_ZERO_DAYS
            is_tte_zeroday = (tte_days is not None and tte_days <= 0)

            entries.append({
                "vendor": vendor,
                "cve": cve_id,
                "published": pub_date_str,
                "kev_date_added": kev_date_str,
                "tte_days": tte_days,
                "remediation_window": remediation_window,
                "is_confirmed_zeroday": is_confirmed_zeroday,
                "is_tte_zeroday": is_tte_zeroday,
                "ransomware": kev_entry.get("knownRansomwareCampaignUse",
                                            "Unknown") == "Known",
                "cvss": cve_data.get("cvss"),
                "cvss_severity": cve_data.get("cvss_severity"),
                "cwe": cve_data.get("cwe"),
                "cwe_name": cve_data.get("cwe_name"),
                "epss": cve_data.get("epss"),
                "kev_product": kev_entry.get("product", ""),
                "kev_short_desc": kev_entry.get("shortDescription", ""),
            })

    return entries


def median(vals):
    """Return median of a sorted list."""
    n = len(vals)
    if n == 0:
        return None
    if n % 2 == 1:
        return vals[n // 2]
    return (vals[n // 2 - 1] + vals[n // 2]) / 2


def compute_analysis(entries):
    """Compute all TTE analysis results."""
    results = {}

    # --- 4a. TTE distribution histogram ---
    with_tte = [e for e in entries if e["tte_days"] is not None]
    tte_vals = sorted(e["tte_days"] for e in with_tte)

    histogram = []
    for label, predicate in BUCKETS:
        count = sum(1 for t in tte_vals if predicate(t))
        pct = 100 * count / len(tte_vals) if tte_vals else 0
        histogram.append({"bucket": label, "count": count, "pct": pct})
    results["histogram"] = histogram

    if tte_vals:
        results["tte_overall"] = {
            "n": len(tte_vals),
            "mean": sum(tte_vals) / len(tte_vals),
            "median": median(tte_vals),
            "min": min(tte_vals),
            "max": max(tte_vals),
            "stdev": (sum((t - sum(tte_vals)/len(tte_vals))**2
                          for t in tte_vals) / len(tte_vals)) ** 0.5,
        }
    else:
        results["tte_overall"] = {"n": 0}

    # --- 4b. Per-vendor mean/median TTE ---
    vendor_tte = collections.defaultdict(list)
    vendor_total = collections.Counter(e["vendor"] for e in entries)
    for e in with_tte:
        vendor_tte[e["vendor"]].append(e["tte_days"])

    vendor_stats = {}
    for v in sorted(vendor_tte):
        vals = sorted(vendor_tte[v])
        n = len(vals)
        vendor_stats[v] = {
            "total_cves": vendor_total[v],
            "tte_count": n,
            "mean": sum(vals) / n,
            "median": median(vals),
            "min": min(vals),
            "max": max(vals),
            "zero_day_tte": sum(1 for t in vals if t <= 0),
        }
    results["vendor_tte"] = vendor_stats

    # --- 4c. TTE trend over time ---
    # Group by NVD publication year to see if TTE is shrinking
    year_tte = collections.defaultdict(list)
    for e in with_tte:
        pub = parse_date(e["published"])
        if pub:
            year_tte[pub.year].append(e["tte_days"])

    trend = {}
    for year in sorted(year_tte):
        vals = sorted(year_tte[year])
        trend[year] = {
            "n": len(vals),
            "mean": sum(vals) / len(vals),
            "median": median(vals),
        }
    results["trend_by_pub_year"] = trend

    # Also by KEV addition year
    kev_year_counts = collections.Counter()
    kev_year_zerodays = collections.Counter()
    for e in entries:
        kev_d = parse_date(e.get("kev_date_added"))
        if kev_d:
            kev_year_counts[kev_d.year] += 1
            if e["is_confirmed_zeroday"]:
                kev_year_zerodays[kev_d.year] += 1
    results["kev_year_counts"] = dict(sorted(kev_year_counts.items()))
    results["kev_year_zerodays"] = dict(sorted(kev_year_zerodays.items()))

    # --- 4d. All zero-days (TTE <= 0 OR confirmed) ---
    all_zerodays = []
    for e in entries:
        if e["is_confirmed_zeroday"] or e["is_tte_zeroday"]:
            info = KNOWN_ZERO_DAYS.get(e["cve"], {})
            all_zerodays.append({
                "cve": e["cve"],
                "vendor": e["vendor"],
                "tte_days": e["tte_days"],
                "published": e["published"],
                "kev_date_added": e["kev_date_added"],
                "confirmed": e["is_confirmed_zeroday"],
                "source": info.get("source", "TTE computation"),
                "days_before_patch": info.get("days_before_patch", "N/A"),
            })
    all_zerodays.sort(key=lambda x: (x["tte_days"] if x["tte_days"] is not None else 9999))
    results["zero_days"] = all_zerodays

    # Zero-days by vendor
    zd_by_vendor = collections.Counter()
    for zd in all_zerodays:
        zd_by_vendor[zd["vendor"]] += 1
    results["zero_days_by_vendor"] = dict(zd_by_vendor.most_common())

    # --- 4e. Top 10 fastest-exploited ---
    fastest = sorted(with_tte, key=lambda e: e["tte_days"])[:10]
    results["fastest_exploited"] = [
        {
            "cve": e["cve"],
            "vendor": e["vendor"],
            "tte_days": e["tte_days"],
            "published": e["published"],
            "kev_date_added": e["kev_date_added"],
            "cvss": e["cvss"],
            "cwe": e["cwe"],
            "confirmed_zeroday": e["is_confirmed_zeroday"],
        }
        for e in fastest
    ]

    # Ransomware CVEs
    ransomware = [e for e in entries if e["ransomware"]]
    results["ransomware_count"] = len(ransomware)
    results["ransomware_cves"] = [
        {"cve": e["cve"], "vendor": e["vendor"],
         "kev_date_added": e["kev_date_added"], "tte_days": e["tte_days"]}
        for e in sorted(ransomware, key=lambda x: x.get("kev_date_added") or "")
    ]

    # Missing data
    no_kev = [e for e in entries if e["kev_date_added"] is None]
    no_pub = [e for e in entries if e["published"] is None]
    results["missing"] = {
        "no_kev_date": [e["cve"] for e in no_kev],
        "no_published_date": [e["cve"] for e in no_pub],
        "no_tte_computable": len(entries) - len(with_tte),
    }

    results["total_cves"] = len(entries)

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def fmt_text(entries, results):
    lines = []
    p = lines.append

    p("=" * 78)
    p("TIME-TO-EXPLOIT (TTE) ANALYSIS -- Edge Security Ground Truth")
    p("=" * 78)
    p(f"\nTotal edge CVEs analyzed: {results['total_cves']}")
    p(f"CVEs with computable TTE: {results['tte_overall'].get('n', 0)}")
    p(f"Missing KEV dateAdded: {len(results['missing']['no_kev_date'])}")
    p(f"Missing NVD published: {len(results['missing']['no_published_date'])}")

    tte = results["tte_overall"]
    if tte["n"]:
        p(f"\n--- TTE Summary (KEV dateAdded - NVD published) ---")
        p(f"  Mean:   {tte['mean']:.1f} days")
        p(f"  Median: {tte['median']:.0f} days")
        p(f"  Std:    {tte['stdev']:.1f} days")
        p(f"  Min:    {tte['min']} days")
        p(f"  Max:    {tte['max']} days")

    p(f"\n--- TTE Distribution ---")
    p(f"  {'Bucket':<20} {'Count':>5} {'%':>6}")
    p(f"  {'-'*20} {'-'*5} {'-'*6}")
    for b in results["histogram"]:
        bar = "#" * int(b["pct"] / 2)
        p(f"  {b['bucket']:<20} {b['count']:>5} {b['pct']:>5.1f}%  {bar}")

    p(f"\n--- Per-Vendor TTE ---")
    p(f"  {'Vendor':<22} {'n':>3} {'Mean':>7} {'Med':>5} "
      f"{'Min':>5} {'Max':>5} {'0-day':>5}")
    p(f"  {'-'*22} {'-'*3} {'-'*7} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")
    for v, s in sorted(results["vendor_tte"].items()):
        p(f"  {v:<22} {s['tte_count']:>3} {s['mean']:>7.0f} "
          f"{s['median']:>5.0f} {s['min']:>5} {s['max']:>5} "
          f"{s['zero_day_tte']:>5}")

    p(f"\n--- Top 10 Fastest-Exploited CVEs ---")
    p(f"  {'CVE':<18} {'Vendor':<22} {'TTE':>5} {'Published':>12} "
      f"{'KEV Added':>12} {'0day':>4}")
    p(f"  {'-'*18} {'-'*22} {'-'*5} {'-'*12} {'-'*12} {'-'*4}")
    for e in results["fastest_exploited"]:
        zd = "YES" if e["confirmed_zeroday"] else ""
        p(f"  {e['cve']:<18} {e['vendor']:<22} {e['tte_days']:>5} "
          f"{e['published'] or 'N/A':>12} {e['kev_date_added'] or 'N/A':>12} "
          f"{zd:>4}")

    p(f"\n--- Confirmed Zero-Days ({len(results['zero_days'])}) ---")
    for zd in results["zero_days"]:
        conf = " [CONFIRMED]" if zd["confirmed"] else " [TTE<=0]"
        p(f"  {zd['cve']} ({zd['vendor']}) TTE={zd['tte_days']}d"
          f"  -- {zd['source']}{conf}")

    p(f"\n--- Zero-Days by Vendor ---")
    for v, c in sorted(results["zero_days_by_vendor"].items(),
                       key=lambda x: -x[1]):
        total = results["vendor_tte"].get(v, {}).get("tte_count",
                    sum(1 for e in entries if e["vendor"] == v))
        pct = 100 * c / total if total else 0
        p(f"  {v}: {c} zero-days / {total} CVEs ({pct:.0f}%)")

    p(f"\n--- TTE Trend by NVD Publication Year ---")
    p(f"  {'Year':>4} {'n':>3} {'Mean TTE':>9} {'Median TTE':>11}")
    p(f"  {'-'*4} {'-'*3} {'-'*9} {'-'*11}")
    for year, t in sorted(results["trend_by_pub_year"].items()):
        p(f"  {year:>4} {t['n']:>3} {t['mean']:>8.0f}d {t['median']:>10.0f}d")

    p(f"\n--- KEV Additions by Year ---")
    for year in sorted(results["kev_year_counts"]):
        total_y = results["kev_year_counts"][year]
        zd_y = results["kev_year_zerodays"].get(year, 0)
        bar = "#" * total_y
        p(f"  {year}: {total_y:>3} additions ({zd_y} zero-day)  {bar}")

    p(f"\n--- Ransomware-Associated CVEs ({results['ransomware_count']}) ---")
    for r in results["ransomware_cves"]:
        p(f"  {r['cve']} ({r['vendor']}) KEV={r['kev_date_added']} "
          f"TTE={r['tte_days']}d")

    return "\n".join(lines)


def fmt_markdown(entries, results):
    lines = []
    p = lines.append

    p("# Time-to-Exploit (TTE) Analysis\n")
    p(f"**{results['total_cves']}** edge CVEs analyzed across "
      f"{len(results['vendor_tte'])} vendors.\n")

    tte = results["tte_overall"]
    if tte["n"]:
        p("## TTE Summary\n")
        p("TTE = CISA KEV `dateAdded` - NVD `publishedDate` (days). "
          "Negative = exploitation confirmed before NVD publication.\n")
        p("| Metric | Value |")
        p("|--------|------:|")
        p(f"| CVEs with TTE | {tte['n']} |")
        p(f"| Mean | {tte['mean']:.1f} days |")
        p(f"| Median | {tte['median']:.0f} days |")
        p(f"| Std Dev | {tte['stdev']:.1f} days |")
        p(f"| Min | {tte['min']} days |")
        p(f"| Max | {tte['max']} days |")

    p("\n## TTE Distribution\n")
    p("| Bucket | Count | % | Bar |")
    p("|--------|------:|--:|-----|")
    for b in results["histogram"]:
        bar = "=" * max(1, int(b["pct"] / 2))
        p(f"| {b['bucket']} | {b['count']} | {b['pct']:.1f}% | {bar} |")

    p("\n## Per-Vendor TTE\n")
    p("| Vendor | CVEs | TTE n | Mean | Median | Min | Max | Zero-Day |")
    p("|--------|-----:|------:|-----:|-------:|----:|----:|---------:|")
    for v, s in sorted(results["vendor_tte"].items()):
        p(f"| {v} | {s['total_cves']} | {s['tte_count']} | "
          f"{s['mean']:.0f} | {s['median']:.0f} | {s['min']} | "
          f"{s['max']} | {s['zero_day_tte']} |")

    p("\n## Top 10 Fastest-Exploited CVEs\n")
    p("| Rank | CVE | Vendor | TTE (days) | Published | KEV Added "
      "| Confirmed 0-day |")
    p("|-----:|-----|--------|----------:|-----------|-----------|"
      ":--------------:|")
    for i, e in enumerate(results["fastest_exploited"], 1):
        zd = "YES" if e["confirmed_zeroday"] else ""
        p(f"| {i} | {e['cve']} | {e['vendor']} | {e['tte_days']} | "
          f"{e['published'] or 'N/A'} | {e['kev_date_added'] or 'N/A'} | "
          f"{zd} |")

    p("\n## Confirmed Zero-Days\n")
    p(f"**{len(results['zero_days'])}** CVEs exploited at or before disclosure:\n")
    p("| CVE | Vendor | TTE (days) | Source | Days Pre-Patch |")
    p("|-----|--------|----------:|--------|:--------------:|")
    for zd in results["zero_days"]:
        p(f"| {zd['cve']} | {zd['vendor']} | "
          f"{zd['tte_days'] if zd['tte_days'] is not None else 'N/A'} | "
          f"{zd['source']} | {zd['days_before_patch']} |")

    p("\n### Zero-Days by Vendor\n")
    p("| Vendor | Zero-Days | Total CVEs | % |")
    p("|--------|----------:|-----------:|--:|")
    vendor_total = collections.Counter(e["vendor"] for e in entries)
    for v, c in sorted(results["zero_days_by_vendor"].items(),
                       key=lambda x: -x[1]):
        total = vendor_total[v]
        pct = 100 * c / total if total else 0
        p(f"| {v} | {c} | {total} | {pct:.0f}% |")

    p("\n## TTE Trend by Publication Year\n")
    p("Is exploitation getting faster over time?\n")
    p("| Year | n | Mean TTE | Median TTE |")
    p("|------|--:|---------:|-----------:|")
    for year, t in sorted(results["trend_by_pub_year"].items()):
        p(f"| {year} | {t['n']} | {t['mean']:.0f} days | "
          f"{t['median']:.0f} days |")

    p("\n## KEV Additions by Year\n")
    p("| Year | Edge KEV Additions | Zero-Days |")
    p("|------|-------------------:|----------:|")
    for year in sorted(results["kev_year_counts"]):
        total_y = results["kev_year_counts"][year]
        zd_y = results["kev_year_zerodays"].get(year, 0)
        p(f"| {year} | {total_y} | {zd_y} |")

    p("\n## Ransomware-Associated CVEs\n")
    p(f"**{results['ransomware_count']}** CVEs used in known ransomware "
      f"campaigns:\n")
    if results["ransomware_cves"]:
        p("| CVE | Vendor | KEV Added | TTE (days) |")
        p("|-----|--------|-----------|----------:|")
        for r in results["ransomware_cves"]:
            tte_str = str(r["tte_days"]) if r["tte_days"] is not None else "N/A"
            p(f"| {r['cve']} | {r['vendor']} | "
              f"{r['kev_date_added'] or 'N/A'} | {tte_str} |")

    return "\n".join(lines)


def fmt_json(entries, results):
    out = {
        "total_cves": results["total_cves"],
        "tte_overall": results["tte_overall"],
        "histogram": results["histogram"],
        "vendor_tte": results["vendor_tte"],
        "fastest_exploited": results["fastest_exploited"],
        "zero_days": results["zero_days"],
        "zero_days_by_vendor": results["zero_days_by_vendor"],
        "trend_by_pub_year": {str(k): v for k, v
                              in results["trend_by_pub_year"].items()},
        "kev_year_counts": results["kev_year_counts"],
        "ransomware_count": results["ransomware_count"],
        "ransomware_cves": results["ransomware_cves"],
        "missing": results["missing"],
    }
    return json.dumps(out, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Time-to-exploit (TTE) analysis for edge CVEs.")
    parser.add_argument("--enriched", "-e", default=ENRICHED_PATH,
                        help="Path to kev_edge_enriched.json")
    parser.add_argument("--counts", "-c", default=COUNTS_PATH,
                        help="Path to kev_edge_counts.json")
    parser.add_argument("--format", "-f",
                        choices=["text", "markdown", "json"],
                        default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", "-o",
                        help="Write output to file instead of stdout")
    parser.add_argument("--no-fetch", action="store_true",
                        help="Skip live KEV fetch (use empty KEV data)")
    args = parser.parse_args()

    for path, label in [(args.enriched, "enriched"),
                        (args.counts, "counts")]:
        if not os.path.isfile(path):
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    # Fetch live KEV catalog for dateAdded
    kev_lookup = {}
    if not args.no_fetch:
        try:
            kev_lookup = fetch_kev_catalog()
            print(f"# KEV catalog: {len(kev_lookup)} vulnerabilities",
                  file=sys.stderr)
        except Exception as e:
            print(f"# WARNING: KEV fetch failed: {e}", file=sys.stderr)
            print("# Proceeding without KEV dateAdded data", file=sys.stderr)

    entries = load_data(args.enriched, args.counts, kev_lookup)
    results = compute_analysis(entries)

    formatters = {
        "text": fmt_text,
        "markdown": fmt_markdown,
        "json": fmt_json,
    }
    output = formatters[args.format](entries, results)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
            if not output.endswith("\n"):
                f.write("\n")
        print(f"# Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
