#!/usr/bin/env python3
"""
Cross-vendor pattern analysis for edge-security-ground-truth.

Analyzes CISA KEV edge-appliance exploitation patterns across vendors:
  1. Timeline    — KEV additions by year per vendor
  2. Concentration — what % of total edge KEVs does each vendor account for?
  3. YoY trend   — are edge KEV additions accelerating?
  4. EPSS        — mean/median/max per vendor (if kev_edge_enriched.json exists)

Usage:
  python3 scripts/analyze_patterns.py                       # table output
  python3 scripts/analyze_patterns.py --format markdown     # markdown tables
  python3 scripts/analyze_patterns.py --format json         # machine-readable
  python3 scripts/analyze_patterns.py --output report.md --format markdown
"""
import argparse
import collections
import json
import math
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")

# Same scope rules as build_kev_counts.py — kept in sync.
SCOPE = {
    "SonicWall":          dict(include=r"SonicOS|SMA|SSLVPN|SSL[- ]?VPN|Secure Remote Access|SRA",
                               exclude=r"Email Security"),
    "Ivanti":             dict(include=r"Connect Secure|Pulse Connect Secure|Policy Secure",
                               exclude=r"MobileIron|Endpoint Manager|EPMM|EPM|Sentry|Cloud Services Appliance|Virtual Traffic Manager"),
    "Juniper":            dict(include=r"Junos OS|ScreenOS",
                               exclude=r""),
    "Cisco":              dict(include=r"Adaptive Security Appliance|ASA|Firepower Threat Defense|FTD|Secure Firewall",
                               exclude=r"Management Center|FMC"),
    "Palo Alto Networks": dict(include=r"PAN-OS",
                               exclude=r"Expedition"),
    "Fortinet":           dict(include=r"FortiOS|FortiProxy",
                               exclude=r"FortiClient|FortiManager|FortiWeb|FortiMail|FortiVoice|FortiNDR"),
    "Check Point":        dict(include=r"Quantum|CloudGuard|Security Gateway|Gaia",
                               exclude=r"Endpoint|Harmony|SmartConsole|ZoneAlarm"),
    "Citrix":             dict(include=r"NetScaler ADC|NetScaler Gateway|Citrix ADC|Citrix Gateway|Application Delivery Controller",
                               exclude=r"Workspace|XenApp|XenDesktop|ShareFile|Endpoint Management"),
    "F5":                 dict(include=r"BIG-IP",
                               exclude=r"BIG-IQ|NGINX"),
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def fetch_kev():
    """Fetch the live CISA KEV feed."""
    print("# Fetching live CISA KEV feed ...", file=sys.stderr)
    with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
        return json.loads(resp.read())


def load_counts():
    """Load the pre-built edge counts JSON."""
    with open(COUNTS_PATH) as f:
        return json.load(f)


def load_enriched():
    """Load the enriched JSON (with EPSS data) if it exists."""
    if not os.path.isfile(ENRICHED_PATH):
        return None
    with open(ENRICHED_PATH) as f:
        return json.load(f)


def match_edge_vulns(kev_data, counts):
    """Match KEV entries to our edge-vendor CVE sets and return per-CVE detail."""
    # Build a reverse map: CVE -> vendor
    cve_vendor = {}
    for vendor, cves in counts.items():
        if vendor.startswith("_"):
            continue
        for cve in cves:
            cve_vendor[cve] = vendor

    # Walk KEV feed and attach dateAdded
    matched = []
    for v in kev_data.get("vulnerabilities", []):
        cve_id = v.get("cveID", "")
        if cve_id in cve_vendor:
            matched.append({
                "cve": cve_id,
                "vendor": cve_vendor[cve_id],
                "dateAdded": v.get("dateAdded", ""),
                "product": v.get("product", ""),
            })
            del cve_vendor[cve_id]  # avoid dups

    # Any CVEs in counts but not in live KEV (future-dated or synthetic ground-truth entries)
    for cve_id, vendor in cve_vendor.items():
        # Extract year from CVE ID as fallback
        year_match = re.match(r"CVE-(\d{4})-", cve_id)
        fallback_year = year_match.group(1) if year_match else "unknown"
        matched.append({
            "cve": cve_id,
            "vendor": vendor,
            "dateAdded": "",
            "product": "(not in live KEV feed)",
            "_fallback_year": fallback_year,
        })

    return matched


# ---------------------------------------------------------------------------
# Analysis dimensions
# ---------------------------------------------------------------------------

def analyze_timeline(matched):
    """Dimension 1: KEV additions by year per vendor."""
    # vendor -> year -> count
    timeline = collections.defaultdict(lambda: collections.defaultdict(int))
    all_years = set()

    for m in matched:
        vendor = m["vendor"]
        if m["dateAdded"]:
            year = m["dateAdded"][:4]
        else:
            year = m.get("_fallback_year", "unknown")
        timeline[vendor][year] += 1
        all_years.add(year)

    # Sort years
    years = sorted(y for y in all_years if y != "unknown")
    if "unknown" in all_years:
        years.append("unknown")

    return dict(timeline), years


def analyze_concentration(counts):
    """Dimension 2: vendor concentration (% of total edge KEVs)."""
    meta = counts.get("_metadata", {}).get("counts", {})
    total = sum(meta.values())
    concentration = {}
    for vendor, count in sorted(meta.items(), key=lambda x: -x[1]):
        pct = (count / total * 100) if total else 0
        concentration[vendor] = {"count": count, "pct": round(pct, 1), "total": total}
    return concentration


def analyze_yoy_trend(matched):
    """Dimension 3: year-over-year trend across all vendors."""
    current_year = datetime.now(timezone.utc).strftime("%Y")
    year_counts = collections.Counter()
    for m in matched:
        if m["dateAdded"]:
            year = m["dateAdded"][:4]
        else:
            year = m.get("_fallback_year", "unknown")
        if year != "unknown":
            year_counts[year] += 1

    years = sorted(year_counts.keys())
    trend = []
    for i, y in enumerate(years):
        entry = {"year": y, "count": year_counts[y], "partial": (y == current_year)}
        if i > 0:
            prev = year_counts[years[i - 1]]
            if prev > 0:
                entry["change_pct"] = round((year_counts[y] - prev) / prev * 100, 1)
            else:
                entry["change_pct"] = None
        else:
            entry["change_pct"] = None
        trend.append(entry)

    # Compute trend on COMPLETE years only (exclude current partial year)
    complete_years = [y for y in years if y != current_year]
    if len(complete_years) >= 2:
        xs = list(range(len(complete_years)))
        ys = [year_counts[y] for y in complete_years]
        n = len(xs)
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
        den = sum((xs[i] - mean_x) ** 2 for i in range(n))
        slope = num / den if den else 0
        direction = "accelerating" if slope > 0.5 else ("decelerating" if slope < -0.5 else "stable")
    else:
        slope = 0
        direction = "insufficient data"

    return trend, round(slope, 2), direction


def analyze_epss(enriched, counts):
    """Dimension 4: EPSS analysis per vendor (if enriched data exists)."""
    if not enriched:
        return None

    # Build vendor -> list of EPSS scores
    vendor_epss = collections.defaultdict(list)

    # The enriched JSON may have different structures; try common patterns
    for vendor, entries in enriched.items():
        if vendor.startswith("_"):
            continue
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    epss = entry.get("epss") or entry.get("epss_score")
                    if epss is not None:
                        try:
                            vendor_epss[vendor].append(float(epss))
                        except (ValueError, TypeError):
                            pass
                elif isinstance(entry, str):
                    # Just a CVE ID string — no EPSS data inline
                    pass
        elif isinstance(entries, dict):
            epss = entries.get("epss") or entries.get("epss_score")
            if epss is not None:
                try:
                    vendor_epss[vendor].append(float(epss))
                except (ValueError, TypeError):
                    pass

    if not vendor_epss:
        return None

    result = {}
    for vendor in sorted(vendor_epss.keys()):
        scores = sorted(vendor_epss[vendor])
        n = len(scores)
        if n == 0:
            continue
        mean_val = sum(scores) / n
        if n % 2 == 0:
            median_val = (scores[n // 2 - 1] + scores[n // 2]) / 2
        else:
            median_val = scores[n // 2]
        result[vendor] = {
            "count": n,
            "mean": round(mean_val, 4),
            "median": round(median_val, 4),
            "max": round(max(scores), 4),
            "min": round(min(scores), 4),
        }
    return result if result else None


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def fmt_table(timeline, years, concentration, trend, slope, direction, epss, generated_at):
    """Plain-text table output."""
    lines = []
    lines.append(f"Edge-KEV Cross-Vendor Analysis  |  Generated: {generated_at}")
    lines.append("=" * 78)

    # --- Dimension 1: Timeline ---
    lines.append("")
    lines.append("1. TIMELINE: KEV additions by year per vendor")
    lines.append("-" * 78)

    # Header
    hdr = f"{'Vendor':<22}"
    for y in years:
        hdr += f" {y:>6}"
    hdr += f" {'Total':>6}"
    lines.append(hdr)
    lines.append("-" * len(hdr))

    vendors_sorted = sorted(timeline.keys(),
                            key=lambda v: -sum(timeline[v].values()))
    for vendor in vendors_sorted:
        row = f"{vendor:<22}"
        total = 0
        for y in years:
            c = timeline[vendor].get(y, 0)
            total += c
            row += f" {c:>6}" if c else f" {'--':>6}"
        row += f" {total:>6}"
        lines.append(row)

    # Totals row
    row = f"{'TOTAL':<22}"
    grand = 0
    for y in years:
        c = sum(timeline[v].get(y, 0) for v in timeline)
        grand += c
        row += f" {c:>6}"
    row += f" {grand:>6}"
    lines.append("-" * len(hdr))
    lines.append(row)

    # --- Dimension 2: Concentration ---
    lines.append("")
    lines.append("2. VENDOR CONCENTRATION")
    lines.append("-" * 50)
    lines.append(f"{'Vendor':<22} {'Count':>6} {'%':>7}  Bar")
    lines.append("-" * 50)
    for vendor, data in concentration.items():
        bar = "#" * int(data["pct"] / 2)
        lines.append(f"{vendor:<22} {data['count']:>6} {data['pct']:>6.1f}%  {bar}")
    lines.append(f"{'TOTAL':<22} {list(concentration.values())[0]['total'] if concentration else 0:>6} {'100.0':>6}%")

    # --- Dimension 3: YoY Trend ---
    lines.append("")
    lines.append("3. YEAR-OVER-YEAR TREND")
    lines.append("-" * 50)
    lines.append(f"{'Year':<8} {'Count':>6} {'YoY Change':>12}  Note")
    lines.append("-" * 58)
    for t in trend:
        change = f"{t['change_pct']:>+.1f}%" if t["change_pct"] is not None else "       --"
        note = "  (partial year)" if t.get("partial") else ""
        lines.append(f"{t['year']:<8} {t['count']:>6} {change:>12}{note}")
    lines.append("-" * 58)
    lines.append(f"Linear slope: {slope:+.2f} CVEs/year  =>  {direction}")
    lines.append(f"  (slope computed on complete years only; partial year excluded)")

    # --- Dimension 4: EPSS ---
    if epss:
        lines.append("")
        lines.append("4. EPSS ANALYSIS (exploitation probability within 30 days)")
        lines.append("-" * 62)
        lines.append(f"{'Vendor':<22} {'N':>4} {'Mean':>8} {'Median':>8} {'Max':>8} {'Min':>8}")
        lines.append("-" * 62)
        for vendor, data in sorted(epss.items(), key=lambda x: -x[1]["mean"]):
            lines.append(f"{vendor:<22} {data['count']:>4} {data['mean']:>8.4f} {data['median']:>8.4f} {data['max']:>8.4f} {data['min']:>8.4f}")

    return "\n".join(lines)


def fmt_markdown(timeline, years, concentration, trend, slope, direction, epss, generated_at):
    """Markdown table output."""
    lines = []
    lines.append(f"# Edge-KEV Cross-Vendor Analysis")
    lines.append(f"")
    lines.append(f"Generated: {generated_at}")
    lines.append("")

    # --- Dimension 1: Timeline ---
    lines.append("## 1. Timeline: KEV additions by year per vendor")
    lines.append("")
    hdr = "| Vendor |"
    sep = "|--------|"
    for y in years:
        hdr += f" {y} |"
        sep += "-----:|"
    hdr += " Total |"
    sep += "------:|"
    lines.append(hdr)
    lines.append(sep)

    vendors_sorted = sorted(timeline.keys(),
                            key=lambda v: -sum(timeline[v].values()))
    for vendor in vendors_sorted:
        row = f"| {vendor} |"
        total = 0
        for y in years:
            c = timeline[vendor].get(y, 0)
            total += c
            row += f" {c if c else '--'} |"
        row += f" **{total}** |"
        lines.append(row)

    # Totals
    row = "| **TOTAL** |"
    grand = 0
    for y in years:
        c = sum(timeline[v].get(y, 0) for v in timeline)
        grand += c
        row += f" **{c}** |"
    row += f" **{grand}** |"
    lines.append(row)

    # --- Dimension 2: Concentration ---
    lines.append("")
    lines.append("## 2. Vendor concentration")
    lines.append("")
    lines.append("| Vendor | Edge KEVs | % of Total |")
    lines.append("|--------|----------:|-----------:|")
    for vendor, data in concentration.items():
        lines.append(f"| {vendor} | {data['count']} | {data['pct']:.1f}% |")
    total_n = list(concentration.values())[0]["total"] if concentration else 0
    lines.append(f"| **TOTAL** | **{total_n}** | **100.0%** |")

    # --- Dimension 3: YoY Trend ---
    lines.append("")
    lines.append("## 3. Year-over-year trend")
    lines.append("")
    lines.append("| Year | Count | YoY Change | Note |")
    lines.append("|------|------:|-----------:|------|")
    for t in trend:
        change = f"{t['change_pct']:+.1f}%" if t["change_pct"] is not None else "--"
        note = "partial year" if t.get("partial") else ""
        lines.append(f"| {t['year']} | {t['count']} | {change} | {note} |")
    lines.append("")
    lines.append(f"**Linear slope:** {slope:+.2f} CVEs/year => **{direction}**")
    lines.append(f"_(slope computed on complete years only; partial year excluded)_")

    # --- Dimension 4: EPSS ---
    if epss:
        lines.append("")
        lines.append("## 4. EPSS analysis (exploitation probability within 30 days)")
        lines.append("")
        lines.append("| Vendor | N | Mean | Median | Max | Min |")
        lines.append("|--------|--:|-----:|-------:|----:|----:|")
        for vendor, data in sorted(epss.items(), key=lambda x: -x[1]["mean"]):
            lines.append(f"| {vendor} | {data['count']} | {data['mean']:.4f} | {data['median']:.4f} | {data['max']:.4f} | {data['min']:.4f} |")

    return "\n".join(lines)


def fmt_json(timeline, years, concentration, trend, slope, direction, epss, generated_at):
    """JSON output."""
    data = {
        "generated_at": generated_at,
        "timeline": {
            "years": years,
            "vendors": {v: dict(yd) for v, yd in timeline.items()},
        },
        "concentration": concentration,
        "yoy_trend": {
            "years": trend,
            "slope": slope,
            "direction": direction,
        },
    }
    if epss:
        data["epss"] = epss
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-vendor pattern analysis for edge-security-ground-truth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--format", "-f", choices=["table", "json", "markdown"],
                        default="table", help="Output format (default: table)")
    parser.add_argument("--output", "-o", default=None,
                        help="Write output to file instead of stdout")
    args = parser.parse_args()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Load the pre-built counts
    if not os.path.isfile(COUNTS_PATH):
        print(f"ERROR: {COUNTS_PATH} not found. Run build_kev_counts.py first.",
              file=sys.stderr)
        sys.exit(1)

    counts = load_counts()

    # Fetch live KEV feed for dateAdded timeline data
    kev_data = fetch_kev()

    # Match edge CVEs to KEV entries
    matched = match_edge_vulns(kev_data, counts)

    # Run all analysis dimensions
    timeline, years = analyze_timeline(matched)
    concentration = analyze_concentration(counts)
    trend, slope, direction = analyze_yoy_trend(matched)

    # EPSS (optional)
    enriched = load_enriched()
    epss = analyze_epss(enriched, counts)

    # Format output
    if args.format == "table":
        output = fmt_table(timeline, years, concentration, trend, slope, direction,
                           epss, generated_at)
    elif args.format == "markdown":
        output = fmt_markdown(timeline, years, concentration, trend, slope, direction,
                              epss, generated_at)
    elif args.format == "json":
        output = fmt_json(timeline, years, concentration, trend, slope, direction,
                          epss, generated_at)

    # Write or print
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
            f.write("\n")
        print(f"# Wrote analysis to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
