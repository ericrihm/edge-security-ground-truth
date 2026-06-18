#!/usr/bin/env python3
"""
Survival analysis of time-to-exploitation (TTE) for edge-security-ground-truth.

We treat each edge CVE as a subject observed from its NVD publication date and
ask: how long does it "survive" before exploitation is confirmed (the event)?

  - Time t      = TTE in days = CISA KEV dateAdded - NVD publishedDate.
  - The "event" = exploitation confirmed (the CVE appears in the CISA KEV
                  catalog). Every CVE in this corpus is eventually KEV-listed,
                  so every subject experiences the event.
  - Negative-TTE CVEs (KEV listed *before* NVD publication -- true zero-days)
    are folded to t = 0: they were already exploited at disclosure.

From these we build a Kaplan-Meier survival curve

      S(t) = P(not-yet-KEV-listed at t days post-disclosure)

for the whole corpus and stratified by vendor and by CVSS severity band.

Why survival analysis (vs. a raw mean/median of TTE)?
  - TTE is heavily right-skewed: most CVEs are KEV-listed within weeks, but a
    long tail trickles in years later (old CVEs swept into KEV retroactively).
    A mean is dragged up by that tail; the median ignores the *shape*.
  - Kaplan-Meier estimates the whole curve non-parametrically and reads the
    median off S(t) = 0.5 -- robust to the tail and to any future censoring.
  - It yields directly actionable horizon probabilities: "what fraction of
    edge CVEs are confirmed-exploited within 7 / 30 / 90 days of disclosure?"

This is implemented from first principles -- standard library only, no
lifelines / scipy / numpy. See docs/SURVIVAL-ANALYSIS.md for method + limits.

Data sources:
  - kev_edge_enriched.json  (NVD published dates, KEV dateAdded, CVSS, CWE)
  - kev_edge_counts.json    (vendor -> CVE-ID lists, used as scope filter)
  - Live CISA KEV feed       (dateAdded; --no-fetch falls back to enriched JSON)

Usage:
  python3 scripts/analyze_survival.py                    # text output
  python3 scripts/analyze_survival.py --format markdown  # markdown tables
  python3 scripts/analyze_survival.py --format json       # machine-readable
  python3 scripts/analyze_survival.py --no-fetch          # offline (enriched)
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

# Horizons (days post-disclosure) at which to report S(t).
HORIZONS = [0, 7, 30, 90, 365]

# CVSS v3.1 severity bands. We key off the enriched `cvss_severity` string but
# fall back to the numeric score so a record with only `cvss` still bands.
CVSS_BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def parse_date(s):
    """Parse YYYY-MM-DD string to datetime, return None on failure."""
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def cvss_band(severity, score):
    """Return a CVSS severity band, preferring the explicit severity string."""
    if severity and severity.upper() in CVSS_BAND_ORDER:
        return severity.upper()
    if isinstance(score, (int, float)):
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
    return "UNKNOWN"


def fetch_kev_catalog():
    """Fetch the live CISA KEV JSON feed. Returns dict keyed by CVE ID."""
    print("# Fetching live CISA KEV catalog ...", file=sys.stderr)
    req = urllib.request.Request(KEV_URL,
                                 headers={"User-Agent": "edge-sec-gt/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        kev = json.loads(resp.read())
    return {v["cveID"]: v for v in kev["vulnerabilities"]}


def load_data(enriched_path, counts_path, kev_lookup):
    """Load enriched + counts JSON, merge with KEV catalog.

    Returns a list of subject dicts, one per CVE, each with the survival time
    `t` (>= 0, negative TTE folded to 0) when computable.
    """
    with open(enriched_path) as f:
        enriched = json.load(f)
    with open(counts_path) as f:
        counts = json.load(f)

    subjects = []
    for vendor, cve_list in counts.items():
        if vendor.startswith("_") or not isinstance(cve_list, list):
            continue
        vendor_enriched = enriched.get(vendor, {})

        for cve_id in cve_list:
            cve_data = vendor_enriched.get(cve_id, {})
            kev_entry = kev_lookup.get(cve_id, {})

            pub_date = parse_date(cve_data.get("published"))
            # Offline path (--no-fetch) reproduces the full dataset from the
            # enriched JSON rather than emitting zeros.
            kev_date_str = kev_entry.get("dateAdded") or cve_data.get("kev_date_added")
            kev_date = parse_date(kev_date_str)

            tte_days = None
            if pub_date and kev_date:
                tte_days = (kev_date - pub_date).days

            # Survival time: clamp negative TTE (zero-day) to t = 0.
            t = None
            if tte_days is not None:
                t = max(0, tte_days)

            subjects.append({
                "vendor": vendor,
                "cve": cve_id,
                "tte_days": tte_days,
                "t": t,
                "zero_day": tte_days is not None and tte_days <= 0,
                "cvss": cve_data.get("cvss"),
                "cvss_band": cvss_band(cve_data.get("cvss_severity"),
                                       cve_data.get("cvss")),
            })

    return subjects


def median(vals):
    """Return median of a sorted list (or None if empty)."""
    n = len(vals)
    if n == 0:
        return None
    if n % 2 == 1:
        return vals[n // 2]
    return (vals[n // 2 - 1] + vals[n // 2]) / 2


def kaplan_meier(times):
    """Kaplan-Meier survival estimate from a list of event times.

    Every subject in this corpus experiences the event (KEV listing), so there
    is no right-censoring here -- but we implement the general product-limit
    estimator anyway so the method is honest and extensible.

    KM product-limit:  S(t) = PROD over event times t_i <= t of (1 - d_i / n_i)
      n_i = number still "at risk" (not yet event) just before t_i
      d_i = number experiencing the event exactly at t_i

    Returns (steps, n) where steps is a list of (t_i, n_i, d_i, S_after)
    dicts in ascending t order, and n is the subject count.
    """
    times = sorted(times)
    n = len(times)
    if n == 0:
        return [], 0

    # Group simultaneous event times (ties).
    counts = collections.Counter(times)
    distinct = sorted(counts)

    steps = []
    at_risk = n
    survival = 1.0
    for t_i in distinct:
        d_i = counts[t_i]
        survival *= (1.0 - d_i / at_risk)
        steps.append({
            "t": t_i,
            "n_at_risk": at_risk,
            "events": d_i,
            "survival": survival,
        })
        at_risk -= d_i
    return steps, n


def survival_at(steps, t):
    """Evaluate the KM curve S(t): the survival value after the last event
    time <= t. S(t) for t before the first event = 1.0."""
    s = 1.0
    for step in steps:
        if step["t"] <= t:
            s = step["survival"]
        else:
            break
    return s


def km_median(steps):
    """Median survival time = smallest t with S(t) <= 0.5 (KM convention)."""
    for step in steps:
        if step["survival"] <= 0.5:
            return step["t"]
    return None  # curve never drops to 0.5 (would be a censored estimate)


def curve_at_horizons(steps, horizons):
    """Return {horizon: S(horizon)} for the requested horizons."""
    return {h: survival_at(steps, h) for h in horizons}


def compute_analysis(subjects):
    """Compute overall + stratified Kaplan-Meier survival curves."""
    results = {}

    with_t = [s for s in subjects if s["t"] is not None]
    times = [s["t"] for s in with_t]

    # --- Overall corpus ---
    steps, n = kaplan_meier(times)
    raw_tte = sorted(s["tte_days"] for s in with_t)
    results["overall"] = {
        "n": n,
        "km_median": km_median(steps),
        "raw_median_tte": median(raw_tte),
        "raw_mean_tte": (sum(raw_tte) / len(raw_tte)) if raw_tte else None,
        "zero_day_count": sum(1 for s in with_t if s["zero_day"]),
        "horizons": curve_at_horizons(steps, HORIZONS),
        "steps": steps,
    }

    # --- Stratified by vendor ---
    by_vendor = collections.defaultdict(list)
    for s in with_t:
        by_vendor[s["vendor"]].append(s["t"])
    vendor_stats = {}
    for v in sorted(by_vendor):
        v_steps, v_n = kaplan_meier(by_vendor[v])
        vendor_stats[v] = {
            "n": v_n,
            "km_median": km_median(v_steps),
            "horizons": curve_at_horizons(v_steps, HORIZONS),
            "steps": v_steps,
        }
    results["by_vendor"] = vendor_stats

    # --- Stratified by CVSS band ---
    by_band = collections.defaultdict(list)
    for s in with_t:
        by_band[s["cvss_band"]].append(s["t"])
    band_stats = {}
    for band in CVSS_BAND_ORDER:
        if band not in by_band:
            continue
        b_steps, b_n = kaplan_meier(by_band[band])
        band_stats[band] = {
            "n": b_n,
            "km_median": km_median(b_steps),
            "horizons": curve_at_horizons(b_steps, HORIZONS),
            "steps": b_steps,
        }
    results["by_cvss_band"] = band_stats

    results["total_cves"] = len(subjects)
    results["no_t_computable"] = len(subjects) - len(with_t)
    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _horizon_cells(horizons):
    return [f"{horizons[h] * 100:.1f}%" for h in HORIZONS]


def fmt_text(results):
    lines = []
    p = lines.append
    ov = results["overall"]

    p("=" * 78)
    p("SURVIVAL ANALYSIS OF TIME-TO-EXPLOITATION -- Edge Security Ground Truth")
    p("=" * 78)
    p(f"\nSubjects (edge CVEs): {results['total_cves']}")
    p(f"With computable survival time: {ov['n']}")
    p(f"Not computable (missing pub or KEV date): {results['no_t_computable']}")
    p(f"Zero-days folded to t=0 (TTE <= 0): {ov['zero_day_count']}")

    p("\n--- Event definition ---")
    p("  time t = max(0, KEV dateAdded - NVD published) in days")
    p("  event  = exploitation confirmed (CISA KEV listing)")
    p("  S(t)   = P(not-yet-KEV-listed at t days post-disclosure)")

    p("\n--- Overall Kaplan-Meier ---")
    km_med = ov["km_median"]
    p(f"  KM median survival : "
      f"{km_med if km_med is not None else 'undefined'} days")
    p(f"  Raw median TTE     : {ov['raw_median_tte']:.0f} days")
    p(f"  Raw mean TTE       : {ov['raw_mean_tte']:.1f} days  "
      f"(skewed up by long tail)")

    p("\n--- Survival S(t) at key horizons ---")
    p(f"  {'Horizon':>10} {'S(t)':>8}  {'1 - S(t) (exploited by t)':>26}")
    p(f"  {'-'*10} {'-'*8}  {'-'*26}")
    for h in HORIZONS:
        s = ov["horizons"][h]
        p(f"  {str(h)+'d':>10} {s*100:>7.1f}% {((1-s)*100):>24.1f}%")

    p("\n--- KM curve (event-time steps) ---")
    p(f"  {'t (days)':>9} {'at risk':>8} {'events':>7} {'S(t)':>8}")
    p(f"  {'-'*9} {'-'*8} {'-'*7} {'-'*8}")
    for step in ov["steps"]:
        p(f"  {step['t']:>9} {step['n_at_risk']:>8} "
          f"{step['events']:>7} {step['survival']*100:>7.1f}%")

    p("\n--- Per-Vendor KM (median + horizons) ---")
    hdr = f"  {'Vendor':<22} {'n':>3} {'Median':>7}"
    for h in HORIZONS:
        hdr += f" {('S'+str(h)):>7}"
    p(hdr)
    p(f"  {'-'*22} {'-'*3} {'-'*7}" + (" " + "-" * 7) * len(HORIZONS))
    for v, s in sorted(results["by_vendor"].items(),
                       key=lambda kv: -kv[1]["n"]):
        med = s["km_median"]
        med_str = str(med) if med is not None else "n/a"
        row = f"  {v:<22} {s['n']:>3} {med_str:>7}"
        for h in HORIZONS:
            row += f" {s['horizons'][h]*100:>6.0f}%"
        p(row)

    p("\n--- By CVSS Band KM (median + horizons) ---")
    hdr = f"  {'Band':<10} {'n':>3} {'Median':>7}"
    for h in HORIZONS:
        hdr += f" {('S'+str(h)):>7}"
    p(hdr)
    p(f"  {'-'*10} {'-'*3} {'-'*7}" + (" " + "-" * 7) * len(HORIZONS))
    for band, s in results["by_cvss_band"].items():
        med = s["km_median"]
        med_str = str(med) if med is not None else "n/a"
        row = f"  {band:<10} {s['n']:>3} {med_str:>7}"
        for h in HORIZONS:
            row += f" {s['horizons'][h]*100:>6.0f}%"
        p(row)

    return "\n".join(lines)


def fmt_markdown(results):
    lines = []
    p = lines.append
    ov = results["overall"]

    p("# Survival Analysis of Time-to-Exploitation\n")
    p(f"**{ov['n']}** edge CVEs analyzed as survival subjects across "
      f"{len(results['by_vendor'])} vendors. "
      f"Event = exploitation confirmed (CISA KEV listing); "
      f"time *t* = `max(0, KEV dateAdded - NVD published)` in days.\n")

    p("## Overall Kaplan-Meier\n")
    km_med = ov["km_median"]
    p("| Metric | Value |")
    p("|--------|------:|")
    p(f"| Subjects | {ov['n']} |")
    p(f"| KM median survival | "
      f"{km_med if km_med is not None else 'undefined'} days |")
    p(f"| Raw median TTE | {ov['raw_median_tte']:.0f} days |")
    p(f"| Raw mean TTE | {ov['raw_mean_tte']:.1f} days |")
    p(f"| Zero-days (t=0) | {ov['zero_day_count']} |")

    p("\n## Survival S(t) at Key Horizons\n")
    p("`S(t)` = fraction of edge CVEs *not yet* confirmed-exploited at *t* "
      "days post-disclosure. `1 - S(t)` = the cumulative exploitation rate.\n")
    p("| Horizon | S(t) | Exploited by t |")
    p("|--------:|-----:|---------------:|")
    for h in HORIZONS:
        s = ov["horizons"][h]
        p(f"| {h} days | {s*100:.1f}% | {(1-s)*100:.1f}% |")

    p("\n## Per-Vendor Survival\n")
    hdr = "| Vendor | n | KM Median |"
    sep = "|--------|--:|----------:|"
    for h in HORIZONS:
        hdr += f" S({h}d) |"
        sep += "------:|"
    p(hdr)
    p(sep)
    for v, s in sorted(results["by_vendor"].items(),
                       key=lambda kv: -kv[1]["n"]):
        med = s["km_median"]
        med_str = str(med) if med is not None else "n/a"
        row = f"| {v} | {s['n']} | {med_str} |"
        for h in HORIZONS:
            row += f" {s['horizons'][h]*100:.0f}% |"
        p(row)

    p("\n## By CVSS Severity Band\n")
    hdr = "| Band | n | KM Median |"
    sep = "|------|--:|----------:|"
    for h in HORIZONS:
        hdr += f" S({h}d) |"
        sep += "------:|"
    p(hdr)
    p(sep)
    for band, s in results["by_cvss_band"].items():
        med = s["km_median"]
        med_str = str(med) if med is not None else "n/a"
        row = f"| {band} | {s['n']} | {med_str} |"
        for h in HORIZONS:
            row += f" {s['horizons'][h]*100:.0f}% |"
        p(row)

    p("\n## Overall KM Curve (Event-Time Steps)\n")
    p("| t (days) | At Risk | Events | S(t) |")
    p("|---------:|--------:|-------:|-----:|")
    for step in ov["steps"]:
        p(f"| {step['t']} | {step['n_at_risk']} | "
          f"{step['events']} | {step['survival']*100:.1f}% |")

    return "\n".join(lines)


def fmt_json(results):
    def clean(stratum):
        return {
            "n": stratum["n"],
            "km_median": stratum["km_median"],
            "horizons": {str(h): stratum["horizons"][h] for h in HORIZONS},
            "steps": stratum.get("steps", []),
        }

    ov = results["overall"]
    out = {
        "total_cves": results["total_cves"],
        "no_t_computable": results["no_t_computable"],
        "horizons_days": HORIZONS,
        "overall": {
            "n": ov["n"],
            "km_median": ov["km_median"],
            "raw_median_tte": ov["raw_median_tte"],
            "raw_mean_tte": ov["raw_mean_tte"],
            "zero_day_count": ov["zero_day_count"],
            "horizons": {str(h): ov["horizons"][h] for h in HORIZONS},
            "steps": ov["steps"],
        },
        "by_vendor": {v: clean(s) for v, s in results["by_vendor"].items()},
        "by_cvss_band": {b: clean(s)
                         for b, s in results["by_cvss_band"].items()},
    }
    return json.dumps(out, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Survival analysis (Kaplan-Meier) of edge CVE TTE.")
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
                        help="Skip live KEV fetch (use enriched JSON dates)")
    args = parser.parse_args()

    for path, label in [(args.enriched, "enriched"), (args.counts, "counts")]:
        if not os.path.isfile(path):
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    kev_lookup = {}
    if not args.no_fetch:
        try:
            kev_lookup = fetch_kev_catalog()
            print(f"# KEV catalog: {len(kev_lookup)} vulnerabilities",
                  file=sys.stderr)
        except Exception as e:
            print(f"# WARNING: KEV fetch failed: {e}", file=sys.stderr)
            print("# Falling back to enriched JSON dates", file=sys.stderr)

    subjects = load_data(args.enriched, args.counts, kev_lookup)
    results = compute_analysis(subjects)

    formatters = {
        "text": fmt_text,
        "markdown": fmt_markdown,
        "json": fmt_json,
    }
    output = formatters[args.format](results)

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
