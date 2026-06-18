#!/usr/bin/env python3
"""
EPSS edge-domain evaluation for edge-security-ground-truth.

Every CVE in this dataset is KEV-listed -- i.e. CISA has confirmed active
exploitation in the wild.  In machine-learning terms, all 115 records are
*ground-truth positives* for "this vulnerability is exploited."  EPSS (the
Exploit Prediction Scoring System, FIRST.org) assigns each CVE a probability
in [0, 1] that it will be exploited in the next 30 days, plus a percentile
rank against all scored CVEs.

This script asks a single, narrow question:

    How well does EPSS *recognize* the edge appliance CVEs that we already
    know were exploited?

Because every record is a known-exploited positive, a well-calibrated EPSS
should -- on this slice -- skew high.  Where it skews low, EPSS is effectively
"missing" a confirmed edge exploitation.  EPSS publishes no device-class
breakdown, so this is, to our knowledge, the first empirical look at EPSS
behaviour on the edge-appliance subset of KEV.

Caveats (see docs/EPSS-EDGE-EVAL.md for the full treatment):
  - EPSS scores here are point-in-time at *enrichment* (2026-06-18), NOT at
    the moment of exploitation.  EPSS for a fresh CVE often climbs only after
    public PoC / mass scanning, so a low score on an *old* exploited CVE is a
    different signal than a low score read the day a 0-day dropped.
  - KEV-listed CVEs are a biased, high-exploitation sample by construction.
    EPSS is trained to predict the general population; "EPSS misses" here are
    misses on an adversarially-selected hard subset, not on average CVEs.

Data sources (source of truth):
  - kev_edge_enriched.json  (epss, percentile, cvss, cwe, published, per CVE)
  - kev_edge_counts.json    (vendor -> CVE-ID lists, used as scope filter)

This script is OFFLINE and STDLIB-ONLY -- no network, no pip dependencies.
All EPSS/percentile values are read straight from kev_edge_enriched.json.

Usage:
  python3 scripts/analyze_epss_eval.py                    # text tables
  python3 scripts/analyze_epss_eval.py --format markdown  # markdown tables
  python3 scripts/analyze_epss_eval.py --format json      # machine-readable
  python3 scripts/analyze_epss_eval.py -o docs/foo.md -f markdown
"""
import argparse
import collections
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")

# Thresholds.  EPSS probability buckets follow the common operational cut-points
# (FIRST.org's own guidance discusses 0.1 / 0.5 thresholds for prioritisation).
EPSS_HIGH = 0.5          # "EPSS thinks exploitation is more likely than not"
EPSS_VERY_HIGH = 0.9     # near-certain by EPSS
EPSS_LOW = 0.1           # "EPSS effectively does not flag this"
PCT_LOW = 0.5            # below median of all scored CVEs

# A confirmed-exploited edge CVE counts as an EPSS "miss" if its probability is
# below EPSS_LOW *or* its percentile rank is below PCT_LOW -- i.e. EPSS would
# not have surfaced it under any reasonable edge-prioritisation cutoff.


def load_data(enriched_path, counts_path):
    """Load enriched + counts JSON, scoped to the vendor->CVE lists in counts.

    Returns list of per-CVE dicts carrying the EPSS fields we evaluate.
    Mirrors analyze_tte.load_data's scope discipline (counts is the authority
    for which CVEs are in-domain; _metadata and non-list keys are skipped).
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
            pub = cve_data.get("published")
            pub_year = None
            if isinstance(pub, str) and len(pub) >= 4 and pub[:4].isdigit():
                pub_year = int(pub[:4])
            entries.append({
                "vendor": vendor,
                "cve": cve_id,
                "epss": cve_data.get("epss"),
                "percentile": cve_data.get("percentile"),
                "cvss": cve_data.get("cvss"),
                "cvss_severity": cve_data.get("cvss_severity"),
                "cwe": cve_data.get("cwe"),
                "published": pub,
                "pub_year": pub_year,
                "ransomware": cve_data.get("ransomware") == "Known",
            })
    return entries


def mean(vals):
    """Arithmetic mean, or None for an empty list."""
    return sum(vals) / len(vals) if vals else None


def median(vals):
    """Median of an UNSORTED list (sorts internally)."""
    s = sorted(vals)
    n = len(s)
    if n == 0:
        return None
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def quantile(sorted_vals, q):
    """Linear-interpolation quantile (NIST/numpy 'linear' method).

    sorted_vals must already be sorted ascending. q in [0, 1].
    Stdlib only -- no numpy.
    """
    n = len(sorted_vals)
    if n == 0:
        return None
    if n == 1:
        return sorted_vals[0]
    pos = q * (n - 1)
    lo = int(pos)
    frac = pos - lo
    if lo + 1 < n:
        return sorted_vals[lo] + frac * (sorted_vals[lo + 1] - sorted_vals[lo])
    return sorted_vals[lo]


def summarize(vals):
    """Return a dict of summary stats for a list of numeric values."""
    s = sorted(v for v in vals if v is not None)
    n = len(s)
    if n == 0:
        return {"n": 0}
    return {
        "n": n,
        "mean": mean(s),
        "median": median(s),
        "min": s[0],
        "max": s[-1],
        "q1": quantile(s, 0.25),
        "q3": quantile(s, 0.75),
    }


def compute_analysis(entries):
    """Compute all EPSS evaluation results."""
    results = {}
    results["total_cves"] = len(entries)

    # CVEs that actually carry an EPSS score.  In this dataset all 115 do,
    # but guard anyway so the script is honest if the data changes.
    scored = [e for e in entries if e["epss"] is not None]
    results["scored_cves"] = len(scored)
    results["unscored_cves"] = [
        {"cve": e["cve"], "vendor": e["vendor"]}
        for e in entries if e["epss"] is None
    ]

    epss_vals = [e["epss"] for e in scored]
    pct_vals = [e["percentile"] for e in scored if e["percentile"] is not None]

    # --- (1) Overall EPSS distribution across the known-exploited slice ---
    results["epss_summary"] = summarize(epss_vals)
    results["percentile_summary"] = summarize(pct_vals)

    n_scored = len(scored) or 1
    results["epss_above_high"] = sum(1 for v in epss_vals if v > EPSS_HIGH)
    results["epss_above_very_high"] = sum(
        1 for v in epss_vals if v > EPSS_VERY_HIGH)
    results["epss_below_low"] = sum(1 for v in epss_vals if v < EPSS_LOW)
    results["pct_above_high"] = sum(1 for v in pct_vals if v > EPSS_HIGH)
    results["pct_above_very_high"] = sum(1 for v in pct_vals if v > EPSS_VERY_HIGH)

    results["epss_above_high_pct"] = 100 * results["epss_above_high"] / n_scored
    results["epss_above_very_high_pct"] = (
        100 * results["epss_above_very_high"] / n_scored)
    results["epss_below_low_pct"] = 100 * results["epss_below_low"] / n_scored

    # EPSS probability histogram (operational buckets)
    buckets = [
        ("0.00-0.10 (EPSS does not flag)", lambda v: v < 0.10),
        ("0.10-0.50 (low)",                lambda v: 0.10 <= v < 0.50),
        ("0.50-0.90 (elevated)",           lambda v: 0.50 <= v < 0.90),
        ("0.90-1.00 (near-certain)",       lambda v: v >= 0.90),
    ]
    hist = []
    for label, pred in buckets:
        c = sum(1 for v in epss_vals if pred(v))
        hist.append({"bucket": label, "count": c,
                     "pct": 100 * c / n_scored})
    results["epss_histogram"] = hist

    # --- (2) Per-vendor EPSS distribution ---
    by_vendor = collections.defaultdict(list)
    for e in scored:
        by_vendor[e["vendor"]].append(e)
    vendor_stats = []
    for vendor, evs in by_vendor.items():
        ev_epss = [e["epss"] for e in evs]
        ev_pct = [e["percentile"] for e in evs if e["percentile"] is not None]
        misses = [e for e in evs if is_miss(e)]
        vendor_stats.append({
            "vendor": vendor,
            "n": len(evs),
            "epss_mean": mean(ev_epss),
            "epss_median": median(ev_epss),
            "epss_min": min(ev_epss),
            "epss_max": max(ev_epss),
            "pct_median": median(ev_pct) if ev_pct else None,
            "n_below_low": sum(1 for v in ev_epss if v < EPSS_LOW),
            "n_above_high": sum(1 for v in ev_epss if v > EPSS_HIGH),
            "n_misses": len(misses),
            "miss_pct": 100 * len(misses) / len(evs) if evs else 0,
        })
    # Sort ascending by median EPSS so the vendors EPSS under-scores float up.
    vendor_stats.sort(key=lambda v: (v["epss_median"] is None,
                                     v["epss_median"]))
    results["vendor_stats"] = vendor_stats

    # --- (3) Gap analysis: confirmed-exploited but LOW EPSS ("misses") ---
    misses = [e for e in scored if is_miss(e)]
    misses.sort(key=lambda e: (e["epss"], e["percentile"] or 0))
    results["misses"] = [
        {
            "cve": e["cve"],
            "vendor": e["vendor"],
            "epss": e["epss"],
            "percentile": e["percentile"],
            "cvss": e["cvss"],
            "cvss_severity": e["cvss_severity"],
            "cwe": e["cwe"],
            "published": e["published"],
            "ransomware": e["ransomware"],
            "reason": miss_reason(e),
        }
        for e in misses
    ]
    results["miss_count"] = len(misses)
    results["miss_pct"] = 100 * len(misses) / n_scored

    # Ransomware-associated misses are the most pointed: EPSS under-scored a CVE
    # that was not only exploited but used in known ransomware campaigns.
    results["ransomware_misses"] = [
        m for m in results["misses"] if m["ransomware"]]

    # --- (4) Percentile-at-enrichment patterns by publish year ---
    by_year = collections.defaultdict(list)
    for e in scored:
        if e["pub_year"] is not None:
            by_year[e["pub_year"]].append(e)
    year_stats = []
    for year in sorted(by_year):
        evs = by_year[year]
        ev_epss = [e["epss"] for e in evs]
        ev_pct = [e["percentile"] for e in evs if e["percentile"] is not None]
        year_stats.append({
            "year": year,
            "n": len(evs),
            "epss_mean": mean(ev_epss),
            "epss_median": median(ev_epss),
            "pct_mean": mean(ev_pct) if ev_pct else None,
            "pct_median": median(ev_pct) if ev_pct else None,
            "n_misses": sum(1 for e in evs if is_miss(e)),
        })
    results["year_stats"] = year_stats

    results["thresholds"] = {
        "epss_high": EPSS_HIGH,
        "epss_very_high": EPSS_VERY_HIGH,
        "epss_low": EPSS_LOW,
        "pct_low": PCT_LOW,
    }
    return results


def is_miss(e):
    """True if this confirmed-exploited CVE is an EPSS 'miss'.

    Miss == EPSS probability below EPSS_LOW OR percentile below PCT_LOW.
    Either condition means EPSS would not have surfaced this CVE under a
    reasonable edge-prioritisation cutoff.
    """
    if e["epss"] is None:
        return False
    low_prob = e["epss"] < EPSS_LOW
    low_pct = e["percentile"] is not None and e["percentile"] < PCT_LOW
    return low_prob or low_pct


def miss_reason(e):
    """Human-readable reason a CVE is flagged as a miss."""
    parts = []
    if e["epss"] is not None and e["epss"] < EPSS_LOW:
        parts.append(f"epss<{EPSS_LOW}")
    if e["percentile"] is not None and e["percentile"] < PCT_LOW:
        parts.append(f"percentile<{PCT_LOW}")
    return " & ".join(parts) if parts else ""


# --------------------------------------------------------------------------- #
# Formatters
# --------------------------------------------------------------------------- #
def _fmt_pct(v):
    return "N/A" if v is None else f"{v:.4f}"


def fmt_text(entries, results):
    lines = []
    p = lines.append
    th = results["thresholds"]

    p("=" * 70)
    p("EPSS EDGE-DOMAIN EVALUATION")
    p("=" * 70)
    p(f"Known-exploited (KEV-listed) edge CVEs: {results['total_cves']}")
    p(f"  with an EPSS score:                   {results['scored_cves']}")
    if results["unscored_cves"]:
        p(f"  WITHOUT an EPSS score:                "
          f"{len(results['unscored_cves'])}")
    p("Every record below is a GROUND-TRUTH exploited positive.")
    p("")

    es = results["epss_summary"]
    ps = results["percentile_summary"]
    p("(1) EPSS PROBABILITY DISTRIBUTION (n=%d)" % es["n"])
    p("-" * 50)
    p(f"  mean   {es['mean']:.4f}")
    p(f"  median {es['median']:.4f}")
    p(f"  Q1     {es['q1']:.4f}    Q3 {es['q3']:.4f}")
    p(f"  min    {es['min']:.4f}    max {es['max']:.4f}")
    p(f"  > {th['epss_high']} : {results['epss_above_high']} "
      f"({results['epss_above_high_pct']:.1f}%)")
    p(f"  > {th['epss_very_high']} : {results['epss_above_very_high']} "
      f"({results['epss_above_very_high_pct']:.1f}%)")
    p(f"  < {th['epss_low']} : {results['epss_below_low']} "
      f"({results['epss_below_low_pct']:.1f}%)  <-- EPSS does not flag")
    p("")
    p("    EPSS PERCENTILE DISTRIBUTION (n=%d)" % ps["n"])
    p(f"  mean   {ps['mean']:.4f}")
    p(f"  median {ps['median']:.4f}")
    p(f"  Q1     {ps['q1']:.4f}    Q3 {ps['q3']:.4f}")
    p("")
    p("  EPSS probability histogram:")
    for h in results["epss_histogram"]:
        bar = "#" * int(round(h["pct"] / 2))
        p(f"    {h['bucket']:<34} {h['count']:>3} ({h['pct']:>5.1f}%) {bar}")
    p("")

    p("(2) PER-VENDOR EPSS DISTRIBUTION (sorted by median, ascending)")
    p("-" * 50)
    p(f"  {'Vendor':<20} {'n':>3} {'med':>7} {'mean':>7} "
      f"{'min':>7} {'<0.1':>5} {'miss%':>6}")
    for v in results["vendor_stats"]:
        p(f"  {v['vendor']:<20} {v['n']:>3} {v['epss_median']:>7.4f} "
          f"{v['epss_mean']:>7.4f} {v['epss_min']:>7.4f} "
          f"{v['n_below_low']:>5} {v['miss_pct']:>5.1f}%")
    p("")

    p("(3) GAP ANALYSIS -- exploited-but-LOW-EPSS edge CVEs (\"misses\")")
    p(f"    miss = epss < {th['epss_low']} OR percentile < {th['pct_low']}")
    p("-" * 50)
    p(f"  {results['miss_count']} of {results['scored_cves']} "
      f"({results['miss_pct']:.1f}%) confirmed-exploited edge CVEs are EPSS "
      f"misses")
    p(f"  of those, {len(results['ransomware_misses'])} are also "
      f"ransomware-associated")
    p("")
    if results["misses"]:
        p(f"  {'CVE':<18} {'Vendor':<18} {'EPSS':>8} {'pctl':>8} "
          f"{'CVSS':>5} {'Pub':>10}  reason")
        for m in results["misses"]:
            rw = " [RANSOMWARE]" if m["ransomware"] else ""
            cvss = "N/A" if m["cvss"] is None else f"{m['cvss']:.1f}"
            p(f"  {m['cve']:<18} {m['vendor']:<18} {m['epss']:>8.5f} "
              f"{_fmt_pct(m['percentile']):>8} {cvss:>5} "
              f"{m['published'] or 'N/A':>10}  {m['reason']}{rw}")
    p("")

    p("(4) PERCENTILE-AT-ENRICHMENT BY PUBLISH YEAR")
    p("-" * 50)
    p(f"  {'Year':<6} {'n':>3} {'EPSS med':>9} {'EPSS mean':>10} "
      f"{'pctl med':>9} {'misses':>7}")
    for y in results["year_stats"]:
        pm = "N/A" if y["pct_median"] is None else f"{y['pct_median']:.4f}"
        p(f"  {y['year']:<6} {y['n']:>3} {y['epss_median']:>9.4f} "
          f"{y['epss_mean']:>10.4f} {pm:>9} {y['n_misses']:>7}")
    p("")
    p("NOTE: EPSS scores are point-in-time at enrichment (not at exploitation);")
    p("      KEV is a biased high-exploitation sample by construction.")
    return "\n".join(lines)


def fmt_markdown(entries, results):
    lines = []
    p = lines.append
    th = results["thresholds"]

    p("# EPSS Edge-Domain Evaluation\n")
    p(f"**Known-exploited (KEV-listed) edge CVEs evaluated:** "
      f"{results['total_cves']} "
      f"({results['scored_cves']} carry an EPSS score)\n")
    p("Every CVE here is a ground-truth exploited positive (KEV-listed). "
      "We measure how well EPSS *recognises* these confirmed edge "
      "exploitations.\n")

    es = results["epss_summary"]
    ps = results["percentile_summary"]
    p("## 1. EPSS Distribution Across the Known-Exploited Slice\n")
    p("| Metric | EPSS probability | EPSS percentile |")
    p("|--------|-----------------:|----------------:|")
    p(f"| mean   | {es['mean']:.4f} | {ps['mean']:.4f} |")
    p(f"| median | {es['median']:.4f} | {ps['median']:.4f} |")
    p(f"| Q1     | {es['q1']:.4f} | {ps['q1']:.4f} |")
    p(f"| Q3     | {es['q3']:.4f} | {ps['q3']:.4f} |")
    p(f"| min    | {es['min']:.4f} | {ps['min']:.4f} |")
    p(f"| max    | {es['max']:.4f} | {ps['max']:.4f} |\n")
    p(f"- **EPSS > {th['epss_high']}:** {results['epss_above_high']} "
      f"({results['epss_above_high_pct']:.1f}%)")
    p(f"- **EPSS > {th['epss_very_high']}:** "
      f"{results['epss_above_very_high']} "
      f"({results['epss_above_very_high_pct']:.1f}%)")
    p(f"- **EPSS < {th['epss_low']} (does not flag):** "
      f"{results['epss_below_low']} "
      f"({results['epss_below_low_pct']:.1f}%)\n")
    p("### EPSS probability histogram\n")
    p("| Bucket | n | % |")
    p("|--------|--:|--:|")
    for h in results["epss_histogram"]:
        p(f"| {h['bucket']} | {h['count']} | {h['pct']:.1f}% |")
    p("")

    p("## 2. Per-Vendor EPSS Distribution\n")
    p("Sorted by median EPSS ascending -- vendors EPSS systematically "
      "under-scores float to the top.\n")
    p("| Vendor | n | median | mean | min | max | <0.1 | misses | miss % |")
    p("|--------|--:|-------:|-----:|----:|----:|-----:|-------:|-------:|")
    for v in results["vendor_stats"]:
        p(f"| {v['vendor']} | {v['n']} | {v['epss_median']:.4f} | "
          f"{v['epss_mean']:.4f} | {v['epss_min']:.4f} | "
          f"{v['epss_max']:.4f} | {v['n_below_low']} | "
          f"{v['n_misses']} | {v['miss_pct']:.1f}% |")
    p("")

    p("## 3. Gap Analysis -- Exploited-but-Low-EPSS Edge CVEs\n")
    p(f"A **miss** is a confirmed-exploited edge CVE with "
      f"`epss < {th['epss_low']}` **or** `percentile < {th['pct_low']}` -- "
      f"EPSS would not surface it under a reasonable edge cutoff.\n")
    p(f"**{results['miss_count']} of {results['scored_cves']} "
      f"({results['miss_pct']:.1f}%)** confirmed-exploited edge CVEs are EPSS "
      f"misses; **{len(results['ransomware_misses'])}** are also "
      f"ransomware-associated.\n")
    if results["misses"]:
        p("| CVE | Vendor | EPSS | Percentile | CVSS | CWE | Published | "
          "Ransomware | Reason |")
        p("|-----|--------|-----:|-----------:|-----:|-----|-----------|"
          "------------|--------|")
        for m in results["misses"]:
            cvss = "N/A" if m["cvss"] is None else f"{m['cvss']:.1f}"
            rw = "Known" if m["ransomware"] else "-"
            p(f"| {m['cve']} | {m['vendor']} | {m['epss']:.5f} | "
              f"{_fmt_pct(m['percentile'])} | {cvss} | {m['cwe'] or 'N/A'} | "
              f"{m['published'] or 'N/A'} | {rw} | {m['reason']} |")
    p("")

    p("## 4. Percentile-at-Enrichment by Publish Year\n")
    p("| Year | n | EPSS median | EPSS mean | Percentile median | Misses |")
    p("|------|--:|------------:|----------:|------------------:|-------:|")
    for y in results["year_stats"]:
        pm = "N/A" if y["pct_median"] is None else f"{y['pct_median']:.4f}"
        p(f"| {y['year']} | {y['n']} | {y['epss_median']:.4f} | "
          f"{y['epss_mean']:.4f} | {pm} | {y['n_misses']} |")
    p("")
    p("> EPSS scores are point-in-time at enrichment (not at exploitation); "
      "KEV is a biased high-exploitation sample by construction.")
    return "\n".join(lines)


def fmt_json(entries, results):
    out = {
        "total_cves": results["total_cves"],
        "scored_cves": results["scored_cves"],
        "unscored_cves": results["unscored_cves"],
        "thresholds": results["thresholds"],
        "epss_summary": results["epss_summary"],
        "percentile_summary": results["percentile_summary"],
        "epss_above_high": results["epss_above_high"],
        "epss_above_high_pct": results["epss_above_high_pct"],
        "epss_above_very_high": results["epss_above_very_high"],
        "epss_above_very_high_pct": results["epss_above_very_high_pct"],
        "epss_below_low": results["epss_below_low"],
        "epss_below_low_pct": results["epss_below_low_pct"],
        "epss_histogram": results["epss_histogram"],
        "vendor_stats": results["vendor_stats"],
        "miss_count": results["miss_count"],
        "miss_pct": results["miss_pct"],
        "misses": results["misses"],
        "ransomware_misses": results["ransomware_misses"],
        "year_stats": results["year_stats"],
    }
    return json.dumps(out, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="EPSS edge-domain evaluation for KEV-listed edge CVEs.")
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
    args = parser.parse_args()

    for path, label in [(args.enriched, "enriched"),
                        (args.counts, "counts")]:
        if not os.path.isfile(path):
            print(f"Error: {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    entries = load_data(args.enriched, args.counts)
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
