#!/usr/bin/env python3
"""
Per-install-normalized cross-vendor analysis for edge-security-ground-truth.

This is the per-share companion to analyze_statistics.py and the
MARKET-SHARE-SENSITIVITY.md sensitivity study. It answers the North-Star
question HONESTLY: once you divide each vendor's KEV count by its estimated
market share, does the picture change -- and which vendors are over- or
under-represented relative to a popularity-proportional baseline?

For each vendor and EACH of three published share vectors
(conservative / moderate / aggressive, taken verbatim from
docs/MARKET-SHARE-SENSITIVITY.md Section 3) we compute:

  * per-share exploitation RATE      r_i = count_i / share_i
  * RATE RATIO vs the corpus mean     rr_i = r_i / r_bar
        where r_bar = N / sum(shares) = N (shares sum to 1.0), so
        rr_i = (count_i / share_i) / N  ==  count_i / (N * share_i)
        == observed / share-expected. rr_i > 1 => above the popularity
        baseline (more KEVs than its share predicts); rr_i < 1 => below.
  * a Poisson exact (Garwood) confidence interval on the COUNT, and the
    share-expected count E_i = N * share_i, flagged as inside/below/above
    that interval.

Because three share vectors are used, every per-vendor result is reported as
a BRACKET (min..max across the three vectors), never a single point estimate.

CRITICAL HONESTY CAVEATS (echoed in the docs):
  - Market share here is unit/revenue/footprint proxy, NOT a device census.
    unit-share != revenue-share != deployed-device-count.
  - Shares are analyst point estimates with no published error bars; the
    three vectors only bracket cross-source DISAGREEMENT, not formal CIs.
  - A high per-share rate does NOT establish a code-quality difference. It
    conflates installed base, researcher attention, attacker targeting,
    disclosure transparency, and (presumably) code quality in unknown
    proportions.

This analysis does NOT crown a "winner". It shows that the raw spread is
largely a popularity-tax artifact: low-share vendors look bad per-install and
the raw-high leader (Fortinet) normalizes DOWN toward/below average.

All computations use Python stdlib only (math, json, argparse).
No numpy, scipy, pandas, or matplotlib.

Usage:
  python3 scripts/analyze_normalization.py                    # text tables
  python3 scripts/analyze_normalization.py --format markdown  # markdown
  python3 scripts/analyze_normalization.py --format json      # machine-readable
  python3 scripts/analyze_normalization.py -o out.md -f markdown
"""

import argparse
import json
import math
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")

# ---------------------------------------------------------------------------
# Three market-share vectors -- copied verbatim from
# docs/MARKET-SHARE-SENSITIVITY.md Section 3. These are analyst point
# estimates (Gartner/IDC/Omdia + SEC filings), NOT a device census.
# ---------------------------------------------------------------------------

SCENARIOS = {
    "Conservative (Fortinet 24%)": {
        "Fortinet": 0.24, "Palo Alto Networks": 0.18, "Cisco": 0.15,
        "Check Point": 0.08, "Citrix": 0.08, "SonicWall": 0.07,
        "Ivanti": 0.05, "Juniper": 0.04, "F5": 0.03,
        "Sophos": 0.03, "Zyxel": 0.02, "WatchGuard": 0.02,
        "Array Networks": 0.01,
    },
    "Moderate (Fortinet 34%)": {
        "Fortinet": 0.34, "Palo Alto Networks": 0.18, "Cisco": 0.12,
        "Check Point": 0.06, "Citrix": 0.06, "SonicWall": 0.06,
        "Ivanti": 0.05, "Juniper": 0.04, "F5": 0.03,
        "Sophos": 0.02, "Zyxel": 0.02, "WatchGuard": 0.01,
        "Array Networks": 0.01,
    },
    "Aggressive (Fortinet 48%)": {
        "Fortinet": 0.48, "Palo Alto Networks": 0.15, "Cisco": 0.08,
        "Check Point": 0.04, "Citrix": 0.05, "SonicWall": 0.05,
        "Ivanti": 0.04, "Juniper": 0.03, "F5": 0.02,
        "Sophos": 0.02, "Zyxel": 0.02, "WatchGuard": 0.01,
        "Array Networks": 0.01,
    },
}

# The "moderate" vector is the headline one (mid-range analyst assumption).
HEADLINE_SCENARIO = "Moderate (Fortinet 34%)"

# ---------------------------------------------------------------------------
# Mathematical primitives (stdlib-only) -- match analyze_statistics.py
# ---------------------------------------------------------------------------

def _normal_ppf(p):
    """Inverse standard normal (rational approximation, Beasley-Springer-Moro)."""
    if p <= 0:
        return -10.0
    if p >= 1:
        return 10.0
    if p == 0.5:
        return 0.0
    if p < 0.5:
        return -_normal_ppf(1.0 - p)
    t = math.sqrt(-2.0 * math.log(1.0 - p))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)


def _chi2_quantile(p, df):
    """Chi-squared quantile via Wilson-Hilferty inverse (matches poisson_ci)."""
    if df <= 0:
        return 0.0
    z = _normal_ppf(p)
    x = df * (1.0 - 2.0 / (9.0 * df) + z * math.sqrt(2.0 / (9.0 * df))) ** 3
    return max(0.0, x)


def poisson_ci(k, alpha=0.05):
    """Exact Poisson confidence interval (Garwood 1936) on the count k.

    CI is [chi2(alpha/2, 2k)/2, chi2(1-alpha/2, 2k+2)/2]; chi-squared
    quantiles approximated via the Wilson-Hilferty inverse. Identical method
    to analyze_statistics.py::poisson_ci so the two analyses agree.
    """
    if k == 0:
        lower = 0.0
    else:
        lower = _chi2_quantile(alpha / 2.0, 2 * k) / 2.0
    upper = _chi2_quantile(1.0 - alpha / 2.0, 2 * (k + 1)) / 2.0
    return lower, upper


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_counts(path):
    with open(path) as f:
        data = json.load(f)
    counts = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, list):
            counts[k] = len(v)
    # Prefer the authoritative _metadata.counts block if present.
    meta = data.get("_metadata", {})
    if "counts" in meta:
        counts = dict(meta["counts"])
    return counts, meta


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze(counts):
    vendors = list(counts.keys())
    N = sum(counts.values())
    k = len(vendors)

    # Validate every scenario covers every vendor and sums to ~1.0.
    for name, shares in SCENARIOS.items():
        missing = set(vendors) - set(shares)
        extra = set(shares) - set(vendors)
        if missing or extra:
            raise ValueError(
                f"Scenario '{name}' vendor mismatch. missing={missing} extra={extra}"
            )
        s = sum(shares.values())
        if abs(s - 1.0) > 0.011:
            raise ValueError(f"Scenario '{name}' shares sum to {s:.4f}, not ~1.0")

    # Per-scenario per-vendor metrics.
    # corpus-mean rate r_bar = N / sum(shares) = N (shares sum to 1.0).
    scenario_results = {}
    for name, shares in SCENARIOS.items():
        r_bar = N / sum(shares.values())  # == N
        rows = {}
        for v in vendors:
            c = counts[v]
            s = shares[v]
            rate = c / s                      # per-share exploitation rate
            rate_ratio = rate / r_bar         # vs corpus mean; == c/(N*s)
            expected = N * s                  # share-expected count
            lo, hi = poisson_ci(c)            # Poisson exact CI on the count
            if expected < lo:
                pos = "above"   # observed CI sits ABOVE the share-expectation
            elif expected > hi:
                pos = "below"   # observed CI sits BELOW the share-expectation
            else:
                pos = "inside"
            rows[v] = {
                "count": c,
                "share": round(s, 4),
                "rate_per_share": round(rate, 2),
                "rate_ratio": round(rate_ratio, 3),
                "expected_count": round(expected, 3),
                "count_ci_low": round(lo, 3),
                "count_ci_high": round(hi, 3),
                "expected_vs_ci": pos,
                "low_expected_cell": expected < 5,
            }
        scenario_results[name] = {
            "corpus_mean_rate": round(r_bar, 3),
            "vendors": rows,
        }

    # Cross-scenario BRACKETS: min/max rate_ratio per vendor across the 3 vectors.
    brackets = {}
    for v in vendors:
        rrs = [scenario_results[n]["vendors"][v]["rate_ratio"] for n in SCENARIOS]
        # Categorize: above 1.0 in all vectors, below in all, or straddling.
        if all(rr > 1.0 for rr in rrs):
            cat = "above"
        elif all(rr < 1.0 for rr in rrs):
            cat = "below"
        else:
            cat = "straddles"
        brackets[v] = {
            "count": counts[v],
            "rate_ratio_min": round(min(rrs), 3),
            "rate_ratio_max": round(max(rrs), 3),
            "category": cat,
        }

    return {
        "N": N,
        "k": k,
        "vendors": vendors,
        "headline_scenario": HEADLINE_SCENARIO,
        "scenarios": scenario_results,
        "brackets": brackets,
    }


# ---------------------------------------------------------------------------
# Output: text
# ---------------------------------------------------------------------------

def _sorted_by_count(counts_map, vendors):
    return sorted(vendors, key=lambda x: (-counts_map[x], x))


def print_text(res):
    N, k = res["N"], res["k"]
    print("=" * 76)
    print("PER-INSTALL-NORMALIZED CROSS-VENDOR ANALYSIS")
    print("=" * 76)
    print(f"N = {N} KEV CVEs across k = {k} edge-appliance vendors")
    print("Market share = analyst proxy (unit/revenue), NOT a device census.")
    print("rate_ratio > 1.0 => MORE KEVs than market share predicts (above baseline)")
    print("rate_ratio < 1.0 => FEWER KEVs than market share predicts (below baseline)")
    print()

    counts_map = {v: res["brackets"][v]["count"] for v in res["vendors"]}
    order = _sorted_by_count(counts_map, res["vendors"])

    for name in SCENARIOS:
        sc = res["scenarios"][name]
        print("-" * 76)
        print(f"Scenario: {name}   (corpus-mean rate r_bar = {sc['corpus_mean_rate']})")
        hdr = f"{'Vendor':19s} {'Cnt':>3s} {'Share':>6s} {'Rate':>8s} {'RateRatio':>9s} {'Exp':>6s} {'Exp vs CI':>10s}"
        print(hdr)
        print("-" * len(hdr))
        for v in order:
            r = sc["vendors"][v]
            flag = " *" if r["low_expected_cell"] else ""
            print(f"{v:19s} {r['count']:3d} {r['share']:6.3f} "
                  f"{r['rate_per_share']:8.2f} {r['rate_ratio']:9.3f} "
                  f"{r['expected_count']:6.2f} {r['expected_vs_ci']:>10s}{flag}")
        print("  * = share-expected cell < 5 (small-count caveat)")
        print()

    print("=" * 76)
    print("CROSS-SCENARIO RATE-RATIO BRACKETS (min..max over all 3 share vectors)")
    print("=" * 76)
    hdr = f"{'Vendor':19s} {'Cnt':>3s} {'RateRatio bracket':>20s}  Category"
    print(hdr)
    print("-" * len(hdr))
    for v in order:
        b = res["brackets"][v]
        bracket = f"{b['rate_ratio_min']:.2f}..{b['rate_ratio_max']:.2f}"
        print(f"{v:19s} {b['count']:3d} {bracket:>20s}  {b['category']}")
    print()
    above = [v for v in order if res["brackets"][v]["category"] == "above"]
    below = [v for v in order if res["brackets"][v]["category"] == "below"]
    straddle = [v for v in order if res["brackets"][v]["category"] == "straddles"]
    print(f"ABOVE baseline in ALL vectors ({len(above)}): {', '.join(above)}")
    print(f"BELOW baseline in ALL vectors ({len(below)}): {', '.join(below)}")
    print(f"STRADDLES 1.0 (vector-dependent) ({len(straddle)}): {', '.join(straddle)}")
    print()
    print("CAVEAT: a high per-share rate does NOT prove worse code quality. It")
    print("conflates install base, researcher attention, attacker targeting, and")
    print("disclosure practices. This does not crown a winner; it shows the raw")
    print("spread is largely a popularity-tax artifact.")


# ---------------------------------------------------------------------------
# Output: markdown
# ---------------------------------------------------------------------------

def print_markdown(res):
    N, k = res["N"], res["k"]
    counts_map = {v: res["brackets"][v]["count"] for v in res["vendors"]}
    order = _sorted_by_count(counts_map, res["vendors"])

    print("# Per-Install-Normalized Cross-Vendor Analysis\n")
    print(f"`N = {N}` KEV CVEs across `k = {k}` edge-appliance vendors. Market share is "
          "an analyst proxy (unit/revenue), **not** a deployed-device census.\n")
    print("- `rate_ratio > 1.0` => vendor has **more** KEVs than its market share predicts "
          "(above the popularity baseline)")
    print("- `rate_ratio < 1.0` => vendor has **fewer** KEVs than its market share predicts "
          "(below the popularity baseline)\n")

    for name in SCENARIOS:
        sc = res["scenarios"][name]
        print(f"## Scenario: {name}\n")
        print(f"Corpus-mean rate `r_bar = {sc['corpus_mean_rate']}`.\n")
        print("| Vendor | Count | Share | Rate (cnt/share) | Rate ratio | Expected | Expected vs count 95% CI |")
        print("|--------|:-:|:-:|:-:|:-:|:-:|:-:|")
        for v in order:
            r = sc["vendors"][v]
            flag = " \\*" if r["low_expected_cell"] else ""
            print(f"| {v} | {r['count']} | {r['share']:.3f} | {r['rate_per_share']:.1f} | "
                  f"{r['rate_ratio']:.3f} | {r['expected_count']:.2f}{flag} | "
                  f"{r['expected_vs_ci']} (CI {r['count_ci_low']:.1f}..{r['count_ci_high']:.1f}) |")
        print("\n\\* = share-expected cell < 5 (small-count caveat).\n")

    print("## Cross-scenario rate-ratio brackets\n")
    print("Each result is a **bracket** (min..max over the three share vectors), never a "
          "point estimate.\n")
    print("| Vendor | Count | Rate-ratio bracket | Category |")
    print("|--------|:-:|:-:|:-:|")
    for v in order:
        b = res["brackets"][v]
        print(f"| {v} | {b['count']} | {b['rate_ratio_min']:.2f}..{b['rate_ratio_max']:.2f} | "
              f"{b['category']} |")
    above = [v for v in order if res["brackets"][v]["category"] == "above"]
    below = [v for v in order if res["brackets"][v]["category"] == "below"]
    straddle = [v for v in order if res["brackets"][v]["category"] == "straddles"]
    print()
    print(f"- **Above baseline in all vectors ({len(above)}):** {', '.join(above)}")
    print(f"- **Below baseline in all vectors ({len(below)}):** {', '.join(below)}")
    print(f"- **Straddles 1.0 (vector-dependent) ({len(straddle)}):** {', '.join(straddle)}")
    print()
    print("> **Caveat.** A high per-share rate does NOT establish a code-quality "
          "difference. Unit-share != revenue-share != deployed-device count; shares are "
          "analyst estimates with no error bars. Normalization does not crown a winner -- "
          "it shows the raw spread is largely a popularity-tax artifact.")


# ---------------------------------------------------------------------------
# Output: json
# ---------------------------------------------------------------------------

def print_json(res):
    print(json.dumps(res, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Per-install-normalized cross-vendor KEV analysis (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/analyze_normalization.py
  python3 scripts/analyze_normalization.py --format markdown
  python3 scripts/analyze_normalization.py --format json -o out.json
        """,
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "markdown", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    if not os.path.isfile(COUNTS_PATH):
        print(f"Error: {COUNTS_PATH} not found. Run build_kev_counts.py first.",
              file=sys.stderr)
        sys.exit(1)

    counts, _meta = load_counts(COUNTS_PATH)
    res = analyze(counts)

    out = sys.stdout
    if args.output:
        out = open(args.output, "w")
        sys.stdout = out

    if args.format == "markdown":
        print_markdown(res)
    elif args.format == "json":
        print_json(res)
    else:
        print_text(res)

    if args.output:
        out.close()
        sys.stdout = sys.__stdout__
        print(f"Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
