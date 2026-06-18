#!/usr/bin/env python3
"""
Statistical framework for edge-security-ground-truth.

Applies basic statistical tests to determine whether vendor differences
in KEV counts, CWE patterns, and exploitation timing are statistically
meaningful or consistent with random variation.

All computations use Python stdlib only (math module). No numpy/scipy.

Usage:
  python3 scripts/analyze_statistics.py                    # text output
  python3 scripts/analyze_statistics.py --format markdown  # markdown
  python3 scripts/analyze_statistics.py --format json      # JSON
"""
import argparse
import collections
import json
import math
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")


def chi_squared_gof(observed, expected):
    """Chi-squared goodness-of-fit. Returns (statistic, df)."""
    assert len(observed) == len(expected)
    stat = sum((o - e) ** 2 / e for o, e in zip(observed, expected) if e > 0)
    df = len([e for e in expected if e > 0]) - 1
    return stat, df


def chi_squared_p_approx(chi2, df):
    """Approximate p-value for chi-squared using Wilson-Hilferty transform."""
    if df <= 0:
        return 1.0
    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    p = 0.5 * math.erfc(z / math.sqrt(2))
    return max(0, min(1, p))


def herfindahl_hirschman(counts):
    """HHI concentration index. 1/n = perfectly equal, 1.0 = monopoly."""
    total = sum(counts)
    if total == 0:
        return 0
    shares = [c / total for c in counts]
    return sum(s ** 2 for s in shares)


def gini_coefficient(values):
    """Gini coefficient. 0 = perfect equality, 1 = maximum inequality."""
    n = len(values)
    if n == 0:
        return 0
    sorted_vals = sorted(values)
    total = sum(sorted_vals)
    if total == 0:
        return 0
    cumulative = 0
    gini_sum = 0
    for i, v in enumerate(sorted_vals):
        cumulative += v
        gini_sum += (2 * (i + 1) - n - 1) * v
    return gini_sum / (n * total)


def coefficient_of_variation(values):
    """CV = std/mean. Higher = more dispersed."""
    n = len(values)
    if n < 2:
        return 0
    mean = sum(values) / n
    if mean == 0:
        return 0
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return math.sqrt(variance) / mean


def spearman_rank(x, y):
    """Spearman rank correlation (stdlib-only, no scipy)."""
    n = len(x)
    if n < 3:
        return 0, 1.0

    def rank(vals):
        indexed = sorted(enumerate(vals), key=lambda t: t[1])
        ranks = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j < n - 1 and indexed[j + 1][1] == indexed[j][1]:
                j += 1
            avg_rank = (i + j) / 2 + 1
            for k in range(i, j + 1):
                ranks[indexed[k][0]] = avg_rank
            i = j + 1
        return ranks

    rx = rank(x)
    ry = rank(y)
    d_sq = sum((a - b) ** 2 for a, b in zip(rx, ry))
    rho = 1 - (6 * d_sq) / (n * (n ** 2 - 1))
    # t-test approximation for significance
    if abs(rho) >= 1:
        return rho, 0.0
    t_stat = rho * math.sqrt((n - 2) / (1 - rho ** 2))
    # Very rough p-value via normal approximation for n > 10
    p = 2 * 0.5 * math.erfc(abs(t_stat) / math.sqrt(2))
    return rho, p


def load_counts(path):
    with open(path) as f:
        data = json.load(f)
    return {k: v for k, v in data.items()
            if not k.startswith("_") and isinstance(v, list)}


def load_enriched(path):
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    vendors = {k: v for k, v in data.items()
               if not k.startswith("_") and isinstance(v, dict)}

    import urllib.request
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = urllib.request.Request(kev_url, headers={"User-Agent": "edge-sec-gt/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            kev = json.loads(resp.read())
        kev_lookup = {v["cveID"]: v for v in kev["vulnerabilities"]}
        for vendor, cves in vendors.items():
            for cve_id, cve_data in cves.items():
                kv = kev_lookup.get(cve_id, {})
                if "kev_date_added" not in cve_data and "dateAdded" in kv:
                    cve_data["kev_date_added"] = kv["dateAdded"]
                if "kev_due_date" not in cve_data and "dueDate" in kv:
                    cve_data["kev_due_date"] = kv["dueDate"]
                if "ransomware" not in cve_data:
                    cve_data["ransomware"] = kv.get("knownRansomwareCampaignUse", "Unknown")
                if not cve_data.get("published") and "dateAdded" in kv:
                    cve_data["kev_date_added"] = kv["dateAdded"]
        print(f"# Merged KEV catalog data", file=sys.stderr)
    except Exception as e:
        print(f"# Warning: could not fetch KEV catalog: {e}", file=sys.stderr)

    return vendors


def analyze(counts, enriched):
    results = {}
    n_vendors = len(counts)
    vendor_counts = {v: len(cves) for v, cves in counts.items()}
    count_values = list(vendor_counts.values())
    total = sum(count_values)

    results["n_vendors"] = n_vendors
    results["total_cves"] = total
    results["vendor_counts"] = vendor_counts

    # Descriptive stats
    mean = total / n_vendors
    results["mean"] = mean
    results["median"] = sorted(count_values)[n_vendors // 2]
    results["std"] = math.sqrt(
        sum((c - mean) ** 2 for c in count_values) / (n_vendors - 1)
    )
    results["cv"] = coefficient_of_variation(count_values)

    # Concentration metrics
    results["hhi"] = herfindahl_hirschman(count_values)
    results["hhi_equal"] = 1.0 / n_vendors
    results["gini"] = gini_coefficient(count_values)

    # Chi-squared: are counts uniform across vendors?
    expected_uniform = [mean] * n_vendors
    chi2, df = chi_squared_gof(count_values, expected_uniform)
    p = chi_squared_p_approx(chi2, df)
    results["chi2_uniform"] = {"statistic": chi2, "df": df, "p_value": p}

    # EPSS correlation with count
    if enriched:
        vendor_epss_means = {}
        for vendor, cves in enriched.items():
            epss_vals = [d["epss"] for d in cves.values()
                         if d.get("epss") is not None]
            if epss_vals:
                vendor_epss_means[vendor] = sum(epss_vals) / len(epss_vals)

        if len(vendor_epss_means) >= 3:
            shared = [v for v in vendor_counts if v in vendor_epss_means]
            x = [vendor_counts[v] for v in shared]
            y = [vendor_epss_means[v] for v in shared]
            rho, p = spearman_rank(x, y)
            results["epss_count_correlation"] = {
                "spearman_rho": rho,
                "p_value": p,
                "n": len(shared),
                "interpretation": (
                    "significant positive" if rho > 0.5 and p < 0.05 else
                    "significant negative" if rho < -0.5 and p < 0.05 else
                    "not significant"
                ),
            }

    # Ransomware concentration
    if enriched:
        vendor_ransomware = {}
        for vendor, cves in enriched.items():
            rw = sum(1 for d in cves.values()
                     if d.get("ransomware") == "Known")
            vendor_ransomware[vendor] = rw

        total_rw = sum(vendor_ransomware.values())
        results["ransomware"] = {
            "total": total_rw,
            "by_vendor": vendor_ransomware,
            "concentration_hhi": herfindahl_hirschman(
                list(vendor_ransomware.values())
            ),
        }

    # Year-over-year acceleration
    if enriched:
        year_counts = collections.Counter()
        for vendor, cves in enriched.items():
            for data in cves.values():
                date = data.get("kev_date_added", "")
                if date:
                    year_counts[date[:4]] += 1

        years = sorted(year_counts.keys())
        if len(years) >= 3:
            vals = [year_counts[y] for y in years]
            # Simple linear regression slope
            n_y = len(vals)
            x_vals = list(range(n_y))
            x_mean = sum(x_vals) / n_y
            y_mean = sum(vals) / n_y
            num = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, vals))
            den = sum((x - x_mean) ** 2 for x in x_vals)
            slope = num / den if den else 0
            results["yoy_trend"] = {
                "years": dict(zip(years, vals)),
                "slope": slope,
                "interpretation": (
                    "accelerating" if slope > 2 else
                    "decelerating" if slope < -2 else
                    "roughly stable"
                ),
            }

    return results


def print_text(results):
    print("=" * 78)
    print("STATISTICAL FRAMEWORK — Edge Security Ground Truth")
    print("=" * 78)

    print(f"\n--- Descriptive Statistics ---")
    print(f"Vendors:     {results['n_vendors']}")
    print(f"Total CVEs:  {results['total_cves']}")
    print(f"Mean:        {results['mean']:.1f}")
    print(f"Median:      {results['median']}")
    print(f"Std Dev:     {results['std']:.1f}")
    print(f"CV:          {results['cv']:.2f} "
          f"({'high dispersion' if results['cv'] > 0.5 else 'moderate dispersion'})")

    print(f"\n--- Concentration Metrics ---")
    print(f"HHI:         {results['hhi']:.4f} (equal would be {results['hhi_equal']:.4f})")
    print(f"Gini:        {results['gini']:.3f} "
          f"(0=equal, 1=max inequality)")
    hhi_ratio = results['hhi'] / results['hhi_equal']
    print(f"HHI ratio:   {hhi_ratio:.2f}x equal "
          f"({'concentrated' if hhi_ratio > 1.5 else 'moderately concentrated' if hhi_ratio > 1.2 else 'near-uniform'})")

    chi = results["chi2_uniform"]
    print(f"\n--- Chi-Squared Uniformity Test ---")
    print(f"H₀: all vendors have equal exploitation rates")
    print(f"χ²({chi['df']}) = {chi['statistic']:.2f}, p ≈ {chi['p_value']:.4f}")
    if chi['p_value'] < 0.05:
        print(f"Result: REJECT H₀ (p < 0.05) — counts differ significantly")
        print(f"  BUT: this does NOT imply code quality differs.")
        print(f"  Confounders: installed base, researcher attention, disclosure policy")
    else:
        print(f"Result: FAIL TO REJECT H₀ — differences consistent with chance")

    if "epss_count_correlation" in results:
        ec = results["epss_count_correlation"]
        print(f"\n--- EPSS vs Count Correlation ---")
        print(f"Spearman ρ = {ec['spearman_rho']:.3f} (n={ec['n']}, "
              f"p ≈ {ec['p_value']:.3f})")
        print(f"Interpretation: {ec['interpretation']}")

    if "ransomware" in results:
        rw = results["ransomware"]
        print(f"\n--- Ransomware Association ---")
        print(f"Total CVEs with known ransomware use: {rw['total']}/{results['total_cves']} "
              f"({100*rw['total']/results['total_cves']:.0f}%)")
        for v, c in sorted(rw["by_vendor"].items(), key=lambda x: -x[1]):
            if c > 0:
                print(f"  {v}: {c}")

    if "yoy_trend" in results:
        trend = results["yoy_trend"]
        print(f"\n--- Year-over-Year Trend ---")
        for y, c in sorted(trend["years"].items()):
            print(f"  {y}: {c}")
        print(f"Linear slope: {trend['slope']:.1f} CVEs/year ({trend['interpretation']})")

    print(f"\n--- Interpretation Guide ---")
    print(f"1. Statistical significance ≠ practical significance.")
    print(f"   Even if counts differ significantly, the confounders")
    print(f"   (installed base, researcher focus) are uncontrolled.")
    print(f"2. The Gini coefficient measures inequality in the distribution,")
    print(f"   not quality. A Gini near 0 means vendors are equally exploited.")
    print(f"3. EPSS–count correlation tests whether 'more CVEs' also means")
    print(f"   'higher-probability CVEs' — or just more volume.")


def print_markdown(results):
    print("# Statistical Framework\n")

    print("## Descriptive Statistics\n")
    print("| Metric | Value |")
    print("|--------|------:|")
    print(f"| Vendors | {results['n_vendors']} |")
    print(f"| Total edge CVEs | {results['total_cves']} |")
    print(f"| Mean per vendor | {results['mean']:.1f} |")
    print(f"| Median | {results['median']} |")
    print(f"| Std deviation | {results['std']:.1f} |")
    print(f"| Coefficient of variation | {results['cv']:.2f} |")

    print("\n## Concentration\n")
    print("| Metric | Value | Interpretation |")
    print("|--------|------:|----------------|")
    hhi_ratio = results['hhi'] / results['hhi_equal']
    print(f"| HHI | {results['hhi']:.4f} | "
          f"{'concentrated' if hhi_ratio > 1.5 else 'moderate'} "
          f"(equal={results['hhi_equal']:.4f}) |")
    print(f"| Gini | {results['gini']:.3f} | "
          f"{'high' if results['gini'] > 0.3 else 'moderate' if results['gini'] > 0.15 else 'low'} "
          f"inequality |")

    chi = results["chi2_uniform"]
    print("\n## Chi-Squared Uniformity Test\n")
    print(f"**H₀:** all vendors have equal exploitation rates.\n")
    print(f"- χ²({chi['df']}) = {chi['statistic']:.2f}")
    print(f"- p ≈ {chi['p_value']:.4f}")
    if chi['p_value'] < 0.05:
        print(f"\n**Result:** REJECT H₀ (p < 0.05). Vendor counts differ "
              f"significantly from uniform.\n")
        print("> **Critical caveat:** rejecting uniformity does NOT demonstrate "
              "that vendors differ in code quality. The primary confounders — "
              "installed base, researcher attention, and disclosure transparency — "
              "are uncontrolled. This test confirms the *distribution is uneven*, "
              "not *why*.")
    else:
        print(f"\n**Result:** Fail to reject H₀. Differences are consistent "
              f"with random variation.")

    if "ransomware" in results:
        rw = results["ransomware"]
        print(f"\n## Ransomware Association\n")
        pct = 100 * rw['total'] / results['total_cves']
        print(f"**{rw['total']}/{results['total_cves']}** ({pct:.0f}%) edge CVEs "
              f"have known ransomware campaign use.\n")
        print("| Vendor | Ransomware CVEs |")
        print("|--------|----------------:|")
        for v, c in sorted(rw["by_vendor"].items(), key=lambda x: -x[1]):
            if c > 0:
                print(f"| {v} | {c} |")

    if "yoy_trend" in results:
        trend = results["yoy_trend"]
        print(f"\n## Year-over-Year Trend\n")
        print("| Year | Edge KEV Additions |")
        print("|------|-------------------:|")
        for y, c in sorted(trend["years"].items()):
            print(f"| {y} | {c} |")
        print(f"\nLinear slope: **{trend['slope']:.1f}** CVEs/year "
              f"({trend['interpretation']})")


def print_json(results):
    def clean(obj):
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                return None
            return round(obj, 6)
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [clean(v) for v in obj]
        return obj

    json.dump(clean(results), sys.stdout, indent=2)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Statistical framework for edge CVE analysis.")
    parser.add_argument("--format", "-f", choices=["text", "markdown", "json"],
                        default="text")
    parser.add_argument("--output", "-o")
    args = parser.parse_args()

    if not os.path.isfile(COUNTS_PATH):
        print(f"Error: {COUNTS_PATH} not found", file=sys.stderr)
        sys.exit(1)

    counts = load_counts(COUNTS_PATH)
    enriched = load_enriched(ENRICHED_PATH)
    results = analyze(counts, enriched)

    if args.output:
        sys.stdout = open(args.output, "w")

    if args.format == "markdown":
        print_markdown(results)
    elif args.format == "json":
        print_json(results)
    else:
        print_text(results)


if __name__ == "__main__":
    main()
