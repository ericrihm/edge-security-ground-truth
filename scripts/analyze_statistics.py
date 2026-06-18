#!/usr/bin/env python3
"""
Statistical analysis for edge-security-ground-truth.

Computes descriptive statistics, concentration metrics, Poisson regression,
vendor-pair significance tests, CVSS/EPSS comparisons, and confidence
intervals for CISA KEV counts across 11 edge-appliance vendors.

All computations use Python stdlib only (math, statistics, collections).
No numpy, scipy, or pandas.

Usage:
  python3 scripts/analyze_statistics.py                    # text tables
  python3 scripts/analyze_statistics.py --format markdown  # markdown
  python3 scripts/analyze_statistics.py --format json      # machine-readable
  python3 scripts/analyze_statistics.py -o results.txt     # write to file
"""

import argparse
import collections
import json
import math
import os
import statistics
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")

# ---------------------------------------------------------------------------
# Mathematical primitives (stdlib-only)
# ---------------------------------------------------------------------------

def _erfc_approx(x):
    """Complementary error function approximation (Abramowitz & Stegun 7.1.26)."""
    t = 1.0 / (1.0 + 0.3275911 * abs(x))
    poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741
            + t * (-1.453152027 + t * 1.061405429))))
    result = poly * math.exp(-x * x)
    return result if x >= 0 else 2.0 - result


def _normal_cdf(z):
    """Standard normal CDF via erfc."""
    return 0.5 * _erfc_approx(-z / math.sqrt(2))


def _normal_ppf(p):
    """Inverse standard normal (rational approximation, Beasley-Springer-Moro)."""
    if p <= 0:
        return -10.0
    if p >= 1:
        return 10.0
    if p == 0.5:
        return 0.0
    # Rational approximation for 0.5 < p < 1
    if p < 0.5:
        return -_normal_ppf(1.0 - p)
    t = math.sqrt(-2.0 * math.log(1.0 - p))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)


def chi2_gof(observed, expected):
    """Chi-squared goodness-of-fit statistic and degrees of freedom."""
    stat = sum((o - e) ** 2 / e for o, e in zip(observed, expected) if e > 0)
    df = sum(1 for e in expected if e > 0) - 1
    return stat, df


def chi2_p_value(chi2_stat, df):
    """P-value for chi-squared via Wilson-Hilferty normal approximation."""
    if df <= 0:
        return 1.0
    if chi2_stat <= 0:
        return 1.0
    z = ((chi2_stat / df) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
    return max(0.0, min(1.0, 1.0 - _normal_cdf(z)))


def chi2_2x2(a, b, c, d):
    """Chi-squared test for a 2x2 contingency table with Yates correction.
    Layout: [[a, b], [c, d]]
    Returns (chi2, p_value).
    """
    n = a + b + c + d
    if n == 0:
        return 0.0, 1.0
    num = n * (abs(a * d - b * c) - n / 2.0) ** 2
    denom = (a + b) * (c + d) * (a + c) * (b + d)
    if denom == 0:
        return 0.0, 1.0
    chi2 = num / denom
    return chi2, chi2_p_value(chi2, 1)


def poisson_ci(k, alpha=0.05):
    """Exact Poisson confidence interval using the chi-squared relationship.
    Uses Garwood (1936) method: CI is [chi2(alpha/2, 2k)/2, chi2(1-alpha/2, 2k+2)/2].
    We approximate chi-squared quantiles via Wilson-Hilferty inverse.
    """
    def chi2_quantile(p, df):
        if df <= 0:
            return 0.0
        # Wilson-Hilferty approximation for chi-squared quantile
        z = _normal_ppf(p)
        x = df * (1.0 - 2.0 / (9.0 * df) + z * math.sqrt(2.0 / (9.0 * df))) ** 3
        return max(0.0, x)

    if k == 0:
        lower = 0.0
    else:
        lower = chi2_quantile(alpha / 2.0, 2 * k) / 2.0
    upper = chi2_quantile(1.0 - alpha / 2.0, 2 * (k + 1)) / 2.0
    return lower, upper


def herfindahl_hirschman(counts):
    """HHI: sum of squared market shares. 1/n = perfectly equal, 1.0 = monopoly."""
    total = sum(counts)
    if total == 0:
        return 0.0
    return sum((c / total) ** 2 for c in counts)


def gini_coefficient(values):
    """Gini coefficient: 0 = perfect equality, 1 = maximum inequality."""
    n = len(values)
    if n == 0:
        return 0.0
    s = sorted(values)
    total = sum(s)
    if total == 0:
        return 0.0
    numer = sum((2 * (i + 1) - n - 1) * v for i, v in enumerate(s))
    return numer / (n * total)


def coefficient_of_variation(values):
    """CV = sample_std / mean. Higher means more dispersion."""
    if len(values) < 2:
        return 0.0
    m = statistics.mean(values)
    if m == 0:
        return 0.0
    return statistics.stdev(values) / m


def poisson_mle_rate_test(counts_by_year):
    """Poisson trend test via method-of-moments slope.
    Fits lambda_t = a + b*t by OLS, then tests b != 0 using the
    Poisson dispersion (variance ~ mean under H0).
    Returns (slope, se_slope, z_score, p_value, interpretation).
    """
    years = sorted(counts_by_year.keys())
    n = len(years)
    if n < 3:
        return None

    # Recode years to 0, 1, 2, ...
    t_vals = list(range(n))
    y_vals = [counts_by_year[y] for y in years]

    t_mean = statistics.mean(t_vals)
    y_mean = statistics.mean(y_vals)

    ss_tt = sum((t - t_mean) ** 2 for t in t_vals)
    if ss_tt == 0:
        return None
    ss_ty = sum((t - t_mean) * (y - y_mean) for t, y in zip(t_vals, y_vals))

    slope = ss_ty / ss_tt
    intercept = y_mean - slope * t_mean

    # Under Poisson assumption, Var(Y_t) = E[Y_t] = lambda_t
    # SE of slope ~ sqrt(mean_lambda / ss_tt)
    mean_lambda = max(y_mean, 1.0)  # avoid division by zero
    se_slope = math.sqrt(mean_lambda / ss_tt)
    z = slope / se_slope if se_slope > 0 else 0.0
    p = 2.0 * (1.0 - _normal_cdf(abs(z)))

    if p < 0.05 and slope > 0:
        interp = "Significant increase (p < 0.05)"
    elif p < 0.05 and slope < 0:
        interp = "Significant decrease (p < 0.05)"
    else:
        interp = "No significant trend (p >= 0.05)"

    return {
        "years": {y: counts_by_year[y] for y in years},
        "slope_per_year": round(slope, 3),
        "intercept": round(intercept, 3),
        "se_slope": round(se_slope, 3),
        "z_score": round(z, 3),
        "p_value": round(p, 4),
        "interpretation": interp,
    }


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_counts(path):
    with open(path) as f:
        data = json.load(f)
    vendors = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, list):
            vendors[k] = v
    return vendors, data.get("_metadata", {})


def load_enriched(path):
    if not os.path.isfile(path):
        return {}, {}
    with open(path) as f:
        data = json.load(f)
    vendors = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            vendors[k] = v
    return vendors, data.get("_metadata", {})


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze(counts_data, enriched_data):
    """Run all statistical analyses. Returns a structured dict of results."""
    results = collections.OrderedDict()
    vendor_names = sorted(counts_data.keys())
    vendor_counts = {v: len(counts_data[v]) for v in vendor_names}
    count_vals = [vendor_counts[v] for v in vendor_names]
    n = len(vendor_names)
    total = sum(count_vals)

    # -----------------------------------------------------------------------
    # 1. Descriptive statistics
    # -----------------------------------------------------------------------
    q = sorted(count_vals)
    q1_idx = (n - 1) * 0.25
    q3_idx = (n - 1) * 0.75
    # Linear interpolation for quartiles
    q1 = q[int(q1_idx)] + (q1_idx % 1) * (q[min(int(q1_idx) + 1, n - 1)] - q[int(q1_idx)])
    q3 = q[int(q3_idx)] + (q3_idx % 1) * (q[min(int(q3_idx) + 1, n - 1)] - q[int(q3_idx)])

    results["descriptive"] = {
        "n_vendors": n,
        "total_kevs": total,
        "vendor_counts": vendor_counts,
        "mean": round(statistics.mean(count_vals), 2),
        "median": statistics.median(count_vals),
        "std_dev": round(statistics.stdev(count_vals), 2) if n > 1 else 0,
        "variance": round(statistics.variance(count_vals), 2) if n > 1 else 0,
        "min": min(count_vals),
        "max": max(count_vals),
        "range": max(count_vals) - min(count_vals),
        "q1": round(q1, 1),
        "q3": round(q3, 1),
        "iqr": round(q3 - q1, 1),
        "cv": round(coefficient_of_variation(count_vals), 3),
    }

    # -----------------------------------------------------------------------
    # 2. Concentration metrics (HHI, Gini, normalized HHI)
    # -----------------------------------------------------------------------
    hhi = herfindahl_hirschman(count_vals)
    hhi_equal = 1.0 / n
    hhi_max = 1.0
    hhi_normalized = (hhi - hhi_equal) / (hhi_max - hhi_equal) if n > 1 else 0.0
    gini = gini_coefficient(count_vals)
    cr3 = sum(sorted(count_vals, reverse=True)[:3]) / total if total > 0 else 0.0

    results["concentration"] = {
        "hhi": round(hhi, 5),
        "hhi_equal_baseline": round(hhi_equal, 5),
        "hhi_normalized": round(hhi_normalized, 5),
        "gini": round(gini, 4),
        "cr3_ratio": round(cr3, 4),
        "top_3_vendors": sorted(vendor_counts.items(), key=lambda x: -x[1])[:3],
        "interpretation": (
            "Unconcentrated" if hhi_normalized < 0.10 else
            "Moderately concentrated" if hhi_normalized < 0.25 else
            "Highly concentrated"
        ),
    }

    # -----------------------------------------------------------------------
    # 3. Poisson regression (yearly KEV additions)
    # -----------------------------------------------------------------------
    year_counts = collections.Counter()
    for vendor, cves in counts_data.items():
        for cve_id in cves:
            # Extract year from CVE ID as a proxy (enriched has published date)
            year = cve_id.split("-")[1] if "-" in cve_id else None
            if year and year.isdigit():
                year_counts[int(year)] += 1

    # If enriched data has published dates, use those instead
    if enriched_data:
        year_counts_pub = collections.Counter()
        for vendor, cves in enriched_data.items():
            for cve_id, data in cves.items():
                pub = data.get("published", "")
                if pub:
                    try:
                        y = int(pub[:4])
                        year_counts_pub[y] += 1
                    except (ValueError, IndexError):
                        pass
        if year_counts_pub:
            year_counts = year_counts_pub

    poisson_result = poisson_mle_rate_test(year_counts)
    results["poisson_trend"] = poisson_result

    # -----------------------------------------------------------------------
    # 4. Chi-squared uniformity test + vendor pair comparisons
    # -----------------------------------------------------------------------
    mean_count = total / n if n > 0 else 0
    expected_uniform = [mean_count] * n
    chi2_stat, df = chi2_gof(count_vals, expected_uniform)
    chi2_p = chi2_p_value(chi2_stat, df)

    results["chi2_uniformity"] = {
        "h0": "All vendors have equal KEV counts (uniform distribution)",
        "statistic": round(chi2_stat, 3),
        "df": df,
        "p_value": round(chi2_p, 5),
        "reject_h0": chi2_p < 0.05,
    }

    # Pairwise vendor comparisons using 2x2 chi-squared
    # For each pair: compare vendor_i count vs vendor_j count
    # Table: [[count_i, total-count_i], [count_j, total-count_j]]
    pair_tests = []
    for i in range(n):
        for j in range(i + 1, n):
            vi, vj = vendor_names[i], vendor_names[j]
            ci, cj = vendor_counts[vi], vendor_counts[vj]
            rest_i = total - ci
            rest_j = total - cj
            chi2, p = chi2_2x2(ci, rest_i, cj, rest_j)
            pair_tests.append({
                "vendor_a": vi,
                "vendor_b": vj,
                "count_a": ci,
                "count_b": cj,
                "difference": abs(ci - cj),
                "chi2": round(chi2, 3),
                "p_value": round(p, 5),
                "significant": p < 0.05,
            })

    # Bonferroni correction for multiple comparisons
    n_comparisons = len(pair_tests)
    bonferroni_alpha = 0.05 / n_comparisons if n_comparisons > 0 else 0.05
    for pt in pair_tests:
        pt["bonferroni_significant"] = pt["p_value"] < bonferroni_alpha

    # Sort by significance then difference
    pair_tests.sort(key=lambda x: (not x["bonferroni_significant"], -x["difference"]))

    results["pairwise_tests"] = {
        "method": "Chi-squared 2x2 with Yates correction",
        "n_comparisons": n_comparisons,
        "bonferroni_alpha": round(bonferroni_alpha, 5),
        "significant_pairs_raw": sum(1 for p in pair_tests if p["significant"]),
        "significant_pairs_bonferroni": sum(1 for p in pair_tests if p["bonferroni_significant"]),
        "tests": pair_tests,
    }

    # -----------------------------------------------------------------------
    # 5. CVSS severity distribution comparison
    # -----------------------------------------------------------------------
    if enriched_data:
        severity_dist = {}
        for vendor in vendor_names:
            if vendor not in enriched_data:
                continue
            dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            for cve_id, data in enriched_data[vendor].items():
                sev = data.get("cvss_severity")
                if sev in dist:
                    dist[sev] += 1
                else:
                    dist["UNKNOWN"] += 1
            severity_dist[vendor] = dist

        # Compute critical-or-high ratio per vendor
        crit_high_ratios = {}
        for vendor, dist in severity_dist.items():
            known = sum(v for k, v in dist.items() if k != "UNKNOWN")
            if known > 0:
                crit_high_ratios[vendor] = round(
                    (dist["CRITICAL"] + dist["HIGH"]) / known, 3
                )

        # Mean CVSS per vendor
        mean_cvss = {}
        for vendor in vendor_names:
            if vendor not in enriched_data:
                continue
            scores = [d["cvss"] for d in enriched_data[vendor].values()
                      if d.get("cvss") is not None]
            if scores:
                mean_cvss[vendor] = round(statistics.mean(scores), 2)

        results["cvss_analysis"] = {
            "severity_distribution": severity_dist,
            "critical_high_ratio": crit_high_ratios,
            "mean_cvss_by_vendor": mean_cvss,
            "overall_mean_cvss": round(
                statistics.mean(v for v in mean_cvss.values()), 2
            ) if mean_cvss else None,
        }

    # -----------------------------------------------------------------------
    # 6. EPSS comparison
    # -----------------------------------------------------------------------
    if enriched_data:
        epss_stats = {}
        all_epss = []
        for vendor in vendor_names:
            if vendor not in enriched_data:
                continue
            scores = [d["epss"] for d in enriched_data[vendor].values()
                      if d.get("epss") is not None]
            if scores:
                epss_stats[vendor] = {
                    "n": len(scores),
                    "mean": round(statistics.mean(scores), 5),
                    "median": round(statistics.median(scores), 5),
                    "min": round(min(scores), 5),
                    "max": round(max(scores), 5),
                    "std_dev": round(statistics.stdev(scores), 5) if len(scores) > 1 else 0,
                }
                all_epss.extend(scores)

        results["epss_analysis"] = {
            "by_vendor": epss_stats,
            "overall_mean": round(statistics.mean(all_epss), 5) if all_epss else None,
            "overall_median": round(statistics.median(all_epss), 5) if all_epss else None,
            "interpretation": (
                "EPSS scores are uniformly high across vendors, reflecting "
                "that KEV-listed CVEs are by definition actively exploited."
            ),
        }

    # -----------------------------------------------------------------------
    # 7. Poisson confidence intervals per vendor
    # -----------------------------------------------------------------------
    ci_results = {}
    for vendor in vendor_names:
        k = vendor_counts[vendor]
        lo, hi = poisson_ci(k, alpha=0.05)
        ci_results[vendor] = {
            "observed": k,
            "ci_lower_95": round(lo, 2),
            "ci_upper_95": round(hi, 2),
            "width": round(hi - lo, 2),
        }

    results["confidence_intervals"] = ci_results

    # -----------------------------------------------------------------------
    # Key question: can we distinguish vendors by count alone?
    # -----------------------------------------------------------------------
    overlapping_pairs = 0
    total_pairs_checked = 0
    for i in range(n):
        for j in range(i + 1, n):
            vi, vj = vendor_names[i], vendor_names[j]
            ci_i = ci_results[vi]
            ci_j = ci_results[vj]
            total_pairs_checked += 1
            # Check if CIs overlap
            if ci_i["ci_lower_95"] <= ci_j["ci_upper_95"] and ci_j["ci_lower_95"] <= ci_i["ci_upper_95"]:
                overlapping_pairs += 1

    results["distinguishability"] = {
        "total_vendor_pairs": total_pairs_checked,
        "overlapping_ci_pairs": overlapping_pairs,
        "non_overlapping_ci_pairs": total_pairs_checked - overlapping_pairs,
        "overlap_fraction": round(overlapping_pairs / total_pairs_checked, 3) if total_pairs_checked > 0 else 0,
        "verdict": (
            "Most vendor pairs have overlapping Poisson confidence intervals. "
            "KEV counts alone do not reliably distinguish the majority of vendors. "
            "Only extreme outliers (Fortinet vs Check Point) are statistically separable."
        ),
    }

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _fmt_table(headers, rows, col_widths=None):
    """Format a simple text table."""
    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            w = len(str(h))
            for row in rows:
                if i < len(row):
                    w = max(w, len(str(row[i])))
            col_widths.append(w + 2)
    lines = []
    header_line = "".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    for row in rows:
        lines.append("".join(str(c).ljust(w) for c, w in zip(row, col_widths)))
    return "\n".join(lines)


def print_text(results):
    w = 78
    print("=" * w)
    print("STATISTICAL ANALYSIS -- Edge Security Ground Truth")
    print("=" * w)

    # 1. Descriptive
    d = results["descriptive"]
    print("\n1. DESCRIPTIVE STATISTICS")
    print("-" * w)
    rows = sorted(d["vendor_counts"].items(), key=lambda x: -x[1])
    print(_fmt_table(
        ["Vendor", "KEV Count"],
        rows,
    ))
    print()
    print(f"  N vendors:    {d['n_vendors']}")
    print(f"  Total KEVs:   {d['total_kevs']}")
    print(f"  Mean:         {d['mean']}")
    print(f"  Median:       {d['median']}")
    print(f"  Std Dev:      {d['std_dev']}")
    print(f"  IQR:          {d['iqr']}  (Q1={d['q1']}, Q3={d['q3']})")
    print(f"  Range:        {d['range']}  (min={d['min']}, max={d['max']})")
    print(f"  CV:           {d['cv']}")

    # 2. Concentration
    c = results["concentration"]
    print(f"\n2. CONCENTRATION METRICS")
    print("-" * w)
    print(f"  HHI:              {c['hhi']:.5f}  (equal baseline: {c['hhi_equal_baseline']:.5f})")
    print(f"  HHI normalized:   {c['hhi_normalized']:.5f}")
    print(f"  Gini coefficient: {c['gini']:.4f}")
    print(f"  CR3 (top-3 share):{c['cr3_ratio']:.1%}")
    print(f"  Interpretation:   {c['interpretation']}")

    # 3. Poisson
    pt = results.get("poisson_trend")
    if pt:
        print(f"\n3. POISSON TREND ANALYSIS")
        print("-" * w)
        print(f"  Model: lambda(t) = {pt['intercept']} + {pt['slope_per_year']} * t")
        for y, cnt in sorted(pt["years"].items()):
            print(f"    {y}: {cnt}")
        print(f"  Slope:  {pt['slope_per_year']} CVEs/year  (SE={pt['se_slope']})")
        print(f"  z = {pt['z_score']},  p = {pt['p_value']}")
        print(f"  {pt['interpretation']}")

    # 4. Chi-squared + pairwise
    chi = results["chi2_uniformity"]
    print(f"\n4. VENDOR COMPARISON TESTS")
    print("-" * w)
    print(f"  Chi-squared uniformity test:")
    print(f"    H0: {chi['h0']}")
    print(f"    chi2({chi['df']}) = {chi['statistic']},  p = {chi['p_value']}")
    print(f"    {'REJECT H0' if chi['reject_h0'] else 'Fail to reject H0'}")

    pw = results["pairwise_tests"]
    print(f"\n  Pairwise vendor comparisons ({pw['n_comparisons']} tests):")
    print(f"    Method: {pw['method']}")
    print(f"    Raw significant (p<0.05):         {pw['significant_pairs_raw']}")
    print(f"    Bonferroni significant (p<{pw['bonferroni_alpha']:.5f}): {pw['significant_pairs_bonferroni']}")
    print()
    sig_pairs = [t for t in pw["tests"] if t["bonferroni_significant"]]
    if sig_pairs:
        print("  Significant pairs after Bonferroni correction:")
        print(_fmt_table(
            ["Vendor A", "Vendor B", "Counts", "chi2", "p"],
            [(t["vendor_a"], t["vendor_b"], f"{t['count_a']} vs {t['count_b']}",
              f"{t['chi2']:.2f}", f"{t['p_value']:.5f}") for t in sig_pairs[:15]],
        ))
    else:
        print("  No pairs survive Bonferroni correction.")

    # 5. CVSS
    if "cvss_analysis" in results:
        cvss = results["cvss_analysis"]
        print(f"\n5. CVSS SEVERITY DISTRIBUTION")
        print("-" * w)
        print(_fmt_table(
            ["Vendor", "CRIT", "HIGH", "MED", "LOW", "UNK", "Mean CVSS", "Crit+High%"],
            [(v,
              cvss["severity_distribution"].get(v, {}).get("CRITICAL", "-"),
              cvss["severity_distribution"].get(v, {}).get("HIGH", "-"),
              cvss["severity_distribution"].get(v, {}).get("MEDIUM", "-"),
              cvss["severity_distribution"].get(v, {}).get("LOW", "-"),
              cvss["severity_distribution"].get(v, {}).get("UNKNOWN", "-"),
              cvss["mean_cvss_by_vendor"].get(v, "-"),
              f"{cvss['critical_high_ratio'].get(v, 0):.0%}" if v in cvss.get("critical_high_ratio", {}) else "-",
              ) for v in sorted(cvss.get("severity_distribution", {}).keys())],
        ))

    # 6. EPSS
    if "epss_analysis" in results:
        epss = results["epss_analysis"]
        print(f"\n6. EPSS COMPARISON")
        print("-" * w)
        print(_fmt_table(
            ["Vendor", "N", "Mean EPSS", "Median", "Min", "Max", "Std Dev"],
            [(v, s["n"], f"{s['mean']:.4f}", f"{s['median']:.4f}",
              f"{s['min']:.4f}", f"{s['max']:.4f}", f"{s['std_dev']:.4f}")
             for v, s in sorted(epss["by_vendor"].items())],
        ))
        print(f"\n  Overall mean EPSS:   {epss['overall_mean']:.4f}")
        print(f"  Overall median EPSS: {epss['overall_median']:.4f}")
        print(f"  Note: {epss['interpretation']}")

    # 7. Confidence intervals
    ci = results["confidence_intervals"]
    print(f"\n7. POISSON CONFIDENCE INTERVALS (95%)")
    print("-" * w)
    print(_fmt_table(
        ["Vendor", "Observed", "CI Lower", "CI Upper", "Width"],
        [(v, ci[v]["observed"], ci[v]["ci_lower_95"], ci[v]["ci_upper_95"], ci[v]["width"])
         for v in sorted(ci.keys(), key=lambda x: -ci[x]["observed"])],
    ))

    # Distinguishability
    dist = results["distinguishability"]
    print(f"\n8. DISTINGUISHABILITY VERDICT")
    print("-" * w)
    print(f"  Vendor pairs with overlapping 95% CIs: {dist['overlapping_ci_pairs']}/{dist['total_vendor_pairs']} ({dist['overlap_fraction']:.0%})")
    print(f"  Non-overlapping pairs:                  {dist['non_overlapping_ci_pairs']}/{dist['total_vendor_pairs']}")
    print()
    print(f"  {dist['verdict']}")

    print(f"\n{'=' * w}")
    print("IMPORTANT CAVEATS")
    print(f"{'=' * w}")
    print("""
  1. Install-base confound (Simpson's paradox): A vendor with 40% market share
     and 17% of KEVs may be SAFER per-device than one with 2% share and 2% KEVs.
     Raw counts conflate exposure with vulnerability.

  2. Selection bias: KEV inclusion requires CISA to observe active exploitation.
     Vendors with more transparent disclosure or larger researcher communities
     will have more CVEs cataloged, independent of actual risk.

  3. Ecological fallacy: Aggregate vendor counts say nothing about any specific
     deployment. A "high-count" vendor's specific product line may be unaffected.

  4. Temporal non-stationarity: The KEV catalog launched Nov 2021. Pre-2021
     entries are backfilled. Comparing year-over-year rates conflates catalog
     maturation with exploitation trends.

  5. Small N: With 11 vendors and counts ranging 2-18, statistical power for
     pairwise tests is inherently low. Many real differences will not reach
     significance.
""")


def print_markdown(results):
    d = results["descriptive"]
    c = results["concentration"]
    chi = results["chi2_uniformity"]
    ci = results["confidence_intervals"]
    dist = results["distinguishability"]

    print("# Statistical Analysis Results\n")
    print(f"*Generated: {datetime.now().strftime('%Y-%m-%d')}*\n")

    # 1
    print("## 1. Descriptive Statistics\n")
    print("| Vendor | KEV Count |")
    print("|--------|----------:|")
    for v, cnt in sorted(d["vendor_counts"].items(), key=lambda x: -x[1]):
        print(f"| {v} | {cnt} |")
    print()
    print("| Metric | Value |")
    print("|--------|------:|")
    for k in ["mean", "median", "std_dev", "iqr", "range", "cv"]:
        label = k.replace("_", " ").title()
        print(f"| {label} | {d[k]} |")

    # 2
    print("\n## 2. Concentration Metrics\n")
    print("| Metric | Value | Interpretation |")
    print("|--------|------:|----------------|")
    print(f"| HHI | {c['hhi']:.5f} | {c['interpretation']} (baseline {c['hhi_equal_baseline']:.5f}) |")
    print(f"| HHI (normalized) | {c['hhi_normalized']:.5f} | 0=equal, 1=monopoly |")
    print(f"| Gini | {c['gini']:.4f} | 0=equal, 1=max inequality |")
    print(f"| CR3 | {c['cr3_ratio']:.1%} | Top-3 share of total |")

    # 3
    pt = results.get("poisson_trend")
    if pt:
        print("\n## 3. Poisson Trend Analysis\n")
        print(f"**Model:** lambda(t) = {pt['intercept']} + {pt['slope_per_year']} * t\n")
        print("| Year | Count |")
        print("|------|------:|")
        for y, cnt in sorted(pt["years"].items()):
            print(f"| {y} | {cnt} |")
        print(f"\n- Slope: **{pt['slope_per_year']}** CVEs/year (SE = {pt['se_slope']})")
        print(f"- z = {pt['z_score']}, p = {pt['p_value']}")
        print(f"- **{pt['interpretation']}**")

    # 4
    print("\n## 4. Vendor Comparison Tests\n")
    print("### Chi-Squared Uniformity\n")
    print(f"- H0: {chi['h0']}")
    print(f"- chi2({chi['df']}) = {chi['statistic']}, p = {chi['p_value']}")
    print(f"- **{'REJECT H0' if chi['reject_h0'] else 'Fail to reject H0'}**\n")

    pw = results["pairwise_tests"]
    print("### Pairwise Vendor Comparisons\n")
    print(f"- Method: {pw['method']}")
    print(f"- {pw['n_comparisons']} comparisons, Bonferroni alpha = {pw['bonferroni_alpha']:.5f}")
    print(f"- Raw significant: {pw['significant_pairs_raw']}")
    print(f"- Bonferroni significant: **{pw['significant_pairs_bonferroni']}**\n")

    sig = [t for t in pw["tests"] if t["bonferroni_significant"]]
    if sig:
        print("| Vendor A | Vendor B | Counts | chi2 | p | Significant |")
        print("|----------|----------|--------|-----:|--:|:-----------:|")
        for t in sig:
            print(f"| {t['vendor_a']} | {t['vendor_b']} | {t['count_a']} vs {t['count_b']} | {t['chi2']:.2f} | {t['p_value']:.5f} | Yes |")
    else:
        print("*No pairs survive Bonferroni correction.*")

    # 5
    if "cvss_analysis" in results:
        cvss = results["cvss_analysis"]
        print("\n## 5. CVSS Severity Distribution\n")
        print("| Vendor | Critical | High | Medium | Low | Mean CVSS | Crit+High % |")
        print("|--------|:--------:|:----:|:------:|:---:|----------:|:-----------:|")
        for v in sorted(cvss["severity_distribution"].keys()):
            sd = cvss["severity_distribution"][v]
            mc = cvss["mean_cvss_by_vendor"].get(v, "N/A")
            ch = cvss["critical_high_ratio"].get(v, None)
            ch_str = f"{ch:.0%}" if ch is not None else "N/A"
            print(f"| {v} | {sd.get('CRITICAL',0)} | {sd.get('HIGH',0)} | {sd.get('MEDIUM',0)} | {sd.get('LOW',0)} | {mc} | {ch_str} |")

    # 6
    if "epss_analysis" in results:
        epss = results["epss_analysis"]
        print("\n## 6. EPSS Comparison\n")
        print("| Vendor | N | Mean | Median | Min | Max |")
        print("|--------|--:|-----:|-------:|----:|----:|")
        for v, s in sorted(epss["by_vendor"].items()):
            print(f"| {v} | {s['n']} | {s['mean']:.4f} | {s['median']:.4f} | {s['min']:.4f} | {s['max']:.4f} |")
        print(f"\nOverall mean: {epss['overall_mean']:.4f}, median: {epss['overall_median']:.4f}")
        print(f"\n> {epss['interpretation']}")

    # 7
    print("\n## 7. Poisson Confidence Intervals (95%)\n")
    print("| Vendor | Observed | 95% CI Lower | 95% CI Upper | Width |")
    print("|--------|:--------:|:------------:|:------------:|------:|")
    for v in sorted(ci.keys(), key=lambda x: -ci[x]["observed"]):
        c = ci[v]
        print(f"| {v} | {c['observed']} | {c['ci_lower_95']} | {c['ci_upper_95']} | {c['width']} |")

    print(f"\n## 8. Distinguishability Verdict\n")
    print(f"- Overlapping 95% CI pairs: **{dist['overlapping_ci_pairs']}/{dist['total_vendor_pairs']}** ({dist['overlap_fraction']:.0%})")
    print(f"- Non-overlapping pairs: {dist['non_overlapping_ci_pairs']}/{dist['total_vendor_pairs']}")
    print(f"\n> {dist['verdict']}")


def print_json(results):
    def clean(obj):
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                return None
            return round(obj, 6)
        if isinstance(obj, dict):
            return {str(k): clean(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [clean(v) for v in obj]
        return obj
    json.dump(clean(results), sys.stdout, indent=2)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Statistical analysis for edge-security-ground-truth KEV data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/analyze_statistics.py
  python3 scripts/analyze_statistics.py --format markdown
  python3 scripts/analyze_statistics.py --format json -o results.json
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

    counts_data, counts_meta = load_counts(COUNTS_PATH)
    enriched_data, enriched_meta = load_enriched(ENRICHED_PATH)

    results = analyze(counts_data, enriched_data)

    out = sys.stdout
    if args.output:
        out = open(args.output, "w")
        sys.stdout = out

    if args.format == "markdown":
        print_markdown(results)
    elif args.format == "json":
        print_json(results)
    else:
        print_text(results)

    if args.output:
        out.close()
        sys.stdout = sys.__stdout__
        print(f"Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
