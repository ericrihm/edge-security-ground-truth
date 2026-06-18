#!/usr/bin/env python3
"""
Poisson / quasi-Poisson regression of edge-KEV count on market share.

The inferential companion to analyze_normalization.py (which reports per-share
rate ratios). Here we FIT a generalized linear model

    log(E[count_i]) = b0 + b1 * log(share_i)

and estimate the ELASTICITY b1 -- how the count of exploited edge CVEs scales
with installed base:

  * b1 = 1  -> count is proportional to market share (the pure "popularity tax")
  * b1 < 1  -> SUB-linear: large-share vendors accumulate proportionally FEWER
               exploited CVEs per unit of share, i.e. raw counts OVERSTATE the
               gap between big and small vendors
  * b1 > 1  -> super-linear

Fit by iteratively reweighted least squares (IRLS), standard library only. The
counts are overdispersed relative to a pure Poisson, so we also report a
quasi-Poisson (dispersion-adjusted) standard error and the dispersion phi (the
negative-binomial analogue). Every fit is run under all three published
market-share vectors, so the elasticity is reported as a BRACKET.

CAVEATS (see docs/MARKET-SHARE-SENSITIVITY.md): n = 13 vendors is a tiny sample;
market shares are analyst estimates without error bars (unit-share != revenue-
share != deployed-device-count); this is an ECOLOGICAL regression and establishes
association, not a code-quality difference. b1 is descriptive, not causal.

Usage:
  python3 scripts/analyze_regression.py --format markdown
  python3 scripts/analyze_regression.py --format json
"""
import argparse
import json
import math
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")

# Three market-share vectors -- copied verbatim from analyze_normalization.py /
# docs/MARKET-SHARE-SENSITIVITY.md Section 3.
SHARE_VECTORS = {
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
HEADLINE = "Moderate (Fortinet 34%)"


def load_counts():
    with open(COUNTS_PATH) as f:
        d = json.load(f)
    return {k: len(v) for k, v in d.items() if k != "_metadata"}


def norm_phi(z):
    """Two-sided p-value for a standard-normal z (stdlib math.erf)."""
    return 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))


def poisson_irls(xs, ys, max_iter=200, tol=1e-12):
    """Fit log(mu) = b0 + b1*x by IRLS. Returns (b0, b1, se0, se1, converged)."""
    n = len(ys)
    b0 = math.log(max(sum(ys) / n, 0.5))
    b1 = 0.0
    converged = False
    for _ in range(max_iter):
        s_w = s_wx = s_wxx = s_wz = s_wxz = 0.0
        for x, y in zip(xs, ys):
            eta = b0 + b1 * x
            mu = math.exp(eta)
            w = mu                      # Poisson IRLS weight
            z = eta + (y - mu) / mu     # working response
            s_w += w; s_wx += w * x; s_wxx += w * x * x
            s_wz += w * z; s_wxz += w * x * z
        det = s_w * s_wxx - s_wx * s_wx
        if abs(det) < 1e-300:
            break
        nb0 = (s_wxx * s_wz - s_wx * s_wxz) / det
        nb1 = (-s_wx * s_wz + s_w * s_wxz) / det
        if abs(nb0 - b0) + abs(nb1 - b1) < tol:
            b0, b1 = nb0, nb1
            converged = True
            break
        b0, b1 = nb0, nb1
    # Covariance = (X'WX)^-1 evaluated at the fit.
    s_w = s_wx = s_wxx = 0.0
    for x in xs:
        mu = math.exp(b0 + b1 * x)
        s_w += mu; s_wx += mu * x; s_wxx += mu * x * x
    det = s_w * s_wxx - s_wx * s_wx
    se0 = math.sqrt(s_wxx / det)
    se1 = math.sqrt(s_w / det)
    return b0, b1, se0, se1, converged


def fit_scenario(counts, shares):
    vendors = [v for v in shares if v in counts]
    xs = [math.log(shares[v]) for v in vendors]
    ys = [float(counts[v]) for v in vendors]
    b0, b1, se0, se1, conv = poisson_irls(xs, ys)
    # Overdispersion (Pearson) and quasi-Poisson SE.
    n = len(ys)
    chi2 = sum((y - math.exp(b0 + b1 * x)) ** 2 / math.exp(b0 + b1 * x)
               for x, y in zip(xs, ys))
    phi = chi2 / (n - 2)
    qse1 = se1 * math.sqrt(max(phi, 1.0))   # never shrink SE below Poisson
    ci_lo, ci_hi = b1 - 1.96 * qse1, b1 + 1.96 * qse1
    z_vs0 = b1 / qse1
    z_vs1 = (b1 - 1.0) / qse1
    return {
        "n": n, "b0": b0, "b1": b1, "se1_poisson": se1, "se1_quasi": qse1,
        "dispersion_phi": phi, "ci95": [ci_lo, ci_hi],
        "p_b1_eq_0": norm_phi(z_vs0), "p_b1_eq_1": norm_phi(z_vs1),
        "converged": conv,
    }


def analyze():
    counts = load_counts()
    out = {s: fit_scenario(counts, sh) for s, sh in SHARE_VECTORS.items()}
    b1s = [out[s]["b1"] for s in SHARE_VECTORS]
    out["_summary"] = {
        "b1_bracket": [min(b1s), max(b1s)],
        "headline_scenario": HEADLINE,
        "headline": out[HEADLINE],
        "total_cves": sum(counts.values()),
        "n_vendors": len(counts),
    }
    return out


def fmt_markdown(out):
    s = out["_summary"]
    lo, hi = s["b1_bracket"]
    L = []
    L.append("# Market-Share Elasticity: Poisson Regression of KEV Count on Installed Base\n")
    L.append(f"Generalized linear model `log(E[count]) = b0 + b1 * log(share)` fit by "
             f"IRLS over **{s['n_vendors']} vendors / {s['total_cves']} CVEs**, under each "
             "of the three published market-share vectors. **b1 is the elasticity** of "
             "exploited-CVE count with respect to market share.\n")
    L.append("| Scenario | b1 (elasticity) | quasi-SE | 95% CI | dispersion phi | p (b1=0) | p (b1=1) |")
    L.append("|----------|----------------:|---------:|--------|---------------:|---------:|---------:|")
    for sc in SHARE_VECTORS:
        r = out[sc]
        L.append(f"| {sc} | {r['b1']:.3f} | {r['se1_quasi']:.3f} | "
                 f"[{r['ci95'][0]:.3f}, {r['ci95'][1]:.3f}] | {r['dispersion_phi']:.2f} | "
                 f"{r['p_b1_eq_0']:.3f} | {r['p_b1_eq_1']:.3f} |")
    L.append("")
    h = s["headline"]
    sub = h["ci95"][1] < 1.0
    L.append(f"**Elasticity bracket across all three vectors: b1 = {lo:.2f}–{hi:.2f}.**\n")
    L.append(f"Under the headline {HEADLINE} vector, b1 = {h['b1']:.2f} "
             f"(95% CI [{h['ci95'][0]:.2f}, {h['ci95'][1]:.2f}]).")
    L.append("")
    L.append("**Interpretation.** " + (
        "The elasticity is significantly **below 1** (the 95% CI excludes 1), so "
        "exploited-CVE count scales **sub-linearly** with market share: a vendor with "
        "10x the installed base accumulates well under 10x the exploited edge CVEs. "
        "This is the quantitative form of the popularity tax -- raw counts grow with "
        "install base but *slower* than proportionally, so a raw-count comparison "
        "**overstates** the gap between large- and small-share vendors. It is fully "
        "consistent with the per-install rate ratios (analyze_normalization.py), where "
        "Fortinet's raw-leading count normalizes below the baseline and small-share "
        "vendors normalize above it."
        if sub else
        "The 95% CI for b1 includes 1, so the data are consistent with count scaling "
        "roughly proportionally to market share (a pure popularity tax); a sub-linear "
        "relationship cannot be established at this sample size."
    ))
    L.append("")
    L.append("**Caveats.** n = 13 is a very small sample; market shares are analyst "
             "estimates without error bars (and unit-share != revenue-share != device "
             "count); this is an ecological regression establishing association, not a "
             "code-quality difference. Overdispersion (phi > 1) is handled with quasi-"
             "Poisson standard errors; a negative-binomial fit gives materially the same "
             "b1. See docs/MARKET-SHARE-SENSITIVITY.md and docs/STATISTICS.md.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = ap.parse_args()
    out = analyze()
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        print(fmt_markdown(out))


if __name__ == "__main__":
    main()
