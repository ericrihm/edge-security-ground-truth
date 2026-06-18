# Statistical Analysis of CISA KEV Edge-Appliance Exploitation

This document presents the statistical methods and results used to evaluate whether
differences in CISA Known Exploited Vulnerabilities (KEV) counts across 13
edge-appliance vendors are statistically meaningful. It is intended to read like
the Results section of a security measurement paper.

All computations are reproduced by `scripts/analyze_statistics.py` (stdlib-only
Python; no numpy or scipy). Catalog version: 2026.06.18.

---

## 1. Descriptive Statistics

We analyze N = 115 CVEs distributed across k = 13 vendors. The per-vendor counts are:

| Vendor | KEV Count | Share |
|--------|----------:|------:|
| Fortinet | 18 | 15.7% |
| Cisco | 13 | 11.3% |
| Citrix | 13 | 11.3% |
| Ivanti | 13 | 11.3% |
| Palo Alto Networks | 12 | 10.4% |
| SonicWall | 12 | 10.4% |
| Juniper | 8 | 7.0% |
| F5 | 6 | 5.2% |
| Sophos | 6 | 5.2% |
| Zyxel | 6 | 5.2% |
| WatchGuard | 4 | 3.5% |
| Check Point | 2 | 1.7% |
| Array Networks | 2 | 1.7% |

| Statistic | Value |
|-----------|------:|
| Mean | 8.85 |
| Median | 8 |
| Standard Deviation | 4.98 |
| Variance | 24.81 |
| Q1 | 6.0 |
| Q3 | 13.0 |
| Interquartile Range (IQR) | 7.0 |
| Range | 16 (2 to 18) |
| Coefficient of Variation (CV) | 0.563 |

**Interpretation.** The distribution is mildly right-skewed: the median (8)
is below the mean (8.85), with Fortinet's count of 18 pulling the mean up while
the low-count vendors (Check Point and Array Networks at 2) anchor the bottom.
A CV of 0.563 indicates moderate dispersion -- counts vary, but not
by an order of magnitude. The IQR of 7.0 tells us that the middle 50% of vendors
have between 6 and 13 KEV entries, a factor of roughly 2x rather than 10x.

---

## 2. Concentration Metrics

We measure whether KEV exploitation is concentrated in a few vendors or spread
across many, using three standard indices from industrial organization economics.

### Herfindahl-Hirschman Index (HHI)

The HHI is the sum of squared market shares. For k equal vendors, HHI = 1/k.

| Metric | Value |
|--------|------:|
| HHI (observed) | 0.09943 |
| HHI (equal baseline, 1/13) | 0.07692 |
| HHI (normalized) | 0.02439 |
| Gini coefficient | 0.3023 |
| CR3 (top-3 concentration ratio) | 38.26% |

**Interpretation.** The normalized HHI of 0.024 is well below the DOJ/FTC
threshold of 0.15 for "moderately concentrated" markets. By the HHI lens,
KEV exploitation is **unconcentrated** -- it is spread across vendors roughly
in proportion to what we would expect from random variation alone.

The Gini coefficient of 0.302 indicates mild inequality: present but modest.
For context, a Gini of 0.30 is comparable to the income distribution of
Scandinavian countries -- relatively egalitarian. A Gini above 0.40 would
indicate substantial concentration.

The CR3 of 38.26% means the top three vendors (Fortinet, Cisco, Citrix) account
for less than half of all edge KEVs. This is a diffuse distribution.

**Key finding:** Exploitation is NOT concentrated in a few "insecure" vendors.
The distribution is nearly uniform, which is consistent with the hypothesis that
KEV inclusion is driven by factors common to all edge appliances (internet
exposure, attacker interest in the device class) rather than vendor-specific
code quality.

---

## 3. Poisson Trend Analysis

We model yearly KEV additions as a Poisson process and test whether the rate
parameter is increasing over time. The Poisson is the natural model for count
data (non-negative integer events in a time interval).

**Method.** Ordinary least squares regression of count_t on year_t (recoded to
t = 0, 1, ..., T), with the standard error first computed under the Poisson
assumption that Var(Y) = E[Y], yielding SE(slope) = sqrt(mean_lambda / SS_tt).
Because count data are typically over-dispersed, we then apply a quasi-Poisson
correction: we estimate the dispersion parameter phi as the Pearson chi-squared
of the fitted line divided by the residual degrees of freedom (n - 2), and
multiply the Poisson SE by sqrt(phi). The corrected z and p are reported
alongside the naive figures. (Underdispersion, phi < 1, is treated
conservatively by flooring phi at 1.0.)

| Year | Published CVEs |
|------|---------------:|
| 2014 | 1 |
| 2015 | 1 |
| 2016 | 2 |
| 2017 | 1 |
| 2018 | 1 |
| 2019 | 11 |
| 2020 | 19 |
| 2021 | 9 |
| 2022 | 10 |
| 2023 | 18 |
| 2024 | 17 |
| 2025 | 20 |
| 2026 | 5 |

- Model: lambda(t) = 0.736 + 1.352 * t
- Slope: **+1.352 CVEs/year** (Poisson SE = 0.22)
- Naive Poisson: z = 6.131, p < 0.001
- Dispersion phi = 3.13; quasi-Poisson SE = SE * sqrt(phi) = 0.39
- Overdispersion-adjusted: z = 3.466, p = 0.0005
- **Significant increase (even after overdispersion adjustment)**

**Interpretation.** The increasing trend is statistically significant, but we
urge caution in interpreting this as "edge appliances are getting less secure."
Several confounders explain the upward slope equally well:

1. **Catalog maturation.** CISA KEV launched November 2021. Pre-2021 entries are
   backfilled selectively. The apparent acceleration from 2019-2020 onward likely
   reflects CISA's expanding operational coverage, not a sudden spike in exploitation.

2. **Researcher attention.** Post-2021, edge appliances became a fashionable
   research target (ProxyLogon, Citrix Bleed, Ivanti Connect Secure campaigns).
   More researchers looking means more vulnerabilities found.

3. **2026 is partial.** Only 5 CVEs for 2026 (as of June) will increase as the year
   progresses. The slope would be shallower if estimated on complete years only.

The pure Poisson model is misspecified: counts exhibit overdispersion (the
2020 spike of 19 and 2014-2018 sparse counts violate the equal mean-variance
assumption). The estimated dispersion of phi = 3.13 confirms this -- the
year-to-year variance is roughly 3x the mean. We therefore report the
quasi-Poisson-adjusted standard error (Poisson SE inflated by sqrt(phi)),
which widens the SE from 0.22 to 0.39 and lowers the z from 6.131 to 3.466.
The trend remains significant (p = 0.0005) even under this more conservative
variance assumption. A full negative-binomial fit would be marginally more
appropriate, but the quasi-Poisson correction captures the same overdispersion
adjustment within the stdlib-only constraint.

---

## 4. Vendor Comparison Tests

### 4a. Chi-Squared Goodness-of-Fit (Uniformity)

We test whether the vendor distribution departs significantly from uniform.

- H0: All 13 vendors have equal expected KEV counts (8.85 each)
- chi-squared(12) = 33.652
- p = 0.00082

**Result: Reject H0 at alpha = 0.05.** The vendor counts are significantly
non-uniform. Fortinet's 18 and the low counts of Check Point and Array Networks
(2 each) are the primary contributors to the chi-squared statistic.

**Critical caveat:** Rejecting uniformity does NOT demonstrate that vendors
differ in code quality. The chi-squared test answers "are these counts plausibly
drawn from the same Poisson rate?" The answer is "probably not" -- but the
reason could be install-base differences, researcher focus, or disclosure
transparency, not security engineering quality.

### 4b. Pairwise Vendor Comparisons

For each of the C(13,2) = 78 vendor pairs, we use a **conditional exact binomial
test**. The earlier method built a 2x2 table `[[ci, N-ci], [cj, N-cj]]`, whose
effective sample size is 2N because every one of the N CVEs in the corpus appears
in the "rest" cell of *both* vendor rows -- this double-counts the entire dataset
and inflates the chi-squared statistic. The conditional test instead fixes the
pair total n = ci + cj and asks whether the split k = ci out of n trials departs
from p = 0.5 (the rate-equality null), using the exact two-sided binomial. Pairs
whose minimum expected cell (n * 0.5) falls below 5 are flagged as having low
power, where the large-sample approximation would be unreliable.

| Correction | Significant Pairs |
|------------|------------------:|
| Raw (p < 0.05) | 19 of 78 |
| Bonferroni (p < 0.000641) | **2 of 78** |

The pairs surviving Bonferroni correction:

| Vendor A | Vendor B | Counts | n | p |
|----------|----------|--------|:-:|------:|
| Fortinet | Check Point | 18 vs 2 | 20 | 0.0004 |
| Fortinet | Array Networks | 18 vs 2 | 20 | 0.0004 |

**Interpretation.** After correcting for 78 simultaneous tests, only the most
extreme pairs (Fortinet vs Check Point and Fortinet vs Array Networks, both a
9:1 ratio) are distinguishable. The remaining 76 pairs -- including Fortinet vs
Cisco (18 vs 13), Cisco vs Zyxel (13 vs 6), and all other comparisons that might
appear meaningful in a bar chart -- are NOT statistically significant after
multiple-testing correction.

This is a direct consequence of the small sample sizes involved. With total
N = 115 spread across 13 vendors, the statistical power to detect moderate
differences is very low; 9 of the 78 pairwise comparisons also have a minimum
expected cell below 5, where even the exact test has little power to separate
the vendors.

---

## 5. CVSS Severity Distribution

For each vendor, we tabulate the CVSS v3.1 severity breakdown of their KEV entries.

| Vendor | Critical | High | Medium | Low | No Score | Mean CVSS | Crit+High % |
|--------|:--------:|:----:|:------:|:---:|:--------:|----------:|:-----------:|
| Array Networks | 1 | 1 | 0 | 0 | 0 | 8.50 | 100% |
| Check Point | 1 | 1 | 0 | 0 | 0 | 8.95 | 100% |
| Cisco | 1 | 6 | 6 | 0 | 0 | 7.11 | 54% |
| Citrix | 6 | 1 | 4 | 0 | 2 | 8.13 | 64% |
| F5 | 5 | 1 | 0 | 0 | 0 | 9.63 | 100% |
| Fortinet | 11 | 1 | 5 | 1 | 0 | 7.96 | 67% |
| Ivanti | 5 | 8 | 0 | 0 | 0 | 8.51 | 100% |
| Juniper | 2 | 1 | 5 | 0 | 0 | 6.75 | 38% |
| Palo Alto Networks | 4 | 6 | 0 | 0 | 2 | 8.76 | 100% |
| SonicWall | 6 | 4 | 2 | 0 | 0 | 8.48 | 83% |
| Sophos | 6 | 0 | 0 | 0 | 0 | 9.83 | 100% |
| WatchGuard | 3 | 1 | 0 | 0 | 0 | 9.43 | 100% |
| Zyxel | 5 | 1 | 0 | 0 | 0 | 9.42 | 100% |

**Interpretation.** KEV-listed CVEs are overwhelmingly critical or high severity
across all vendors, which is expected: CISA catalogs actively exploited
vulnerabilities, and attackers preferentially exploit high-impact bugs. The
overall mean CVSS is 8.57.

Vendors with lower mean CVSS (Juniper 6.75, Cisco 7.11) are not necessarily
"safer" -- they may have more medium-severity KEV entries because their specific
exploitation patterns (e.g., Juniper J-Web PHP chaining, Cisco ASA XSS) produce
confirmed exploitation at lower CVSS thresholds.

Palo Alto Networks has 2 CVEs with no CVSS score (NVD has not assigned scores
to recent PAN-SA advisories using Palo Alto's own scoring system). This is a
data completeness artifact, not a severity signal.

---

## 6. EPSS Comparison

The Exploit Prediction Scoring System (EPSS) estimates the probability that a
CVE will be exploited in the next 30 days. We compare mean EPSS across vendors.

| Vendor | N | Mean EPSS | Median | Min | Max |
|--------|--:|----------:|-------:|----:|----:|
| Array Networks | 2 | 0.3535 | 0.3535 | 0.0305 | 0.6765 |
| Check Point | 2 | 0.7057 | 0.7057 | 0.4115 | 0.9998 |
| Cisco | 13 | 0.5475 | 0.6327 | 0.1403 | 0.9999 |
| Citrix | 13 | 0.5598 | 0.5763 | 0.0319 | 1.0000 |
| F5 | 6 | 0.6071 | 0.7879 | 0.0225 | 1.0000 |
| Fortinet | 18 | 0.5486 | 0.5843 | 0.0087 | 1.0000 |
| Ivanti | 13 | 0.7775 | 0.9862 | 0.1415 | 1.0000 |
| Juniper | 8 | 0.5387 | 0.7305 | 0.0110 | 0.9421 |
| Palo Alto Networks | 12 | 0.5128 | 0.3554 | 0.0186 | 1.0000 |
| SonicWall | 12 | 0.4290 | 0.2848 | 0.0191 | 0.9991 |
| Sophos | 6 | 0.5898 | 0.6988 | 0.0473 | 0.9980 |
| WatchGuard | 4 | 0.4860 | 0.4789 | 0.1225 | 0.8637 |
| Zyxel | 6 | 0.5820 | 0.5943 | 0.0296 | 0.9994 |

Overall mean: 0.5628 | Overall median: 0.6140

**Interpretation.** EPSS scores are high across the board (overall mean 0.56),
which is tautological: KEV-listed CVEs are known to be actively exploited,
and EPSS models partially incorporate exploitation evidence. The variation
between vendors (Ivanti 0.78, SonicWall 0.43) reflects differences in the
*fame and tooling* of specific exploit chains (Ivanti's CVEs were heavily
weaponized in mass-exploitation campaigns) rather than inherent product risk.

EPSS is not an independent signal when conditioned on KEV membership.

---

## 7. Poisson Confidence Intervals

Under a Poisson model, the 95% confidence interval for the true rate (lambda)
given an observed count k uses the Garwood (1936) exact method based on the
chi-squared distribution.

| Vendor | Observed | 95% CI Lower | 95% CI Upper | Width |
|--------|:--------:|:------------:|:------------:|------:|
| Fortinet | 18 | 10.66 | 28.45 | 17.79 |
| Cisco | 13 | 6.91 | 22.23 | 15.32 |
| Citrix | 13 | 6.91 | 22.23 | 15.32 |
| Ivanti | 13 | 6.91 | 22.23 | 15.32 |
| Palo Alto Networks | 12 | 6.19 | 20.96 | 14.77 |
| SonicWall | 12 | 6.19 | 20.96 | 14.77 |
| Juniper | 8 | 3.44 | 15.77 | 12.32 |
| F5 | 6 | 2.19 | 13.06 | 10.87 |
| Sophos | 6 | 2.19 | 13.06 | 10.87 |
| Zyxel | 6 | 2.19 | 13.06 | 10.87 |
| WatchGuard | 4 | 1.08 | 10.24 | 9.17 |
| Check Point | 2 | 0.22 | 7.22 | 7.00 |
| Array Networks | 2 | 0.22 | 7.22 | 7.00 |

**Interpretation.** The confidence intervals are wide relative to the observed
values. Fortinet's CI of [10.66, 28.45] fully contains the observed counts
of most other vendors. Cisco's CI of [6.91, 22.23] overlaps with every vendor
except Check Point and Array Networks.

Of 78 vendor pairs, **75 (96%) have overlapping confidence intervals**. Only
3 pairs (Fortinet vs Check Point, Fortinet vs Array Networks, and Fortinet vs
WatchGuard) have non-overlapping CIs and are statistically separable.

This means: if we observed a new independent time window of similar length,
the vendor ranking could easily shuffle. A vendor at 6 could plausibly appear
at 13; a vendor at 13 could appear at 7. The observed ordering is one
realization of a highly uncertain process.

---

## 8. Key Question: Can We Distinguish Vendors by KEV Count Alone?

**No, with very few exceptions.**

The evidence converges from multiple angles:

1. **Concentration is low.** HHI normalized = 0.024, Gini = 0.302. The distribution
   is close to uniform.

2. **Only two pairs survive correction.** After Bonferroni adjustment of 78
   pairwise tests, only Fortinet vs Check Point and Fortinet vs Array Networks
   (both 18 vs 2) are significant.

3. **96% of CI pairs overlap.** Poisson confidence intervals show that nearly
   all vendor counts are statistically indistinguishable from each other.

4. **CVSS and EPSS do not differentiate.** Severity distributions are uniformly
   high (this is a property of KEV, not of vendors), and EPSS is confounded
   by KEV membership itself.

The honest statistical answer is: **Fortinet has significantly more KEV entries
than the two lowest-count vendors (Check Point and Array Networks). Every other
vendor comparison is noise at these sample sizes.** Any ranking of the
intermediate vendors (ranging 4-13) is not supported by the data.

---

## 9. The Install-Base Confound

Even the Fortinet-Check Point difference cannot be interpreted as a security
quality difference without addressing the install-base confound. This section
discusses why.

### Simpson's Paradox

Consider two hypothetical vendors:

| Vendor | KEV Count | Install Base | Rate (per 10K installs) |
|--------|----------:|-------------:|------------------------:|
| Vendor A | 18 | 500,000 | 0.36 |
| Vendor B | 2 | 10,000 | 2.00 |

Vendor A has 9x more KEVs but a 5.6x *lower* rate per device. Without install-base
normalization, raw counts reward obscurity and penalize market leaders.

This is a textbook instance of **Simpson's paradox**: the vendor that appears
worse in aggregate may be better after stratifying by exposure. Public install-base
data does not exist at the granularity needed to perform this normalization,
which is why we do not attempt it.

### Ecological Fallacy

Aggregate vendor-level counts say nothing about specific products or deployments.
Fortinet's 18 KEVs span FortiOS and FortiProxy across versions from 5.x to 7.x
over a 7-year window. A customer running current FortiOS 7.6 with rapid patching
faces a fundamentally different risk profile than the aggregate suggests.

Drawing per-deployment conclusions from vendor-level aggregates is the
**ecological fallacy**: a well-documented statistical error where group-level
associations are incorrectly attributed to individuals.

### Researcher Attention Bias

Vendors that are:
- more widely deployed (larger attack surface for researchers to find bugs)
- more transparent in disclosure (publish advisories that researchers can verify)
- more prominent in breach news (attract more follow-on research)

will accumulate more KEV entries independent of code quality. This is a form of
**detection bias** or **surveillance bias** analogous to the well-known problem in
epidemiology where diseases screened more frequently appear more prevalent.

---

## 10. Limitations

1. **Small sample sizes.** N = 115 total, with per-vendor counts of 2-18,
   severely limits statistical power. Many real differences (if they exist)
   cannot be detected at conventional significance levels. This is a
   fundamental constraint of the KEV catalog's size for this vendor set.

2. **Selection bias in KEV.** The catalog includes only vulnerabilities CISA
   has confirmed as actively exploited AND deemed relevant to federal agencies.
   This is not a random sample of all exploited vulnerabilities. Vendors whose
   products are more common in federal networks may be overrepresented.

3. **Temporal non-stationarity.** The KEV catalog launched November 3, 2021.
   Pre-2021 entries are retrospective additions. The Poisson model assumes a
   stationary (or linearly changing) rate, which is violated by the catalog's
   bootstrapping period and by the bursty nature of coordinated campaigns
   (e.g., the 2023-2024 Ivanti and Fortinet waves).

4. **Non-independence.** CVE entries are not independent events. A single
   vulnerability campaign may produce multiple CVEs (e.g., the five Juniper
   J-Web CVEs from August 2023 are a single exploitation chain assigned five
   identifiers). This violates the Poisson independence assumption and inflates
   counts for vendors targeted by chain-based attacks.

5. **Missing install-base denominators.** Without normalization by the number
   of deployed devices per vendor, all between-vendor comparisons are
   confounded. No public dataset provides this at sufficient granularity.

6. **Scope boundary effects.** Our scope rules (e.g., Cisco ASA/FTD only,
   excluding FMC; Fortinet FortiOS/FortiProxy only, excluding FortiManager)
   affect counts. Different scope choices would yield different numbers.
   The scope is documented in `kev_edge_counts.json` metadata.

7. **P-value approximations.** The chi-squared uniformity p-value uses the
   Wilson-Hilferty normal approximation, and Poisson CIs use the Garwood method
   with approximate chi-squared quantiles; these are accurate to ~0.01 for our
   parameter ranges but are not exact. The pairwise vendor comparisons, by
   contrast, use an exact two-sided binomial test (no approximation), and the
   year-trend now reports an overdispersion-adjusted (quasi-Poisson) standard
   error alongside the naive Poisson SE.

---

## Reproducibility

All results are produced by:

```
python3 scripts/analyze_statistics.py              # text output
python3 scripts/analyze_statistics.py -f markdown  # markdown tables
python3 scripts/analyze_statistics.py -f json      # machine-readable
```

The script requires only Python 3.8+ standard library (`math`, `statistics`,
`collections`, `json`, `argparse`). No external dependencies.

Input data: `scripts/kev_edge_counts.json` (vendor-to-CVE-list mapping) and
`scripts/kev_edge_enriched.json` (EPSS/CVSS enrichment).
