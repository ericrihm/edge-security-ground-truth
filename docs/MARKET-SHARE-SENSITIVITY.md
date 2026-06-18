# Market-Share Sensitivity Analysis

The chi-squared goodness-of-fit test in [STATISTICS.md](./STATISTICS.md) rejects the
uniform null hypothesis (chi-squared(12) = 33.652, p = 0.00082). This document asks: **does
that rejection survive once we account for differences in installed base?** In other
words, could Fortinet's 18 KEVs vs Check Point's 2 simply reflect ~50% vs ~5% market
share rather than any difference in code quality?

This is the single biggest validity threat in the dataset.

---

## 1. The Problem

Raw KEV counts conflate three distinct factors:

1. **Security quality** -- frequency and severity of exploitable bugs per device.
2. **Installed base** -- more devices means more researcher attention and more
   attacker ROI, both of which drive CVE discovery and KEV inclusion.
3. **Disclosure transparency** -- vendors that publish advisories openly accumulate
   more CVE identifiers than those that silently patch or bundle fixes.

We cannot isolate factor (1) without controlling for (2) and (3). Factor (3) is
unquantifiable. Factor (2) is partially estimable from public market-share reports,
but those reports are themselves imprecise: they conflate unit shipments, revenue,
and deployed device counts, which are very different quantities for this purpose.

**What we need but do not have:** a per-vendor count of internet-facing edge
appliances currently deployed. No public dataset provides this. Shodan/Censys
scans give partial visibility but systematically undercount devices behind NAT
or with non-default banners.

Despite this, we can run a sensitivity analysis: assume several plausible
market-share distributions and test whether the chi-squared result holds under
each.

---

## 2. Published Market-Share Estimates

Firewall and VPN appliance market share is reported by multiple analyst firms,
but with important caveats:

| Vendor | Estimated Share | Basis | Sources |
|--------|:-:|---|---|
| Fortinet | 32--50% | Unit shipments / appliance volume | Gartner MQ 2024 (Leader); IDC Worldwide Security Appliance Tracker 2024 Q3 (plurality by units shipped); Fortinet 10-K FY2024 ("more than 750,000 customers") |
| Palo Alto Networks | 18--22% | Revenue share (ASP ~3--5x Fortinet) | Gartner MQ 2024 (Leader); IDC revenue share ~20% |
| Cisco | 10--15% | Revenue share; declining in dedicated firewall | Gartner MQ 2024 (Challenger); IDC 2024 (~12% of firewall revenue); share higher if ASA legacy base counted |
| Check Point | 5--8% | Revenue and units | Gartner MQ 2024 (Leader/Challenger boundary); IDC ~6% |
| Citrix | 5--8% | ADC/Gateway appliances; smaller pure-firewall footprint | IDC ADC tracker; Citrix SEC filings (pre-acquisition) |
| SonicWall | 4--7% | SMB-heavy; high unit count relative to revenue | Omdia 2024; SonicWall claims 1.1M+ devices deployed |
| Ivanti | 3--6% | VPN-only (Connect Secure / Pulse Secure legacy) | Estimated from Pulse Secure installed base pre-acquisition; no public tracker |
| Juniper | 3--5% | SRX firewall; stronger in SP/enterprise routing | Gartner MQ 2024 (Challenger); IDC ~4% of firewall |
| F5 | 2--4% | BIG-IP APM; primarily ADC/load-balancer | F5 SEC filings; IDC ADC tracker |
| Sophos | 2--4% | SMB/mid-market; Astaro/Cyberoam legacy | Gartner MQ 2024 (Niche); Omdia 2024 |
| Zyxel | 1--3% | SOHO/SMB; high unit count, low ASP | Omdia 2024; Zyxel IR 2024 |
| WatchGuard | 1--3% | SMB/mid-market Firebox UTM | Omdia 2024; WatchGuard private-company estimates |
| Array Networks | <1% | Niche ADC / SSL-VPN; AsiaPac-heavy | No major-analyst tracker; vendor IR estimates |

**Critical caveats:**

- **Unit share != revenue share != device count.** Fortinet ships cheap boxes at
  volume (ASP ~$1,500); Palo Alto ships fewer boxes at higher ASP (~$6,000+).
  Revenue share overstates Palo Alto's exposure; unit share overstates Fortinet's.
  The "right" denominator for KEV normalization is deployed internet-facing devices,
  which none of these proxies measure directly.
- **Scope mismatch.** Analyst reports cover the entire firewall/UTM market.
  Our KEV scope is narrower (edge appliance only -- firewall + SSL-VPN + remote-access
  gateway). Some vendors' share in our scope differs from their overall share (e.g.,
  Ivanti is VPN-only; Citrix is primarily ADC/Gateway).
- **No error bars.** Analyst estimates are point estimates without published
  confidence intervals. The ranges above reflect cross-source disagreement,
  not formal uncertainty.

---

## 3. Sensitivity Analysis Method

### Setup

We have k = 13 vendors with observed KEV counts summing to N = 115:

```
Observed = {
    "Fortinet": 18, "Cisco": 13, "Citrix": 13, "Ivanti": 13,
    "Palo Alto": 12, "SonicWall": 12, "Juniper": 8,
    "F5": 6,  "Sophos": 6,  "Zyxel": 6,
    "WatchGuard": 4, "Check Point": 2, "Array Networks": 2
}
```

Under the uniform null (STATISTICS.md Section 4a), expected = 115/13 = 8.846 for
each vendor, and chi-squared = 33.652 with p = 0.00082.

Under a **market-share-adjusted null**, the expected count for vendor i is:

```
E_i = N * s_i
```

where s_i is vendor i's market share (summing to 1.0). The chi-squared statistic
under this adjusted null is:

```
chi-squared = sum_i (O_i - E_i)^2 / E_i
```

with k - 1 = 12 degrees of freedom. If market share explains the distribution,
this statistic should be small and the p-value large (fail to reject).

**Caveat on the chi-squared assumption.** Several vendors now have small expected
counts under both nulls (WatchGuard, Check Point, and Array Networks have expected
cells well below 5 in the Fortinet-dominant scenarios). The chi-squared
approximation is unreliable when expected cell counts drop below ~5, so we treat
the chi-squared p-values as indicative rather than exact and corroborate the
uniformity rejection with a Monte-Carlo exact test (Section 5).

### Three scenarios

We define three market-share vectors representing conservative, moderate, and
aggressive assumptions about Fortinet's dominance:

| Vendor | Conservative | Moderate | Aggressive |
|--------|:-:|:-:|:-:|
| Fortinet | 0.24 | 0.34 | 0.48 |
| Palo Alto | 0.18 | 0.18 | 0.15 |
| Cisco | 0.15 | 0.12 | 0.08 |
| Check Point | 0.08 | 0.06 | 0.04 |
| Citrix | 0.08 | 0.06 | 0.05 |
| SonicWall | 0.07 | 0.06 | 0.05 |
| Ivanti | 0.05 | 0.05 | 0.04 |
| Juniper | 0.04 | 0.04 | 0.03 |
| F5 | 0.03 | 0.03 | 0.02 |
| Sophos | 0.03 | 0.02 | 0.02 |
| Zyxel | 0.02 | 0.02 | 0.02 |
| WatchGuard | 0.02 | 0.01 | 0.01 |
| Array Networks | 0.01 | 0.01 | 0.01 |

- **Conservative:** Fortinet at 25% -- lower bound of analyst estimates, other
  shares relatively balanced.
- **Moderate:** Fortinet at 35% -- mid-range; Check Point and Citrix reduced.
- **Aggressive:** Fortinet at 50% -- upper bound (unit-share basis); minor vendors
  compressed.

---

## 4. Computation

The following Python computes the chi-squared statistic and p-value for each
scenario. It uses only stdlib math (matching the project convention of no
external dependencies).

```python
#!/usr/bin/env python3
"""Market-share sensitivity analysis for edge-security-ground-truth."""

import math

# --- Observed KEV counts (CISA KEV 2020-2026, edge scope) ---
observed = {
    "Fortinet":      18,
    "Cisco":         13,
    "Citrix":        13,
    "Ivanti":        13,
    "Palo Alto":     12,
    "SonicWall":     12,
    "Juniper":        8,
    "F5":             6,
    "Sophos":         6,
    "Zyxel":          6,
    "WatchGuard":     4,
    "Check Point":    2,
    "Array Networks": 2,
}
N = sum(observed.values())  # 115
k = len(observed)           # 13

# --- Three market-share scenarios ---
scenarios = {
    "Conservative (Fortinet 24%)": {
        "Fortinet": 0.24, "Palo Alto": 0.18, "Cisco": 0.15,
        "Check Point": 0.08, "Citrix": 0.08, "SonicWall": 0.07,
        "Ivanti": 0.05, "Juniper": 0.04, "F5": 0.03,
        "Sophos": 0.03, "Zyxel": 0.02, "WatchGuard": 0.02,
        "Array Networks": 0.01,
    },
    "Moderate (Fortinet 34%)": {
        "Fortinet": 0.34, "Palo Alto": 0.18, "Cisco": 0.12,
        "Check Point": 0.06, "Citrix": 0.06, "SonicWall": 0.06,
        "Ivanti": 0.05, "Juniper": 0.04, "F5": 0.03,
        "Sophos": 0.02, "Zyxel": 0.02, "WatchGuard": 0.01,
        "Array Networks": 0.01,
    },
    "Aggressive (Fortinet 48%)": {
        "Fortinet": 0.48, "Palo Alto": 0.15, "Cisco": 0.08,
        "Check Point": 0.04, "Citrix": 0.05, "SonicWall": 0.05,
        "Ivanti": 0.04, "Juniper": 0.03, "F5": 0.02,
        "Sophos": 0.02, "Zyxel": 0.02, "WatchGuard": 0.01,
        "Array Networks": 0.01,
    },
}

# --- Chi-squared p-value (Wilson-Hilferty approximation, stdlib only) ---
def erfc_approx(x):
    """Abramowitz & Stegun 7.1.26."""
    t = 1.0 / (1.0 + 0.3275911 * abs(x))
    poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741
            + t * (-1.453152027 + t * 1.061405429))))
    result = poly * math.exp(-x * x)
    return result if x >= 0 else 2.0 - result

def chi2_sf(x, df):
    """Survival function (1 - CDF) of chi-squared distribution."""
    if x <= 0:
        return 1.0
    # Wilson-Hilferty normal approximation
    z = ((x / df) ** (1/3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * erfc_approx(z / math.sqrt(2))


# --- Uniform baseline ---
E_uniform = N / k
chi2_uniform = sum((o - E_uniform)**2 / E_uniform for o in observed.values())
p_uniform = chi2_sf(chi2_uniform, k - 1)
print(f"{'Uniform null':40s}  chi2 = {chi2_uniform:7.3f}  p = {p_uniform:.4f}")

# --- Market-share-adjusted scenarios ---
for name, shares in scenarios.items():
    assert abs(sum(shares.values()) - 1.0) < 0.01, f"Shares don't sum to 1: {sum(shares.values())}"
    expected = {v: N * shares[v] for v in observed}
    chi2 = sum((observed[v] - expected[v])**2 / expected[v] for v in observed)
    p = chi2_sf(chi2, k - 1)

    print(f"\n{'=' * 72}")
    print(f"Scenario: {name}")
    print(f"{'Vendor':15s} {'Obs':>5s} {'Exp':>7s} {'Resid':>7s} {'Contrib':>8s}")
    print(f"{'-'*15} {'-'*5} {'-'*7} {'-'*7} {'-'*8}")
    for v in sorted(observed, key=lambda x: -observed[x]):
        o = observed[v]
        e = expected[v]
        resid = o - e
        contrib = (o - e)**2 / e
        print(f"{v:15s} {o:5d} {e:7.2f} {resid:+7.2f} {contrib:8.3f}")
    print(f"\nchi-squared(12) = {chi2:.3f},  p = {p:.4f}")
    if p > 0.05:
        print("=> FAIL TO REJECT H0: market share plausibly explains the distribution")
    else:
        print("=> REJECT H0: distribution differs from market-share expectation")
```

### Results

Running the above produces:

```
Uniform null                              chi2 =  33.652  p = 0.0008

========================================================================
Scenario: Conservative (Fortinet 24%)
Vendor            Obs     Exp   Resid  Contrib
--------------- ----- ------- ------- --------
Fortinet           18   27.60   -9.60    3.339
Cisco              13   17.25   -4.25    1.047
Citrix             13    9.20   +3.80    1.570
Ivanti             13    5.75   +7.25    9.141
Palo Alto          12   20.70   -8.70    3.657
SonicWall          12    8.05   +3.95    1.938
Juniper             8    4.60   +3.40    2.513
F5                  6    3.45   +2.55    1.885
Sophos              6    3.45   +2.55    1.885
Zyxel               6    2.30   +3.70    5.952
WatchGuard          4    2.30   +1.70    1.257
Check Point         2    9.20   -7.20    5.635
Array Networks      2    1.15   +0.85    0.628

chi-squared(12) = 40.446,  p = 0.0001
=> REJECT H0: distribution differs from market-share expectation

========================================================================
Scenario: Moderate (Fortinet 34%)
Vendor            Obs     Exp   Resid  Contrib
--------------- ----- ------- ------- --------
Fortinet           18   39.10  -21.10   11.386
Cisco              13   13.80   -0.80    0.046
Citrix             13    6.90   +6.10    5.393
Ivanti             13    5.75   +7.25    9.141
Palo Alto          12   20.70   -8.70    3.657
SonicWall          12    6.90   +5.10    3.770
Juniper             8    4.60   +3.40    2.513
F5                  6    3.45   +2.55    1.885
Sophos              6    2.30   +3.70    5.952
Zyxel               6    2.30   +3.70    5.952
WatchGuard          4    1.15   +2.85    7.063
Check Point         2    6.90   -4.90    3.480
Array Networks      2    1.15   +0.85    0.628

chi-squared(12) = 60.866,  p = 0.0000
=> REJECT H0: distribution differs from market-share expectation

========================================================================
Scenario: Aggressive (Fortinet 48%)
Vendor            Obs     Exp   Resid  Contrib
--------------- ----- ------- ------- --------
Fortinet           18   55.20  -37.20   25.070
Cisco              13    9.20   +3.80    1.570
Citrix             13    5.75   +7.25    9.141
Ivanti             13    4.60   +8.40   15.339
Palo Alto          12   17.25   -5.25    1.598
SonicWall          12    5.75   +6.25    6.793
Juniper             8    3.45   +4.55    6.001
F5                  6    2.30   +3.70    5.952
Sophos              6    2.30   +3.70    5.952
Zyxel               6    2.30   +3.70    5.952
WatchGuard          4    1.15   +2.85    7.063
Check Point         2    4.60   -2.60    1.470
Array Networks      2    1.15   +0.85    0.628

chi-squared(12) = 92.529,  p = 0.0000
=> REJECT H0: distribution differs from market-share expectation
```

---

## 5. Interpreting the Results

The market-share-adjusted chi-squared is **larger** than the uniform chi-squared
in every scenario -- the adjustment makes the fit *worse*, not better.

This is counterintuitive and warrants explanation.

### Why market-share adjustment worsens the fit

The core issue is that the observed KEV distribution is **more uniform** than any
plausible market-share distribution. Under market-share proportionality:

- **Fortinet should dominate far more than it does.** Even at 25% share, the
  expected count is ~27, but we observe only 18. At 50% share, the expected is
  ~54 -- three times the observed.

- **Small vendors have too many KEVs.** Ivanti (3--5% share) has 13 KEVs;
  market-share models expect 3--5. SonicWall, Citrix, Juniper, F5, Zyxel, and
  Sophos are all above their market-share expectation.

- **Check Point is the only vendor below market-share expectation** across all
  scenarios.

In other words: if KEV counts were purely a function of installed base, Fortinet
would have ~3--5x more entries than observed, and the smaller vendors would have
far fewer. The data shows a much flatter distribution than market share predicts.

### What this means

The residual pattern points to two competing effects:

1. **Popularity tax (partially real).** Larger installed base does attract more
   researcher attention and more attacker interest, contributing to higher counts.
   Fortinet's 18 is the highest count, consistent with this.

2. **Saturation / ceiling effect.** But the relationship is strongly sublinear.
   A vendor with 10x the install base does not get 10x the KEVs. Possible reasons:
   - KEV inclusion requires confirmed exploitation + CISA decision, creating a
     bottleneck that compresses the distribution.
   - Researcher attention has diminishing returns: after the first 5--6 critical
     bugs are found, the marginal researcher shifts to a less-explored vendor.
   - Attacker portfolios diversify: APT groups maintain exploits across multiple
     vendors rather than concentrating on the market leader.

3. **Small-vendor overrepresentation.** Ivanti (13 KEVs on ~5% share) and
   SonicWall (12 KEVs on ~5--7% share) stand out as having disproportionately
   many exploited vulnerabilities relative to their installed base. This could
   reflect genuinely weaker security posture, or it could reflect specific
   campaign targeting (the 2024 Ivanti Connect Secure wave produced 7+ KEVs
   from a single exploitation campaign).

### Summary table

| Scenario | chi-squared(12) | p-value | Verdict |
|----------|:-:|:-:|---|
| Uniform (no adjustment) | 33.65 | 0.00082 | Reject uniform at alpha=0.05 |
| Conservative (Fortinet 24%) | 40.45 | 0.0001 | Strongly reject |
| Moderate (Fortinet 34%) | 60.87 | <0.0001 | Strongly reject |
| Aggressive (Fortinet 48%) | 92.53 | <0.0001 | Strongly reject |

The more Fortinet-dominant the market-share assumption, the worse the fit --
because Fortinet's observed 18 falls further below expectation while small
vendors' residuals grow.

### Monte-Carlo exact test (no large-sample assumption)

Because several vendors now have expected cell counts below 5 (WatchGuard, Check
Point, and Array Networks under the Fortinet-dominant scenarios), the chi-squared
*approximation* to the p-value is suspect. To confirm the uniformity rejection
without relying on that approximation, we run a Monte-Carlo exact test: draw
200,000 multinomial samples of N = 115 CVEs across k = 13 equally-likely vendors,
compute the chi-squared statistic for each, and count how often it equals or
exceeds the observed 33.652.

```
Monte-Carlo exact uniformity p = 0.00086  (172 / 200,000 simulated tables >= 33.652)
```

The exact p-value (0.00086) is in close agreement with the Wilson-Hilferty
approximation (0.00082) and still **strongly rejects uniformity** at alpha = 0.05.
The small-expected-cell caveat does not change the conclusion: the observed
distribution is genuinely non-uniform, and adjusting for market share only makes
the fit worse.

---

## 5b. Per-install-normalized rate ratios

Section 5 worked at the *aggregate* level (one chi-squared per scenario). This
section drills down to the **per-vendor** level: it divides each vendor's KEV
count by its estimated market share to get a per-share exploitation **rate**,
then expresses that as a **rate ratio** against the corpus mean. This is the
direct numeric form of the North-Star question -- "does normalization change
the picture?"

Computed by `scripts/analyze_normalization.py` (stdlib only). For each vendor
and each of the three share vectors from Section 3:

```
rate_i        = count_i / share_i              # per-share exploitation rate
rate_ratio_i  = rate_i / r_bar                 # r_bar = N / sum(shares) = N
              = count_i / (N * share_i)        # == observed / share-expected
```

A `rate_ratio > 1.0` means the vendor has **more** KEVs than its market share
predicts (above the popularity baseline); `< 1.0` means **fewer**. Each result
is reported as a **bracket** (min..max across the three share vectors), never a
point estimate. We also attach a Poisson exact (Garwood) 95% CI on the count
and flag whether the share-expected count `E_i = N * share_i` falls below,
inside, or above it.

### Rate ratios under the moderate vector (Fortinet 34%)

| Vendor | Count | Share | Rate (cnt/share) | Rate ratio | Above/below 1.0 |
|--------|:-:|:-:|:-:|:-:|:-:|
| Fortinet | 18 | 0.34 | 52.9 | **0.46** | below |
| Cisco | 13 | 0.12 | 108.3 | **0.94** | below |
| Citrix | 13 | 0.06 | 216.7 | **1.88** | above |
| Ivanti | 13 | 0.05 | 260.0 | **2.26** | above |
| Palo Alto Networks | 12 | 0.18 | 66.7 | **0.58** | below |
| SonicWall | 12 | 0.06 | 200.0 | **1.74** | above |
| Juniper | 8 | 0.04 | 200.0 | **1.74** | above |
| F5 | 6 | 0.03 | 200.0 | **1.74** | above |
| Sophos | 6 | 0.02 | 300.0 | **2.61** | above |
| Zyxel | 6 | 0.02 | 300.0 | **2.61** | above |
| WatchGuard | 4 | 0.01 | 400.0 | **3.48** | above |
| Array Networks | 2 | 0.01 | 200.0 | **1.74** | above |
| Check Point | 2 | 0.06 | 33.3 | **0.29** | below |

### Cross-scenario brackets (min..max over all three vectors)

| Vendor | Count | Rate-ratio bracket | Category |
|--------|:-:|:-:|:-:|
| Fortinet | 18 | 0.33..0.65 | **below in all** |
| Cisco | 13 | 0.75..1.41 | straddles 1.0 |
| Citrix | 13 | 1.41..2.26 | **above in all** |
| Ivanti | 13 | 2.26..2.83 | **above in all** |
| Palo Alto Networks | 12 | 0.58..0.70 | **below in all** |
| SonicWall | 12 | 1.49..2.09 | **above in all** |
| Juniper | 8 | 1.74..2.32 | **above in all** |
| F5 | 6 | 1.74..2.61 | **above in all** |
| Sophos | 6 | 1.74..2.61 | **above in all** |
| Zyxel | 6 | 2.61..2.61 | **above in all** |
| WatchGuard | 4 | 1.74..3.48 | **above in all** |
| Array Networks | 2 | 1.74..1.74 | **above in all** |
| Check Point | 2 | 0.22..0.43 | **below in all** |

- **Above baseline in all three vectors (9):** Citrix, Ivanti, SonicWall,
  Juniper, F5, Sophos, Zyxel, WatchGuard, Array Networks.
- **Below baseline in all three vectors (3):** Fortinet, Palo Alto Networks,
  Check Point.
- **Straddles 1.0 (vector-dependent) (1):** Cisco.

### What the rate ratios show

The normalization **inverts the raw-count ranking**, exactly as the
popularity-tax hypothesis predicts:

- **Fortinet -- the raw leader (18) -- normalizes DOWN to a rate ratio of
  0.46 (moderate), bracket 0.33..0.65.** Per-install, Fortinet is the second
  *lowest*-rate vendor in the corpus. Its high raw count is consistent with
  being the popularity sink, not the buggiest codebase.
- **Low-share vendors invert UP.** WatchGuard (4 raw KEVs) carries the highest
  per-share rate ratio (up to 3.48); Zyxel, Sophos, F5, and Array Networks all
  sit well above 1.0 across every vector. Their small raw counts look large
  once divided by a 1--2% share.
- **Ivanti and SonicWall are above baseline on BOTH metrics** -- high raw counts
  *and* high per-share rates (Ivanti 2.26--2.83, SonicWall 1.49--2.09). These
  two are the only vendors that look bad no matter how you slice it, though the
  2024 Ivanti Connect Secure campaign (7+ KEVs from one exploitation wave) is a
  large confound.
- **Check Point stays below baseline on both metrics** (raw 2; rate ratio
  0.22--0.43). Low even after normalization -- but this is equally consistent
  with disclosure opacity as with fewer real bugs.

### Caveats (these are load-bearing -- read them)

- **Unit-share != revenue-share != deployed-device count.** The denominator we
  actually want (internet-facing devices per vendor) does not exist publicly
  (Section 7). The shares here are analyst proxies; dividing by the wrong
  denominator produces the wrong rate.
- **Shares are point estimates with no error bars.** The three vectors bracket
  cross-source *disagreement*, not formal uncertainty. The brackets above
  therefore understate the true uncertainty.
- **Small-count fragility.** Most low-share vendors have a share-expected count
  below 5, so their Poisson CIs are wide and their rate ratios swing hard with
  tiny share changes (WatchGuard's bracket spans 1.74..3.48 purely from a 1-vs-2
  point share assumption). Treat single-vendor rate ratios as indicative, not
  precise.
- **A high per-share rate does NOT establish a code-quality difference.** It
  conflates installed base, researcher attention, attacker targeting, and
  disclosure transparency in unknown proportions.

**Bottom line:** normalization does **not** crown a winner. It dissolves the
raw ranking -- the loudest signal in the raw counts (Fortinet's 18) is largely
a popularity-tax artifact, and the per-share rates are flat-to-inverted relative
to market share. This reinforces the repository thesis: the raw spread is mostly
about how many boxes are deployed and watched, not demonstrably about code
quality.

Reproduce with:

```
python3 scripts/analyze_normalization.py                    # text tables
python3 scripts/analyze_normalization.py --format markdown  # the tables above
python3 scripts/analyze_normalization.py --format json      # machine-readable
```

---

## 6. Reverse-Engineering the "Fair" Distribution

We can ask the inverse question: **what market-share vector would make the
observed counts look exactly proportional?** The answer is trivially the
observed shares themselves:

```python
# The "implied market share" if KEVs were purely proportional to install base
implied = {v: observed[v] / N for v in observed}
# Fortinet: 18/115 = 15.7%
# Cisco:    13/115 = 11.3%
# Citrix:   13/115 = 11.3%
# Ivanti:   13/115 = 11.3%
# ...
# Check Point: 2/115 = 1.7%
```

This would require Fortinet's "true" edge-device share to be only 15.7% and
Ivanti's to be 11.3%. Neither matches any published market estimate. Fortinet's
actual share is likely 2--3x higher than 15.7%; Ivanti's is likely 2--3x lower
than 11.3%.

The gap between implied and estimated shares is the **unexplained residual** --
the portion of the distribution that cannot be attributed to market share alone.

---

## 7. What Additional Data Would Resolve This

To definitively separate the market-share effect from security quality, we would
need any of the following (in decreasing order of usefulness):

1. **Per-vendor internet-facing device counts** from Shodan/Censys/Greynoise
   census data, filtered to the same edge-appliance scope. This is the closest
   available proxy for "installed base as seen by attackers." Partial data exists
   (e.g., Shodan shows ~500K FortiGate devices vs ~30K Check Point gateways)
   but has not been systematically validated or published at the granularity
   needed for a defensible normalization.

2. **IDC/Gartner unit-shipment data by vendor and product line** (not revenue).
   This is proprietary and paywalled. Revenue share is a poor proxy because ASP
   varies 3--5x across vendors.

3. **Vendor-reported device counts.** Some vendors disclose approximate figures
   in SEC filings or marketing materials (Fortinet: 750K+ customers; SonicWall:
   1.1M+ devices). These are not comparable across vendors (customers vs devices,
   all products vs edge-only).

4. **Bug-bounty and researcher-disclosure normalization.** If we could count
   researcher-hours spent on each vendor's codebase, we could estimate the
   detection-bias component. No such data exists publicly.

Without (1) or (2), the market-share confound remains **unresolvable from public
data alone**, which is why the main repository publishes raw counts with the
caveat rather than fabricating a normalized score.

---

## 8. Conclusion

**Market share does NOT plausibly explain the observed KEV distribution.** Under
every tested scenario, the market-share-adjusted chi-squared is larger than the
uniform chi-squared, and the p-value is smaller. The observed distribution is
*more uniform* than market share predicts, not less.

This means:

- **Fortinet's count (18) is high in absolute terms but LOW relative to its
  market share.** A vendor with 34--48% of deployed edge appliances "should"
  have 39--55 KEVs if counts were proportional to install base. Fortinet has
  only 18 -- roughly one-half to one-third of the market-share expectation.

- **Smaller vendors (Ivanti, SonicWall, Citrix) are overrepresented** relative
  to their market share. This could reflect genuinely weaker security, targeted
  campaigns, or the compressive effect of KEV's inclusion criteria.

- **Check Point's count (2) is low even after market-share adjustment.** Under
  the conservative scenario (8% share), the expected count is ~9.2. Check Point's
  2 is significantly below expectation, suggesting either genuinely fewer
  exploitable edge bugs, lower researcher/attacker attention, or opacity in
  disclosure (bugs that exist but are not CVE'd/KEV'd).

- **The original chi-squared rejection (p=0.00082) understates the deviation.**
  The uniform null was actually the *most favorable* null hypothesis for the
  data. Market-share adjustment reveals that the real deviation is larger:
  the counts are too flat (too uniform) to be explained by market share.

**The honest answer:** raw KEV counts are neither proportional to market share
nor equal across vendors. They reflect a complex interaction of installed base,
researcher attention, attacker targeting, disclosure practices, and (presumably)
actual code quality -- in unknown proportions. No normalization available from
public data resolves this. The appropriate response is to present the raw counts
with the caveat, which is what the main repository does.

---

## Reproducibility

The Python code block in Section 4 is self-contained and uses only `math` from
stdlib. Copy-paste it into a Python 3.8+ interpreter to reproduce all results.

Input data (observed counts) matches `scripts/kev_edge_counts.json` as of
catalog version 2026.06.18. Market-share estimates are sourced from the analyst
reports cited in Section 2.

---

## References

- Gartner, "Magic Quadrant for Network Firewalls," December 2024.
- IDC, "Worldwide Security Appliance Tracker," 2024 Q3.
- Omdia, "Network Security Appliance Market Share," 2024.
- Fortinet Inc., Form 10-K, Fiscal Year 2024.
- F5 Networks Inc., Form 10-K, Fiscal Year 2024.
- SonicWall, "2024 Cyber Threat Report" (claims 1.1M+ devices deployed).
- CISA, "Known Exploited Vulnerabilities Catalog," accessed 2026-06-18.
- [STATISTICS.md](./STATISTICS.md) -- this repository's statistical framework.
