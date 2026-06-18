# EPSS Edge-Domain Evaluation

How well does EPSS recognize edge-appliance CVEs that are *already known* to be
exploited?

**115 edge CVEs** across **13 vendors**, every one of them CISA KEV-listed and
therefore a ground-truth exploited positive. EPSS publishes no device-class
breakdown, so this is -- to our knowledge -- the first empirical look at EPSS
calibration specifically for the **edge / perimeter appliance** subset of KEV
(VPN gateways, firewalls, load balancers, secure-access products).

> Reproduce: `python3 scripts/analyze_epss_eval.py --format markdown`
> (offline, stdlib-only -- reads `scripts/kev_edge_enriched.json`)

---

## The question

EPSS (the [Exploit Prediction Scoring System](https://www.first.org/epss/),
FIRST.org) gives each CVE a probability in `[0, 1]` that it will be exploited in
the next 30 days, plus a percentile rank against all scored CVEs. It is a
*predictor* of exploitation.

Every CVE in this dataset has *already been exploited* (KEV is CISA's confirmed
in-the-wild catalog). So on this slice the "right answer" is known: a
well-behaved predictor should skew **high**. Where EPSS skews low, it is
effectively **failing to recognize a confirmed edge exploitation** -- an "EPSS
miss" for the edge domain.

This is not a claim that EPSS is broken. It is a measurement of EPSS behaviour
on a deliberately hard, adversarially-selected slice (see Limitations).

---

## Methodology

| Field | Source |
|-------|--------|
| `epss` (probability), `percentile` | FIRST EPSS API, captured at enrichment |
| Scope (which CVEs are "edge") | `kev_edge_counts.json` vendor -> CVE-ID lists |
| `cvss`, `cwe`, `published` | NVD, captured at enrichment |
| `ransomware` | CISA KEV `knownRansomwareCampaignUse` |

**Enrichment timestamp:** EPSS/CVSS/CWE values were captured 2026-06-18
(`_metadata.generated_at` in `kev_edge_enriched.json`). All 115 in-scope CVEs
carry a non-null EPSS score.

### Definitions

| Term | Meaning |
|------|---------|
| **EPSS probability** | EPSS model output, P(exploit in next 30 days), `[0,1]` |
| **EPSS percentile** | Rank of this CVE's probability vs. all scored CVEs |
| **EPSS > 0.5** | EPSS judges exploitation more likely than not |
| **EPSS > 0.9** | EPSS judges exploitation near-certain |
| **EPSS < 0.1** | EPSS effectively does **not** flag the CVE |
| **Miss** | Confirmed-exploited CVE with `epss < 0.1` **OR** `percentile < 0.5` |

The `0.1` / `0.5` cut-points follow FIRST.org's own prioritisation guidance
(an EPSS threshold of ~0.1 is a common "act on this" floor). A miss is a CVE
that would **not** be surfaced under a reasonable edge-prioritisation cutoff.

---

## Results

### 1. EPSS distribution across the known-exploited slice

| Metric | EPSS probability | EPSS percentile |
|--------|-----------------:|----------------:|
| mean   | 0.5628 | 0.9618 |
| median | 0.6140 | 0.9905 |
| Q1     | 0.1802 | 0.9682 |
| Q3     | 0.9829 | 0.9991 |
| min    | 0.0086 | 0.5390 |
| max    | 1.0000 | 1.0000 |

- **EPSS > 0.5:** 61 / 115 (**53.0%**)
- **EPSS > 0.9:** 39 / 115 (**33.9%**)
- **EPSS < 0.1 (does not flag):** 20 / 115 (**17.4%**)

| EPSS probability bucket | n | % |
|-------------------------|--:|--:|
| 0.00-0.10 (EPSS does not flag) | 20 | 17.4% |
| 0.10-0.50 (low)                | 34 | 29.6% |
| 0.50-0.90 (elevated)           | 22 | 19.1% |
| 0.90-1.00 (near-certain)       | 39 | 33.9% |

**Read this carefully.** Two facts sit side by side:

- The **percentile** distribution is extremely high (median 0.9905, Q1 0.9682).
  Relative to the entire CVE population, these edge CVEs sit near the very top --
  EPSS *does* recognise them as more dangerous than average.
- The **probability** distribution is far more spread out (median 0.6140) and
  has a heavy low tail: **nearly half (47%) sit below 0.5**, and **17.4% sit
  below 0.1**, despite every single one being a confirmed in-the-wild
  exploitation.

The probability/percentile gap is the central finding. A CVE at the 90th
percentile can still carry a raw probability under 0.05 -- because the
*absolute* exploitation probability of the median CVE is tiny. For edge
defenders prioritising on raw EPSS, the percentile is reassuring while the
probability under-counts confirmed edge threats.

### 2. Per-vendor EPSS distribution

Sorted by median EPSS ascending. Vendors EPSS systematically *under-scores*
(for this known-exploited slice) float to the top.

| Vendor | n | median | mean | min | <0.1 | miss % |
|--------|--:|-------:|-----:|----:|-----:|-------:|
| SonicWall          | 12 | 0.2848 | 0.4290 | 0.0191 | 3 | 25.0% |
| Array Networks     |  2 | 0.3535 | 0.3535 | 0.0305 | 1 | 50.0% |
| Palo Alto Networks | 12 | 0.3554 | 0.5128 | 0.0186 | 3 | 25.0% |
| WatchGuard         |  4 | 0.4789 | 0.4860 | 0.1225 | 0 |  0.0% |
| Citrix             | 13 | 0.5763 | 0.5598 | 0.0319 | 3 | 23.1% |
| Fortinet           | 18 | 0.5842 | 0.5486 | 0.0086 | 3 | 16.7% |
| Zyxel              |  6 | 0.5943 | 0.5820 | 0.0296 | 1 | 16.7% |
| Cisco              | 13 | 0.6327 | 0.5475 | 0.1403 | 0 |  0.0% |
| Sophos             |  6 | 0.6988 | 0.5898 | 0.0473 | 1 | 16.7% |
| Check Point        |  2 | 0.7056 | 0.7056 | 0.4115 | 0 |  0.0% |
| Juniper            |  8 | 0.7305 | 0.5387 | 0.0110 | 3 | 37.5% |
| F5                 |  6 | 0.7879 | 0.6071 | 0.0225 | 2 | 33.3% |
| Ivanti             | 13 | 0.9862 | 0.7775 | 0.1415 | 0 |  0.0% |

Observations:

- **Ivanti** is EPSS's best-recognised edge vendor (median 0.9862, zero misses).
  Ivanti's KEV entries are dominated by the heavily-publicised Connect Secure /
  Pulse chains, exactly the kind of CVE EPSS scores highly once PoCs proliferate.
- **SonicWall and Palo Alto Networks** sit at the bottom (medians ~0.28-0.36)
  with a quarter of their confirmed-exploited CVEs flagged as misses. Both have
  several recent (2025) CVEs whose probability had not yet climbed at enrichment.
- **Small-n vendors** (Array Networks n=2, Check Point n=2) are noisy -- a
  single CVE swings the median. Treat their rows as illustrative, not robust.

### 3. Gap analysis -- exploited-but-low-EPSS edge CVEs

**20 of 115 (17.4%)** confirmed-exploited edge CVEs are EPSS misses. All 20 are
flagged by the `epss < 0.1` condition (none of the edge CVEs has a percentile
below 0.5, so the percentile arm of the rule never fires alone here). **4** of
the misses are also associated with known ransomware campaigns.

| CVE | Vendor | EPSS | Percentile | CVSS | CWE | Published | Ransomware |
|-----|--------|-----:|-----------:|-----:|-----|-----------|:----------:|
| CVE-2021-44168 | Fortinet           | 0.00865 | 0.5390 | 3.3  | CWE-494 | 2022-01-04 | - |
| CVE-2023-36851 | Juniper            | 0.01100 | 0.6138 | 5.3  | CWE-306 | 2023-09-26 | - |
| CVE-2025-21590 | Juniper            | 0.01657 | 0.7357 | 4.4  | CWE-653 | 2025-03-12 | - |
| CVE-2025-0111  | Palo Alto Networks | 0.01862 | 0.7652 | 7.1  | CWE-73  | 2025-02-12 | - |
| CVE-2025-40602 | SonicWall          | 0.01910 | 0.7712 | 6.6  | CWE-862 | 2025-12-18 | - |
| CVE-2022-0028  | Palo Alto Networks | 0.02025 | 0.7847 | 8.6  | CWE-406 | 2022-08-10 | - |
| CVE-2025-53521 | F5                 | 0.02246 | 0.8060 | 9.8  | CWE-121 | 2025-10-15 | - |
| CVE-2024-11667 | Zyxel              | 0.02958 | 0.8542 | 7.5  | CWE-22  | 2024-11-27 | **Known** |
| CVE-2025-24472 | Fortinet           | 0.02988 | 0.8557 | 8.1  | CWE-288 | 2025-02-11 | **Known** |
| CVE-2025-66644 | Array Networks     | 0.03046 | 0.8583 | 7.2  | CWE-78  | 2025-12-05 | - |
| CVE-2023-6548  | Citrix             | 0.03191 | 0.8645 | 5.5  | CWE-94  | 2024-01-17 | - |
| CVE-2021-20035 | SonicWall          | 0.03890 | 0.8889 | 6.5  | CWE-78  | 2021-09-27 | - |
| CVE-2019-7483  | SonicWall          | 0.03977 | 0.8915 | 7.5  | CWE-22  | 2019-12-19 | - |
| CVE-2020-2021  | Palo Alto Networks | 0.03994 | 0.8919 | 10.0 | CWE-347 | 2020-06-29 | **Known** |
| CVE-2023-46748 | F5                 | 0.04468 | 0.9022 | 8.8  | CWE-89  | 2023-10-26 | - |
| CVE-2020-1631  | Juniper            | 0.04725 | 0.9068 | 8.8  | CWE-22  | 2020-05-04 | - |
| CVE-2020-29574 | Sophos             | 0.04729 | 0.9069 | 9.8  | CWE-89  | 2020-12-11 | - |
| CVE-2019-6693  | Fortinet           | 0.05352 | 0.9159 | 6.5  | CWE-798 | 2019-11-21 | **Known** |
| CVE-2022-27518 | Citrix             | 0.06931 | 0.9328 | 9.8  | CWE-664 | 2022-12-13 | - |
| CVE-2025-6543  | Citrix             | 0.09756 | 0.9492 | N/A  | CWE-119 | 2025-06-25 | - |

(CWE values are read live from `kev_edge_enriched.json`; verify against the
canonical record if a value matters operationally.)

Notable misses:

- **CVE-2020-2021** (Palo Alto PAN-OS SAML auth bypass, CVSS 10.0, ransomware):
  a maximum-severity, ransomware-associated, confirmed-exploited CVE scored at
  EPSS 0.04. Severity and exploitation are both maxed; EPSS probability is not.
- **CVE-2024-11667 / CVE-2019-6693 / CVE-2025-24472**: ransomware-associated
  edge CVEs all under 0.06 EPSS.
- **2025 CVEs dominate the tail** (5 of the 20 misses are from 2025), consistent
  with EPSS probabilities not yet having climbed at enrichment time.

### 4. Percentile-at-enrichment by publish year

| Year | n | EPSS median | EPSS mean | Percentile median | Misses |
|------|--:|------------:|----------:|------------------:|-------:|
| 2014 |  1 | 0.1403 | 0.1403 | 0.9609 | 0 |
| 2015 |  1 | 0.6140 | 0.6140 | 0.9905 | 0 |
| 2016 |  2 | 0.5504 | 0.5504 | 0.9858 | 0 |
| 2017 |  1 | 0.9834 | 0.9834 | 0.9991 | 0 |
| 2018 |  1 | 0.9990 | 0.9990 | 0.9996 | 0 |
| 2019 | 11 | 0.8169 | 0.6369 | 0.9960 | 2 |
| 2020 | 19 | 0.4934 | 0.5480 | 0.9874 | 3 |
| 2021 |  9 | 0.4004 | 0.3999 | 0.9845 | 1 |
| 2022 | 10 | 0.8860 | 0.5990 | 0.9972 | 3 |
| 2023 | 18 | 0.8519 | 0.6564 | 0.9969 | 2 |
| 2024 | 17 | 0.6327 | 0.6113 | 0.9910 | 2 |
| 2025 | 20 | 0.2572 | 0.4682 | 0.9765 | 7 |
| 2026 |  5 | 0.4115 | 0.4612 | 0.9849 | 0 |

Two patterns:

- **Percentile is remarkably stable across years** (medians 0.96-0.99 for every
  cohort with n > 2). Whatever the publish year, these edge CVEs land near the
  top of the overall CVE population. EPSS's *relative* ranking of edge CVEs is
  consistent and high.
- **The most recent cohort (2025) has the lowest median probability (0.2572)
  and the most misses (7 of 20).** This is the point-in-time artifact made
  visible: EPSS probability for newer CVEs is still maturing at enrichment, so a
  freshly-disclosed-but-already-exploited edge CVE looks under-scored relative
  to its older peers. The 2026 cohort (n=5) is too small to read into.

---

## Headline

- On the known-exploited edge slice, EPSS **percentile** is consistently high
  (median 0.9905) -- edge CVEs *are* ranked near the top of all CVEs.
- EPSS **probability** under-counts: median 0.6140, **47% below 0.5**, and
  **17.4% below 0.1** despite every CVE being a confirmed exploitation.
- **20 confirmed-exploited edge CVEs are EPSS misses** (`epss < 0.1`), 4 of them
  ransomware-associated, including the CVSS-10.0 PAN-OS auth bypass CVE-2020-2021.
- The miss tail concentrates in recent (2025) CVEs and in SonicWall / Palo Alto
  / Juniper / F5; Ivanti and Cisco are scored well.

**Operational takeaway:** for edge appliances, treat raw EPSS probability as a
floor signal, not a gate. A low EPSS on a perimeter appliance CVE does not mean
low risk -- 1 in 6 of these confirmed edge exploitations would have been missed
by an `epss >= 0.1` filter.

---

## Limitations

This evaluation is descriptive and deliberately narrow. It does **not** claim
EPSS is miscalibrated in general.

1. **Point-in-time at enrichment, not at exploitation.** All EPSS/percentile
   values were captured on a single date (2026-06-18), not at the moment each
   CVE was exploited. EPSS probability for a fresh CVE typically climbs only
   *after* public PoC release and mass-scanning signal. A low score on a newly
   disclosed 0-day is expected model behaviour, not necessarily a failure. The
   2025-cohort tail (Result 4) is largely this effect. A true longitudinal study
   would snapshot EPSS at multiple points (disclosure, KEV-add, today).

2. **KEV is a biased, high-exploitation sample by construction.** Every CVE here
   was *selected because* it is exploited. EPSS is trained to predict the general
   CVE population, where the base rate of exploitation is very low. Measuring
   EPSS only on confirmed positives evaluates **recall on a hard subset**; it
   says nothing about precision or about EPSS performance on the population it
   was designed for. "Misses" here are misses on an adversarially-selected slice.

3. **No false-positive view.** Because there are no negatives (non-exploited
   CVEs) in this dataset, we cannot compute precision, ROC/AUC, or full
   calibration curves -- only the score distribution over true positives.

4. **Small-n vendors are noisy.** Array Networks (n=2) and Check Point (n=2)
   per-vendor statistics swing on a single CVE and should be read as
   illustrative only.

5. **Threshold choice is a judgement call.** The `0.1` / `0.5` cut-points follow
   common FIRST.org prioritisation guidance but are not universal; a defender
   using a different EPSS gate will count a different number of misses. The miss
   list scales monotonically with the threshold and can be recomputed.

6. **Enrichment values are read live.** EPSS, CVSS, and CWE in
   `kev_edge_enriched.json` reflect a single capture; FIRST recomputes EPSS
   daily and these numbers will drift. Reproduce against the committed snapshot
   for the figures above.

---

## Reproduce

```bash
# Text tables (default)
python3 scripts/analyze_epss_eval.py

# Markdown (this document's tables)
python3 scripts/analyze_epss_eval.py --format markdown

# Machine-readable JSON
python3 scripts/analyze_epss_eval.py --format json
```

Offline and stdlib-only -- no network calls, no pip dependencies. EPSS and
percentile values are read directly from `scripts/kev_edge_enriched.json`
(scoped by `scripts/kev_edge_counts.json`).

## See also

- [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md) -- how fast these CVEs were exploited
- [STATISTICS.md](STATISTICS.md) -- vendor-count significance testing
- [CWE-ANALYSIS.md](CWE-ANALYSIS.md) -- weakness-class breakdown
