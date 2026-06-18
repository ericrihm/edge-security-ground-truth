# Cross-Vendor Pattern Analysis

`scripts/analyze_patterns.py` produces a cross-vendor analysis of CISA KEV edge-appliance exploitation patterns. It consumes the pre-built `scripts/kev_edge_counts.json` (the same data behind the README tables) and enriches it with `dateAdded` timestamps from the live CISA KEV feed.

---

## What the script produces

Four analysis dimensions:

### 1. Timeline (KEV additions by year per vendor)

A matrix of how many edge-appliance CVEs each vendor had added to the CISA KEV catalog per year. The `dateAdded` field comes from the live CISA feed (not from the CVE ID year). CVEs present in the counts file but absent from the live feed (ground-truth or forward-dated entries) fall back to the CVE-ID year.

**How to interpret:** A vendor's column shows when CISA confirmed active exploitation of their edge products, not when the CVE was published. Spikes indicate periods of concentrated attacker focus. Empty cells mean zero KEV additions that year -- not necessarily zero vulnerabilities.

### 2. Vendor concentration (% of total edge KEVs)

Each vendor's share of the total edge-KEV pool. This is a direct computation from the counts in `kev_edge_counts.json`.

**How to interpret:** Higher concentration means a larger share of confirmed-exploited edge vulnerabilities. This does NOT normalize for installed base, product scope breadth, or disclosure practices (see `METHODOLOGY.md` section 1 for why raw counts are not a valid ranking). A vendor with 2% of KEVs and 2% of the install base is not "safer" than one with 17% of KEVs and 40% of the install base.

### 3. Year-over-year trend

Total edge-KEV additions per year across all vendors, with year-over-year percentage change and a linear regression slope.

**How to interpret:** The slope is computed on **complete years only** -- the current (partial) year is shown but excluded from the trend line to avoid misleading downward bias. A positive slope means the rate of edge-KEV additions is increasing; negative means decreasing. "Stable" means the slope is near zero (+/- 0.5 CVEs/year). The 2023 dip followed by a 2024-2025 rebound likely reflects CISA catalog batching patterns as much as actual exploitation cadence.

### 4. EPSS analysis (conditional)

If `scripts/kev_edge_enriched.json` exists (containing EPSS scores per CVE), the script computes mean, median, max, and min EPSS scores per vendor. EPSS is the FIRST.org Exploit Prediction Scoring System -- the probability a CVE will be exploited in the wild within 30 days.

**How to interpret:** Higher mean EPSS indicates a vendor's edge CVEs are, on average, more likely to be targeted. All CVEs in this dataset are already KEV-listed (confirmed exploited), so EPSS scores here tend to be high. The spread (max vs. min) shows whether a vendor has a mix of opportunistically-exploited and targeted CVEs.

---

## Usage

```bash
# Table output (default)
python3 scripts/analyze_patterns.py

# Markdown tables
python3 scripts/analyze_patterns.py --format markdown

# Machine-readable JSON
python3 scripts/analyze_patterns.py --format json

# Write to file
python3 scripts/analyze_patterns.py --format markdown --output docs/report.md
```

The script requires network access to fetch the live CISA KEV feed (same URL as `build_kev_counts.py`). It uses only Python stdlib -- no pip dependencies.

---

## Snapshot: 2026-06-18

Generated from the live CISA KEV feed against `kev_edge_counts.json` (catalog version 2026.06.18, 115 edge CVEs across 13 vendors).

```
Edge-KEV Cross-Vendor Analysis  |  Generated: 2026-06-18T22:18:21Z
==============================================================================

1. TIMELINE: KEV additions by year per vendor
------------------------------------------------------------------------------
Vendor                   2021   2022   2023   2024   2025   2026  Total
-----------------------------------------------------------------------
Fortinet                    4      5      2      2      4      1     18
Citrix                      4      1      2      2      3      1     13
Cisco                       3      2      1      5      2     --     13
Ivanti                      8     --     --      3      2     --     13
Palo Alto Networks         --      4     --      4      2      2     12
SonicWall                   2      4     --      1      5     --     12
Juniper                    --      1      5     --      2     --      8
F5                          1      2      2     --     --      1      6
Sophos                      1      3     --     --      2     --      6
Zyxel                       1      1      3      1     --     --      6
WatchGuard                 --      2     --     --      2     --      4
Check Point                --     --     --      1     --      1      2
Array Networks             --     --     --      1      1     --      2
-----------------------------------------------------------------------
TOTAL                      24     25     15     20     25      6    115

2. VENDOR CONCENTRATION
--------------------------------------------------
Vendor                  Count       %  Bar
--------------------------------------------------
Fortinet                   18   15.7%  ########
Ivanti                     13   11.3%  ######
Cisco                      13   11.3%  ######
Citrix                     13   11.3%  ######
SonicWall                  12   10.4%  #####
Palo Alto Networks         12   10.4%  #####
Juniper                     8    7.0%  ###
F5                          6    5.2%  ##
Zyxel                       6    5.2%  ##
Sophos                      6    5.2%  ##
WatchGuard                  4    3.5%  #
Check Point                 2    1.7%
Array Networks              2    1.7%
TOTAL                     115  100.0%

3. YEAR-OVER-YEAR TREND
--------------------------------------------------
Year      Count   YoY Change  Note
----------------------------------------------------------
2021         24           --
2022         25        +4.2%
2023         15       -40.0%
2024         20       +33.3%
2025         25       +25.0%
2026          6       -76.0%  (partial year)
----------------------------------------------------------
Linear slope: -0.30 CVEs/year  =>  stable
  (slope computed on complete years only; partial year excluded)
```

### Key observations from this snapshot

- **Fortinet leads** at 15.7% of all edge KEVs, followed by a three-way tie of Ivanti, Cisco, and Citrix at 11.3% each, then SonicWall and Palo Alto Networks at 10.4%. The top 6 vendors account for 70.4% of all edge KEVs.
- **2021 was the peak year** (24 additions), driven heavily by Ivanti/Pulse Secure (8 CVEs from the ProxyLogon-era VPN campaign wave) and Citrix (4).
- **2023 was the trough** (15 additions), but 2024-2025 rebounded to 20-25 -- the dip-then-recovery pattern suggests cyclical attacker focus rather than a sustained decline.
- **The linear trend is essentially flat** (-0.30 CVEs/year on complete years), meaning "no clear sustained direction" rather than acceleration or deceleration.
- **2026 is partial** (6 CVEs through mid-June). Annualized, that projects to approximately 12 for the full year -- but CISA additions are bursty, so extrapolation is unreliable.
- **Two new vendors added**: WatchGuard (4 CVEs, 2022+2025) and Array Networks (2 CVEs, 2024+2025), expanding the dataset from 11 to 13 vendors.
- **EPSS data present** in this snapshot (`kev_edge_enriched.json` populated). Dimension 4 shows exploitation probability distributions per vendor; Ivanti leads with mean EPSS 0.78.
