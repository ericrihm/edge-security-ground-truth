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

Generated from the live CISA KEV feed against `kev_edge_counts.json` (catalog version 2026.06.18, 107 edge CVEs across 11 vendors).

```
Edge-KEV Cross-Vendor Analysis  |  Generated: 2026-06-18T17:52:51Z
==============================================================================

1. TIMELINE: KEV additions by year per vendor
------------------------------------------------------------------------------
Vendor                   2021   2022   2023   2024   2025   2026  Total
-----------------------------------------------------------------------
Fortinet                    4      5      2      2      4      1     18
Cisco                       3      2      1      5      2     --     13
Ivanti                      8     --     --      3      2     --     13
Palo Alto Networks         --      4     --      4      2      2     12
SonicWall                   2      4     --      1      5     --     12
Citrix                      4      1      2      2      2     --     11
Juniper                    --      1      5     --      2     --      8
F5                          1      2      2     --     --      1      6
Sophos                      1      3     --     --      2     --      6
Zyxel                       1      1      3      1     --     --      6
Check Point                --     --     --      1     --      1      2
-----------------------------------------------------------------------
TOTAL                      24     23     15     19     21      5    107

2. VENDOR CONCENTRATION
--------------------------------------------------
Vendor                  Count       %  Bar
--------------------------------------------------
Fortinet                   18   16.8%  ########
Ivanti                     13   12.1%  ######
Cisco                      13   12.1%  ######
SonicWall                  12   11.2%  #####
Palo Alto Networks         12   11.2%  #####
Citrix                     11   10.3%  #####
Juniper                     8    7.5%  ###
F5                          6    5.6%  ##
Zyxel                       6    5.6%  ##
Sophos                      6    5.6%  ##
Check Point                 2    1.9%
TOTAL                     107  100.0%

3. YEAR-OVER-YEAR TREND
--------------------------------------------------
Year      Count   YoY Change  Note
----------------------------------------------------------
2021         24           --
2022         23        -4.2%
2023         15       -34.8%
2024         19       +26.7%
2025         21       +10.5%
2026          5       -76.2%  (partial year)
----------------------------------------------------------
Linear slope: -1.00 CVEs/year  =>  decelerating
  (slope computed on complete years only; partial year excluded)
```

### Key observations from this snapshot

- **Fortinet leads** at 16.8% of all edge KEVs, followed by a tight cluster of Ivanti, Cisco, SonicWall, and Palo Alto Networks at 11-12% each. The top 5 vendors account for 63.6% of all edge KEVs.
- **2021 was the peak year** (24 additions), driven heavily by Ivanti/Pulse Secure (8 CVEs from the ProxyLogon-era VPN campaign wave) and Citrix (4).
- **2023 was the trough** (15 additions), but 2024-2025 rebounded to 19-21 -- the dip-then-recovery pattern suggests cyclical attacker focus rather than a sustained decline.
- **The linear trend is slightly negative** (-1.00 CVEs/year on complete years), but the year-to-year variance is high enough that "decelerating" should be read as "no clear sustained direction" rather than "the problem is shrinking."
- **2026 is partial** (5 CVEs through mid-June). Annualized, that projects to approximately 10-11 for the full year, which would continue the slight downward trend -- but CISA additions are bursty, so extrapolation is unreliable.
- **No EPSS data** in this snapshot (`kev_edge_enriched.json` not present). When EPSS enrichment is added, Dimension 4 will show exploitation probability distributions per vendor.
