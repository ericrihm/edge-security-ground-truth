# Edge Security Vendor Comparison Matrix

**Scope:** 115 CISA KEV-listed CVEs across 13 edge/perimeter vendors (firewalls, SSL-VPNs, remote-access gateways). All numbers sourced from project data files: `kev_edge_counts.json`, `kev_edge_enriched.json`, `CWE-ANALYSIS.md`, `TIME-TO-EXPLOIT.md`, `THREAT-ATTRIBUTION.md`, and per-vendor docs.

**Generated:** 2026-06-18

---

## 1. Side-by-Side Comparison Table

| Vendor | KEV Count | Zero-Days | Ransomware CVEs | Median TTE | Top CWE Category | Attributed APTs | Silent Patch | Vendor Breach |
|--------|----------:|----------:|----------------:|-----------:|-------------------|-----------------|:------------:|:-------------:|
| Fortinet | 18 | 7 | 12 | 21d | Auth/Access Control (8) | UNC3886, China-nexus (unspecified) | Y | N |
| Cisco | 13 | 4 | 3 | 378d | Memory Safety (4) | UAT4356/STORM-1849 (ArcaneDoor) | N | N |
| Citrix | 13 | 7 | 4 | 7d | Memory Safety (6) | LockBit affiliates, China-nexus | N | N |
| Ivanti | 13 | 6 | 8 | 160d | Injection (6) | UNC5221, UNC5337 | N | N |
| Palo Alto Networks | 12 | 4 | 5 | 7d | Auth/Access Control (4) | UTA0218 | N | N |
| SonicWall | 12 | 2 | 7 | 254d | Injection (5) | Akira, Fog (ransomware) | N | Y |
| Juniper | 8 | 1 | 0 | 88d | Auth/Access Control (7) | UNC3886 | N | N |
| F5 | 6 | 1 | 3 | 84d | Auth/Access + Memory (2 each) | None confirmed publicly | N | N |
| Sophos | 6 | 3 | 1 | 550d | Injection (4) | DriftingCloud, TA413, Pacific Rim cluster | N | N |
| Zyxel | 6 | 0 | 1 | 12d | Memory Safety + Injection (2 each) | Mirai botnets, Helldown | Y | N |
| WatchGuard | 4 | 1 | 0 | 34d | Memory Safety (3) | Sandworm (GRU, Cyclops Blink) | N | N |
| Check Point | 2 | 2 | 2 | 1d | Auth/Access Control (1) | Iran-nexus | N | N |
| Array Networks | 2 | 0 | 1 | 312d | Auth/Access + Injection (1 each) | Earth Kasha/MirrorFace (China-nexus) | N | N |

### Column Definitions

- **KEV Count**: Total CVEs in CISA's Known Exploited Vulnerabilities catalog for this vendor's edge products (scope-filtered per `kev_edge_counts.json`).
- **Zero-Days**: CVEs exploited at or before public disclosure, per `TIME-TO-EXPLOIT.md` (includes negative-TTE, TTE=0, and incident-report-confirmed zero-days).
- **Ransomware CVEs**: CVEs flagged by CISA as used in known ransomware campaigns.
- **Median TTE**: Median time-to-exploit in days (KEV dateAdded minus NVD publishedDate). Lower = faster exploitation. Inflated by legacy CVEs backdated when KEV launched in Nov 2021.
- **Top CWE Category**: Most frequent CWE weakness category for this vendor, with count in parentheses, per `CWE-ANALYSIS.md`.
- **Attributed APTs**: Named threat actors publicly attributed to exploiting this vendor's CVEs, per `THREAT-ATTRIBUTION.md`.
- **Silent Patch**: "Y" if the vendor has a documented episode of shipping a security patch without issuing a CVE, advisory, or coordinated disclosure. "N" means no such episode is documented in public reporting.
- **Vendor Breach**: "Y" if the vendor's own infrastructure was compromised in a publicly documented incident related to their edge products. "N" means no such incident is documented.

---

## 2. Vendor Security Posture Profiles

### Fortinet (18 KEV, 7 zero-days, 12 ransomware)

Fortinet has the highest absolute count across every volume metric: KEV entries, zero-days, and ransomware-associated CVEs. Eight of 18 CVEs (44%) are authentication/access-control failures spanning 2018-2026 -- a recurring pattern in FortiOS that suggests the auth subsystem lacks design-level guarantees. Fortinet is also the only vendor with a documented silent-patching episode (CVE-2023-27997), where firmware updates containing a CVSS 9.8 fix were pushed 3-4 days before any advisory was published. Fortinet's 2026 data-leak incident (leaked credentials from prior breach dumps) did not constitute a corporate infrastructure breach but demonstrated downstream impact from customer-side exploitation.

### Ivanti (13 KEV, 6 zero-days, 8 ransomware)

Ivanti is the injection leader in this dataset: 6 of 13 CVEs (46%) are code or command injection in Pulse Connect Secure and Connect Secure. China-nexus actors (UNC5221, UNC5337) have been publicly attributed to exploiting Ivanti products in multiple campaigns (2023-2025), triggering CISA Emergency Directive 24-01. Ivanti's zero-day rate (46%) is among the highest, though the median TTE of 160 days is elevated by legacy Pulse Secure CVEs that predated KEV. Recent CVEs (2024-2025) show TTE of 0-1 days.

### Cisco (13 KEV, 4 zero-days, 3 ransomware)

Cisco's profile is shaped by ASA/FTD -- a long-lived C/C++ codebase where memory-safety bugs (4 CVEs) and legacy vulnerabilities drive the numbers. The median TTE of 378 days is the second-highest, heavily skewed by CVE-2014-2120 (TTE=3,891 days) and other pre-2020 CVEs retroactively added to KEV. The ArcaneDoor campaign (CVE-2024-20353/20359) demonstrated state-level zero-day capability against Cisco's firewall platform. Cisco has 13 KEV entries, tying Citrix and Ivanti for second place.

### Palo Alto Networks (12 KEV, 4 zero-days, 5 ransomware)

Palo Alto has a fast median TTE (7 days) and 4 zero-days including CVE-2024-3400 (Operation MidnightEclipse, attributed to UTA0218). The CWE profile shows 4 auth/access-control failures in PAN-OS management interfaces. No documented silent-patching episodes, though initial severity framing has occasionally lagged behind external researcher findings. The 2024-2025 clustering of CVEs (CVE-2024-3400, CVE-2024-0012, CVE-2024-9474, CVE-2025-0108) represents an accelerating exploitation tempo.

### SonicWall (12 KEV, 2 zero-days, 7 ransomware)

SonicWall's CWE profile combines SQL injection (3 CVEs in SMA appliances) with auth bypass (3 CVEs). The ransomware count (7) is disproportionately high relative to zero-days (2), reflecting SonicWall's position in the SMB firewall market where Akira and Fog ransomware operators specifically target volume over precision. SonicWall is the only vendor with a documented breach of its own infrastructure: the 2025 MySonicWall cloud backup incident exposed encrypted credentials, VPN configurations, and network topology for up to 240,000 devices, leading directly to the Marquis Software ransomware attack affecting 74 U.S. banks.

### Citrix (13 KEV, 7 zero-days, 4 ransomware)

Citrix has the highest zero-day rate (54%) among vendors with 6+ CVEs. Memory-safety bugs (6 CVEs) in the NetScaler C codebase dominate, including the catastrophic CitrixBleed (CVE-2023-4966) which LockBit affiliates exploited to breach Boeing, ICBC, DP World, and others. The median TTE of 7 days reflects rapid weaponization once vulnerabilities are disclosed. CVE-2019-19781 was a watershed event -- a path traversal that sat with mitigation-only guidance for weeks while exploitation expanded.

### Juniper (8 KEV, 1 zero-day, 0 ransomware)

Juniper's profile is dominated by auth/access-control weaknesses (7 of 8 CVEs, 88%), but this is largely an artifact of the 2023 J-Web PHP exploitation chain (CVE-2023-3684x series) where 5 related CVEs were chained. CVE-2015-7755, a hardcoded backdoor in ScreenOS, stands apart as a structural integrity failure. Juniper is the only vendor in this dataset with zero ransomware-associated CVEs and only one zero-day, but UNC3886's exploitation of CVE-2025-21590 on MX-series routers demonstrates China-nexus interest in Juniper's core routing infrastructure. No documented silent patching.

### F5 (6 KEV, 1 zero-day, 3 ransomware)

F5 BIG-IP has a smaller KEV footprint (6 CVEs) with a balanced CWE distribution across auth bypass and memory safety. No public threat actor attribution exists for any F5 KEV entry -- the only vendor in this dataset with completely absent attribution. F5's advisory disclosure process (K-article system with same-day patches) is a documented relative strength. The median TTE of 84 days reflects the gap between disclosure and mass exploitation rather than zero-day usage.

### Zyxel (6 KEV, 0 zero-days, 1 ransomware)

Zyxel is the only vendor with zero confirmed zero-days and has the lowest ransomware count (1). The CWE profile shows buffer overflows and OS command injection across ATP/USG FLEX firewalls marketed to SMBs. Zyxel has a documented silent-patching episode: CVE-2022-30525 was fixed in firmware on April 28, 2022 without a CVE, advisory, or researcher coordination -- the patch was discovered by Rapid7 two weeks later. Botnet exploitation (Mirai variants) is the primary threat, consistent with Zyxel's SMB deployment base.

### Sophos (6 KEV, 3 zero-days, 1 ransomware)

Sophos has a high zero-day rate (50%) with 3 of 6 CVEs exploited before disclosure, all in the XG Firewall (2020-2022). The standout data point is the Pacific Rim campaign: Sophos documented a five-year defensive operation against overlapping China-nexus clusters (with Volt Typhoon, APT31, and APT41 TTP overlap) targeting their firewall platform. The median TTE of 550 days is the highest in the dataset, entirely driven by true zero-days where KEV listing was backdated (e.g., CVE-2020-12271 TTE=555d despite being a true zero-day). All 4 injection CVEs are in the XG Firewall codebase.

### WatchGuard (4 KEV, 1 zero-day, 0 ransomware)

WatchGuard's mid-range footprint (4 CVEs) is dominated by memory corruption: three of four entries are out-of-bounds writes (CWE-787), split across two subsystems -- the 2022 HTTP management-plane RCE (CVE-2022-26318) and a 2025 pair in the `iked` IKEv2 VPN daemon (CVE-2025-9242, CVE-2025-14733). The lone outlier, CVE-2022-23176 (CWE-269 privilege management), was the access primitive Russia's GRU-attributed Sandworm group chained into the Cyclops Blink botnet before an April 2022 FBI court-authorized takedown. CVE-2025-14733 is WatchGuard's one confirmed zero-day -- added to KEV on its NVD publication date (December 19, 2025) with active exploitation and a one-week federal deadline. WatchGuard carries zero CISA ransomware-association flags: its KEV record is a nation-state and botnet story, not a ransomware one. Its SMB-skewed installed base (~117,000 internet-exposed instances counted in late 2025) is a structural slow-to-patch risk multiplier, the same dynamic documented for Zyxel.

### Check Point (2 KEV, 2 zero-days, 2 ransomware)

Check Point has the smallest sample (2 CVEs) making statistical comparison unreliable. Both CVEs are zero-days (100% rate). CVE-2024-24919 was attributed to Iran-nexus actors and exploited before the vendor advisory -- mnemonic.io confirmed exploitation before Check Point's disclosure. The median TTE of 1 day is the fastest in the dataset. No documented silent patching. The small KEV footprint may reflect either a stronger product security posture or lower attacker prioritization; the data cannot distinguish these explanations.

### Array Networks (2 KEV, 0 zero-days, 1 ransomware)

Array Networks ties Check Point for the smallest sample (2 CVEs), but the two profiles differ sharply. Neither Array CVE is a confirmed zero-day -- both were patched well before their KEV listing, most strikingly CVE-2023-28461 (CWE-306 missing authentication, CVSS 9.8), whose ~20-month gap between the March 2023 fix and the November 2024 KEV addition is the longest such tail among the low-count vendors. That CVE carries CISA's ransomware-association flag, though the well-documented exploitation is the China-nexus Earth Kasha / MirrorFace espionage campaign (LodeInfo, NOOPDOOR, Cobalt Strike) against targets in Japan, Taiwan, and India -- the ransomware "Known" flag is CISA-asserted but less publicly corroborated. The second entry, CVE-2025-66644 (CWE-78 OS command injection, CVSS 7.2 with a PR:H prerequisite), was added to KEV three days after publication in December 2025. The access-control-plus-injection pairing aligns Array more with the broader edge-VPN exploitation pattern (Ivanti, Citrix) than with Check Point's credential-extraction / auth-bypass profile, and a small installed base (~3,427 internet-exposed gateways) plus a thin researcher community plausibly explain the low count.

---

## 3. Peer Groups: Clustering by Risk Profile

### Group A: High-Volume Targets

**Vendors:** Fortinet (18), Ivanti (13), Cisco (13), Palo Alto Networks (12), SonicWall (12)

These five vendors account for 68 of 115 CVEs (59%). They share large enterprise and government install bases, making them high-value targets for both nation-state espionage and ransomware operations. All five have named APT attributions. The differentiator within this group is the dominant weakness class: Fortinet and Palo Alto skew toward auth failures, Ivanti and SonicWall toward injection, Cisco toward memory safety.

### Group B: Mid-Volume, High-Severity

**Vendors:** Citrix (13), Juniper (8)

Mid-range KEV counts but with concentration effects. Citrix has the highest zero-day rate (54%) among vendors with 6+ CVEs, and the CitrixBleed incident had outsized real-world impact (Boeing, ICBC). Juniper's 88% auth/access-control concentration is the most skewed CWE profile of any vendor. Both have documented China-nexus targeting.

### Group C: Smaller Footprint, Concentrated Risk

**Vendors:** F5 (6), Zyxel (6), Sophos (6)

Six KEV entries each. The risk profile diverges sharply within this group: Sophos has a 50% zero-day rate and documented multi-year state-actor campaigns (Pacific Rim); Zyxel has zero zero-days but faces commodity botnet exploitation; F5 has no public actor attribution at all. These vendors have smaller edge-appliance market share than Group A, which may explain the lower volume -- but CVE severity is not lower (all three have CVSS 9.8 entries).

### Group D: Insufficient Sample

**Vendors:** Check Point (2)

Two CVEs is insufficient to establish a pattern. Check Point's numbers (100% zero-day rate, 1-day median TTE) reflect the specific characteristics of these two CVEs, not a generalizable posture. The profile may change substantially as more data accumulates -- CVE-2026-50751 was just added in June 2026.

---

## 4. Dimensional Summary

### By Zero-Day Rate (% of KEV CVEs exploited before disclosure)

| Vendor | Zero-Day Rate | Zero-Days / Total |
|--------|-------------:|------------------:|
| Check Point | 100% | 2/2 |
| Citrix | 54% | 7/13 |
| Sophos | 50% | 3/6 |
| Ivanti | 46% | 6/13 |
| Fortinet | 39% | 7/18 |
| Palo Alto Networks | 33% | 4/12 |
| Cisco | 31% | 4/13 |
| WatchGuard | 25% | 1/4 |
| SonicWall | 17% | 2/12 |
| F5 | 17% | 1/6 |
| Juniper | 12% | 1/8 |
| Array Networks | 0% | 0/2 |
| Zyxel | 0% | 0/6 |

### By Ransomware Density (% of KEV CVEs used in ransomware campaigns)

| Vendor | Ransomware % | Ransomware / Total |
|--------|------------:|-------------------:|
| Check Point | 100% | 2/2 |
| Fortinet | 67% | 12/18 |
| Ivanti | 62% | 8/13 |
| SonicWall | 58% | 7/12 |
| F5 | 50% | 3/6 |
| Array Networks | 50% | 1/2 |
| Palo Alto Networks | 42% | 5/12 |
| Citrix | 31% | 4/13 |
| Cisco | 23% | 3/13 |
| Sophos | 17% | 1/6 |
| Zyxel | 17% | 1/6 |
| Juniper | 0% | 0/8 |
| WatchGuard | 0% | 0/4 |

### By Exploitation Speed (Median TTE)

| Vendor | Median TTE |
|--------|----------:|
| Check Point | 1d |
| Palo Alto Networks | 7d |
| Citrix | 7d |
| Zyxel | 12d |
| Fortinet | 21d |
| WatchGuard | 34d |
| F5 | 84d |
| Juniper | 88d |
| Ivanti | 160d |
| SonicWall | 254d |
| Array Networks | 312d |
| Cisco | 378d |
| Sophos | 550d |

Note: High median TTE for Sophos, Cisco, SonicWall, and Ivanti is driven by pre-2022 CVEs backdated when KEV launched in November 2021. For CVEs published in 2024+, median TTE across all vendors converges toward 0-3 days.

---

## 5. Caveats: Why This Matrix Is NOT a Ranking

This matrix presents observable data dimensions. It is **not** a ranking of vendor security quality. The following confounders prevent direct vendor-to-vendor comparison:

### 5.1 Market Share and Attacker Selection Bias

Vendors with larger installed bases in high-value segments (government, critical infrastructure, financial services) attract more sophisticated attackers and more zero-day development investment. Fortinet's high KEV count may reflect market dominance in the enterprise firewall space rather than -- or in addition to -- product weakness. Conversely, Zyxel's zero zero-days may reflect lower attacker interest in the SMB segment rather than superior security engineering. **The data measures attacker interest as much as it measures vendor weakness.**

### 5.2 KEV Catalog Composition Bias

The CISA KEV catalog is not a census of all exploited vulnerabilities. It reflects what CISA has confirmed and chosen to list. Vendors with US-centric customer bases (Cisco, Palo Alto) may be overrepresented due to closer CISA visibility. Vendors with smaller US footprints may have exploited CVEs that never reach KEV. The catalog also launched in November 2021, creating a retroactive backfill that inflates legacy CVE counts and TTE values for all vendors.

### 5.3 Product Scope Differences

The scope of "edge product" varies by vendor. Fortinet's scope includes FortiOS and FortiProxy; Cisco's scope is limited to ASA/FTD (excluding FMC); Ivanti covers only Connect Secure/Policy Secure (excluding EPMM, Sentry, etc.). A vendor with a broader scoped product line will naturally accumulate more CVEs. The `kev_edge_counts.json` scope rules attempt to normalize this, but the underlying product complexity differs.

### 5.4 Disclosure and Transparency Effects

Vendors who are more transparent about vulnerabilities may have higher CVE counts than vendors who fix bugs quietly. A silent-patch culture (documented for Fortinet and Zyxel) may suppress CVE counts while leaving defenders uninformed. Conversely, Sophos's Pacific Rim report -- an unusually detailed multi-year disclosure -- increases visible attribution against Sophos but reflects a positive transparency choice, not a unique vulnerability problem.

### 5.5 Temporal Coverage Asymmetry

Some vendors' edge products have been in the KEV-relevant market longer than others. Cisco ASA dates to the mid-2000s; Check Point's Quantum gateway entered the KEV scope more recently. Longer market presence means more time to accumulate CVEs. The data does not normalize for years-on-market.

### 5.6 Attribution Gaps Are Not Exoneration

F5 has zero public threat actor attributions. This does not mean F5 products are unexploited by sophisticated actors -- CISA's KEV listing confirms active exploitation. It means no analyst has published naming the actor. Attribution depends on incident response visibility, which varies by vendor and victim population.

### 5.7 Zero-Day Rate vs. Volume

A 100% zero-day rate on 2 CVEs (Check Point) is statistically meaningless compared to a 39% rate on 18 CVEs (Fortinet). Small-sample vendors should be interpreted with extreme caution. The matrix presents both the rate and the raw count for this reason.

### 5.8 Median TTE Is a Lagging Indicator

Median TTE for the full dataset is dragged by pre-KEV legacy CVEs. The more operationally relevant metric is TTE for CVEs published in the past 2 years, which converges to 0-3 days across all vendors. The per-vendor median TTE differences in the table above are largely a function of when each vendor's CVEs were published, not how quickly they are exploited today.

---

## Reproducing This Analysis

All source data is in this repository:

```bash
# Source data
cat scripts/kev_edge_counts.json     # CVE lists per vendor
cat scripts/kev_edge_enriched.json   # NVD/EPSS enrichment per CVE

# Analysis documents
cat docs/CWE-ANALYSIS.md             # Weakness-class breakdown
cat docs/TIME-TO-EXPLOIT.md          # TTE and zero-day analysis
cat docs/THREAT-ATTRIBUTION.md       # Actor attribution
cat docs/{Vendor}.md                 # Per-vendor deep-dive profiles
```

---

*Data sources: CISA KEV catalog, NVD API 2.0, FIRST EPSS, Mandiant/GTIG, Volexity, CrowdStrike, Talos, Sophos Pacific Rim, Arctic Wolf, Check Point Research, Microsoft Threat Intelligence.*
