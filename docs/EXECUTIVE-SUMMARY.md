# State of Edge Security 2026: Executive Summary

**Dataset:** 115 CISA KEV-listed CVEs across 13 edge-device vendors (firewalls, SSL-VPNs, remote-access gateways), 2020-01-01 through 2026-06-18. Full data and scripts at [github.com/ericrihm/edge-security-ground-truth](https://github.com/ericrihm/edge-security-ground-truth).

---

## Abstract

Internet-facing edge appliances -- firewalls, SSL-VPN gateways, and remote-access concentrators -- are the primary zero-day battleground for both nation-state espionage and ransomware operations in 2024-2026. This dataset tracks 115 CISA KEV-listed CVEs across 13 major edge vendors under a single, reproducible scope rule and finds that no vendor is meaningfully safer than the others: all thirteen sit between 2 and 18 exploited edge CVEs over six years, with the spread largely tracking installed base and researcher attention rather than demonstrable code-quality differences. The median time-to-exploit for edge CVEs published since 2024 is **0 days** -- exploitation is effectively simultaneous with disclosure, eliminating the traditional patch window. The controllable variable is not which vendor you deploy, but how fast you respond, whether management planes are internet-exposed, and whether you assume breach the moment a KEV lands.

---

## Key Findings

- **115 exploited edge CVEs across 13 vendors, range 2-18 per vendor.** The distribution is near-uniform (Gini coefficient 0.302, HHI just 1.29x the equal-share baseline). A chi-squared test rejects uniformity (chi2(12) = 33.652, p = 0.00082), but the primary confounders -- installed base, researcher attention, disclosure transparency -- are uncontrolled. The spread does not support ranking vendors by security posture.

- **38 confirmed zero-days (33% of all edge CVEs).** Eleven of thirteen vendors have at least one zero-day in the dataset (Zyxel and Array Networks have none). Citrix (54%), Sophos (50%), and Ivanti (46%) have the highest zero-day rates as a proportion of their KEV entries. Fortinet has the highest raw zero-day count (7 of 18).

- **Median time-to-exploit has collapsed from years to zero.** Pre-2020 median TTE was measured in years; by 2022 it was 2 days; for CVEs published in 2024 the median is 0 days. Monthly patching cycles are structurally inadequate for internet-facing edge devices.

- **Three weakness classes account for 72% of all exploited edge CVEs.** Authentication/access-control failures (27%), memory-safety bugs (23%), and injection (22%). These are decades-old, well-understood bug classes -- not novel attack techniques. Auth failures are accelerating (12% pre-2019 to 35% in 2024+); memory-safety bugs surged to 36% in 2024+.

- **41% of edge CVEs are associated with ransomware campaigns.** 47 of 115 CVEs carry CISA's ransomware flag -- far exceeding the overall KEV rate. Edge devices are the dominant initial-access vector for ransomware operators targeting mid-market organizations.

- **China-nexus actors dominate the attribution matrix.** At least 6 distinct China-linked clusters (UNC3886, UNC5221, UNC5337, UTA0218, DriftingCloud, Pacific Rim) have exploited edge CVEs across Fortinet, Ivanti, Cisco, Palo Alto, Sophos, and Juniper. Mandiant/GTIG found 44% of 2024 zero-days targeted security/edge appliances. Iran-nexus actors exploited Check Point CVE-2024-24919 at scale.

- **Path traversal (CWE-22) appears in 7 of 13 vendors** -- effectively universal to the industry -- but is declining over time (24% pre-2019 to 5% in 2024+), making it one of the few genuine SDL improvement signals in the dataset.

---

## Methodology Snapshot

All counts are derived from the CISA Known Exploited Vulnerabilities catalog, filtered to each vendor's internet-facing edge appliance (firewall, SSL-VPN, remote-access gateway) under a single scope rule applied uniformly -- endpoint, management console, email gateway, WAF, switch, and router products are excluded. The gating script ([`scripts/build_kev_counts.py`](../scripts/build_kev_counts.py)) fetches the live CISA JSON feed and is deterministic: anyone can re-run it to reproduce or update every number in this repository. Supporting enrichment (CVSS, CWE, EPSS, NVD publication dates) uses the NVD 2.0 API and FIRST.org EPSS API; time-to-exploit is computed as CISA KEV `dateAdded` minus NVD `publishedDate` (a conservative upper bound, since actual exploitation often precedes KEV confirmation).

---

## For CISOs

### 1. Treat every edge appliance as a high-value, actively-targeted asset regardless of vendor

The data does not support selecting a firewall vendor based on CVE reputation. Eleven vendors, one scope, 2-18 exploited CVEs each -- with the spread tracking market share more than code quality. Instead, invest in reducing your mean-time-to-respond: pre-stage virtual-patch rules, maintain offline configuration backups, and rehearse the KEV-alert response procedure before the next advisory drops.

### 2. Assume the patch window is zero

For edge CVEs published since 2024, the median time from disclosure to confirmed exploitation is 0 days. If your patching SLA for internet-facing appliances is measured in weeks, it is structurally insufficient. Require emergency-patch capability (hotfix within 24 hours of KEV addition) for all edge devices, and treat any management-plane exposure to the internet as a critical finding -- 8 of the 115 CVEs are "missing authentication for critical function" (CWE-306), meaning the management API was simply unprotected.

### 3. Budget for assume-breach hunting, not just prevention

33% of these CVEs were zero-days -- exploited before any patch existed. Prevention alone cannot address this. Fund continuous threat hunting on edge devices: monitor for indicators of compromise published alongside KEV entries, deploy integrity-checking tools (where the vendor supports them), and treat post-exploitation persistence techniques (firmware-surviving symlinks, in-memory implants) as part of the incident-response playbook.

---

## For Threat Intelligence Analysts

### 1. Track the China-nexus edge-targeting cluster as a unified campaign

Six distinct designations (UNC3886, UNC5221, UNC5337, UTA0218, DriftingCloud, Pacific Rim) have exploited edge CVEs across six different vendors. Sophos's Pacific Rim report documented TTP overlap with Volt Typhoon, APT31, and APT41 within a single five-year campaign. UNC3886 alone exploited Fortinet (2022) and then Juniper (2025) -- the same cluster moving across vendors years apart. Treat edge-device targeting by China-nexus actors as a coordinated, multi-vendor, multi-year operational priority, not as isolated vendor-specific incidents.

### 2. Use the CWE weakness fingerprint as a predictive indicator

Each vendor has a distinct CWE concentration: Fortinet skews auth/access-control (8 of 18, 44%), Ivanti skews injection (6 of 13, 46%), Citrix concentrates in memory safety (6 of 13, 46%), Cisco splits memory safety and injection (4 each). When a new advisory drops for a vendor, the historical weakness fingerprint predicts the most likely bug class -- use it to prioritize PoC analysis, detection rule development, and intelligence collection on exploit-broker channels.

### 3. Monitor the ransomware-to-edge pipeline as a leading indicator

41% of edge CVEs end up in ransomware campaigns. The typical sequence is: nation-state zero-day exploitation, then public PoC, then ransomware weaponization within days to weeks. When a new edge zero-day is attributed to a state actor, begin ransomware-specific detection engineering immediately -- do not wait for CISA's ransomware flag.

---

## For Security Researchers

This dataset enables several lines of research that raw CVE counts or isolated vendor analyses cannot support:

- **Cross-vendor weakness-class comparison.** 115 CVEs across 13 vendors, each tagged with NVD CWE assignments and mapped into 10 meta-categories. The per-vendor "weakness fingerprint" (e.g., Fortinet's auth cluster, Ivanti's injection cluster) is available as structured JSON for programmatic analysis.

- **Time-to-exploit trend modeling.** Full TTE computation (KEV dateAdded minus NVD publishedDate) for all 115 CVEs, with per-year medians showing the monotonic collapse from years to zero. The 38 confirmed zero-days are individually sourced and distinguishable from TTE-only signals.

- **Ransomware initial-access research.** 47 CVEs flagged for ransomware association, cross-referenced with vendor, CWE, TTE, and attribution. The dataset supports analysis of which bug classes and which vendors' devices are most frequently weaponized by ransomware operators.

- **Attribution network mapping.** A 19-entry attribution matrix linking CVEs to named threat actors (UNC/UAT/UTA designations), with nexus classification (China, Iran, criminal, botnet) and primary sourcing. Useful for studying actor-vendor targeting preferences and operational tempo.

- **CISA Secure-by-Design benchmarking.** The CWE temporal analysis shows auth failures accelerating (12% to 35%) and memory-safety bugs surging (to 30% in 2024+) despite CISA's Secure-by-Design initiative -- providing empirical grounding for policy effectiveness research.

All analysis scripts are stdlib-only Python with no external dependencies. The enriched dataset (`scripts/kev_edge_enriched.json`) and raw counts (`scripts/kev_edge_counts.json`) are regenerable from live CISA and NVD feeds.

---

## Limitations

### 1. Installed base is uncontrolled and cannot be normalized away

Fortinet's ~50% unit market share in the firewall segment means more deployed devices, more researcher attention, and more attacker ROI -- all of which inflate CVE counts independently of code quality. Installed-base figures are proprietary estimates that conflate unit vs. revenue share, so we publish no normalized score and fabricate none. This is the single most important limitation: the count spread (2-18) partly reflects popularity, and we cannot quantify how much.

### 2. KEV and EPSS are CVE-only -- silent fixes are invisible

Vulnerabilities that are silently patched, bundled into firmware updates without advisories, or never assigned a CVE do not appear in CISA KEV or EPSS. This systematically understates exposure for vendors with weaker disclosure practices. The dataset captures what is publicly trackable; it does not and cannot capture what vendors choose not to disclose.

### 3. Attribution is probabilistic and incomplete

UNC, UAT, and UTA designations are working hypotheses from private-sector analysts, not judicial findings. Many CVEs have zero public attribution -- absence of a named actor does not mean absence of a sophisticated adversary. China-nexus clusters share infrastructure and TTPs in ways that make clean separation impossible (Sophos's Pacific Rim report documented overlap across Volt Typhoon, APT31, and APT41). The attribution matrix reflects the public record as of 2026-06-18 and will shift as clusters are merged, split, or re-attributed.

---

*This summary draws from the full analyses: [CWE-ANALYSIS.md](CWE-ANALYSIS.md), [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md), [STATISTICS.md](STATISTICS.md), [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md), and per-vendor documents. All numbers are reproducible via the scripts in `scripts/`. This is data, not a ranking.*
