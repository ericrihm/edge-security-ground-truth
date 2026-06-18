# Numbers That Matter

Fifteen statistics from [107 exploited edge-device CVEs](../README.md) across 11 vendors, 2020--2026. Every number is reproducible from CISA KEV data and the scripts in this repository.

---

## 0 days

**Median time-to-exploit for edge CVEs published in 2024.**

For vulnerabilities disclosed in 2024, exploitation was confirmed the same day as public disclosure -- or before it. The median TTE has collapsed from years (pre-2020) to months (2021) to days (2022) to zero (2024). There is no patch window left. ([TIME-TO-EXPLOIT.md](./TIME-TO-EXPLOIT.md), Table: Median TTE by NVD Publication Year)

---

## 43%

**The share of exploited edge CVEs associated with known ransomware campaigns.**

46 of 107 CISA KEV-listed edge CVEs are flagged as used in ransomware operations. Nearly half of all edge exploitation feeds directly into the ransomware economy -- Akira, Fog, LockBit, Helldown, and others. Fortinet alone accounts for 12 of the 46 (26%). ([TIME-TO-EXPLOIT.md](./TIME-TO-EXPLOIT.md), Ransomware Association)

---

## 71%

**Three bug classes account for 71% of all exploited edge CVEs.**

Authentication bypass (28%), injection (22%), and memory corruption (21%). These are not exotic zero-days requiring novel research. They are the same weakness families OWASP warned about in 2003 and CISA's Secure-by-Design initiative targets today. They keep shipping in devices whose entire purpose is security. ([CWE-ANALYSIS.md](./CWE-ANALYSIS.md), Executive Summary)

---

## 10 of 11

**Number of vendors with at least one confirmed zero-day.**

Only Zyxel has no confirmed pre-disclosure exploitation. The other ten -- Fortinet, Ivanti, Cisco, Palo Alto, SonicWall, Citrix, Juniper, F5, Sophos, and Check Point -- all have at least one CVE that was exploited before a patch existed. Zero-days are not a Fortinet problem or an Ivanti problem. They are an edge-device problem. ([TIME-TO-EXPLOIT.md](./TIME-TO-EXPLOIT.md), Zero-Days by Vendor)

---

## 7 of 11

**Number of vendors that shipped a path-traversal bug (CWE-22) that was exploited in the wild.**

Citrix, F5, Fortinet, Ivanti, Juniper, SonicWall, and Zyxel all shipped products where an attacker could traverse out of a directory and reach files they should never touch. This is a basic file-path sanitization failure. It is functionally universal to the industry. ([CWE-ANALYSIS.md](./CWE-ANALYSIS.md), Universal CWEs)

---

## 98%

**Percentage of vendor pairs whose confidence intervals overlap.**

Of 55 possible vendor-pair comparisons, 54 have overlapping Poisson confidence intervals. Only Fortinet vs. Check Point (18 vs. 2) is statistically separable. Every other ranking you have seen -- Cisco vs. Palo Alto, Ivanti vs. SonicWall, Juniper vs. F5 -- is noise at these sample sizes. ([STATISTICS.md](./STATISTICS.md), Section 7: Poisson Confidence Intervals)

---

## 2 to 18

**The full range of exploited edge CVEs across all eleven vendors over six years.**

Check Point has 2. Fortinet has 18. Everyone else falls between 6 and 13. Under a consistent scope rule applied identically, no vendor is dramatically cleaner than the others. Anyone selling you "vendor X is secure, vendor Y isn't" on these counts is selling you a confidence interval they haven't computed. ([README.md](../README.md), Main Table)

---

## 35%

**Authentication failures as a share of exploited edge CVEs published since 2024 -- nearly triple the pre-2019 rate.**

Auth/access-control bugs went from 12% of exploited CVEs before 2019 to 35% in 2024 and beyond. Edge vendors are shipping more products with authentication gaps, not fewer. The trend is moving in the opposite direction from CISA's Secure-by-Design goals. ([CWE-ANALYSIS.md](./CWE-ANALYSIS.md), Section (c): CWE Evolution Over Time)

---

## 40%

**The proportion of edge CVEs exploited within one week of disclosure.**

43 of 107 CVEs were added to CISA KEV within 7 days of their NVD publication date. This is a conservative measure -- actual exploitation often precedes the KEV listing. Monthly patching cycles are structurally incompatible with this attack tempo. ([TIME-TO-EXPLOIT.md](./TIME-TO-EXPLOIT.md), Histogram)

---

## 1 to 55

**The range of implied KEV counts if exploitation were proportional to market share.**

Fortinet holds an estimated 35--50% of the edge-appliance market by unit volume. If KEV counts tracked installed base, Fortinet should have 37--54 entries, not 18. Meanwhile, Ivanti (3--5% share) should have 3--5 entries, not 13. The observed distribution is more uniform than market share predicts -- the chi-squared fit gets worse, not better, after adjustment. Raw counts neither reward nor penalize the market leader the way you would expect. ([MARKET-SHARE-SENSITIVITY.md](./MARKET-SHARE-SENSITIVITY.md), Sections 5--6)

---

## 44%

**The share of 2024 zero-days that targeted security and edge appliances.**

Per Mandiant/GTIG, nearly half of all zero-day vulnerabilities exploited in 2024 hit the devices that are supposed to protect everything else. The perimeter is not just a target -- it is the preferred target. ([README.md](../README.md), citing Mandiant/GTIG Time-to-Exploit data)

---

## 8

**Fortinet authentication/access-control CVEs exploited in the wild, spanning 2018--2026.**

Eight of Fortinet's 18 KEV entries (44%) are authentication failures. This is not a single bad release or an unlucky quarter. It is a seven-year pattern suggesting the auth subsystem in FortiOS lacks design-level guarantees. Juniper shows the same pattern in miniature: 7 of 8 (88%) are auth/access-control. ([CWE-ANALYSIS.md](./CWE-ANALYSIS.md), Section (b): Per-Vendor CWE Distribution)

---

## 240,000

**Devices potentially exposed by SonicWall's own cloud-backup breach.**

In September 2025, SonicWall's MySonicWall cloud-backup service was breached by a state-sponsored actor, exposing encrypted credentials, VPN configurations, and network topology. Initially reported as affecting less than 5% of customers, later revised to all cloud-backup users. The Marquis Software ransomware attack on 74 U.S. banks was attributed to this breach. Your vendor's infrastructure is part of your attack surface. ([VENDOR-MATRIX.md](./VENDOR-MATRIX.md), SonicWall profile; [SonicWall.md](./SonicWall.md))

---

## 5 years

**Duration of the documented Chinese state campaign against Sophos edge devices.**

Sophos published "Pacific Rim" in October 2024, disclosing a five-year timeline of overlapping China-nexus campaigns (with Volt Typhoon, APT31, and APT41 TTP overlap) targeting their firewall platform. No other firewall vendor has published a comparable multi-year campaign disclosure. Sophos's transparency is the exception; the targeting is probably the norm. ([VENDOR-MATRIX.md](./VENDOR-MATRIX.md), Sophos profile; [README.md](../README.md))

---

## 2.25x

**Kahneman and Tversky's loss-aversion coefficient.**

A dollar lost hurts 2.25 times as much as a dollar gained feels good. This is how much more a breach through an unpatched edge device hurts your organization than the equivalent savings from deferring the patching investment felt like a win. The math of "we'll get to it next quarter" is asymmetric, and it does not favor the defender. (Tversky & Kahneman, 1992, *Journal of Risk and Uncertainty*)

---

These numbers are reproducible. Run the scripts yourself:

```bash
python3 scripts/build_kev_counts.py            # Rebuild counts from live CISA feed
python3 scripts/analyze_tte.py -f markdown      # Time-to-exploit analysis
python3 scripts/analyze_cwe.py -f markdown      # CWE weakness patterns
python3 scripts/analyze_statistics.py -f markdown  # Statistical framework
```

All scripts are stdlib-only Python with no external dependencies. Data sources: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [NVD](https://nvd.nist.gov/), [FIRST EPSS](https://www.first.org/epss/), [Mandiant/GTIG](https://cloud.google.com/blog/topics/threat-intelligence).
