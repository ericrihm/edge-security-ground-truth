# Citrix (NetScaler ADC / NetScaler Gateway)

**Scope: NetScaler ADC and NetScaler Gateway (formerly Citrix ADC / Citrix Gateway / Citrix SD-WAN WANOP).** Remote access gateway and application delivery controller. Product is now owned by Cloud Software Group following the 2022 acquisition from Elliott Management. *(11 edge KEV entries, 2019--2025.)*

---

## KEV CVE Summary Table

All 11 CISA KEV-listed CVEs for Citrix NetScaler ADC/Gateway edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Published | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|-----------|----------|:--------:|:----------:|
| [CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781) | 9.8 | CWE-22 Path Traversal | 2019-12-27 | 2021-11-03 | Y | Y |
| [CVE-2020-8193](https://nvd.nist.gov/vuln/detail/CVE-2020-8193) | 6.5 | CWE-284 Improper Access Control | 2020-07-10 | 2021-11-03 | N | N |
| [CVE-2020-8195](https://nvd.nist.gov/vuln/detail/CVE-2020-8195) | 6.5 | CWE-20 Improper Input Validation | 2020-07-10 | 2021-11-03 | N | N |
| [CVE-2020-8196](https://nvd.nist.gov/vuln/detail/CVE-2020-8196) | 4.3 | CWE-284 Improper Access Control | 2020-07-10 | 2021-11-03 | N | N |
| [CVE-2022-27518](https://nvd.nist.gov/vuln/detail/CVE-2022-27518) | 9.8 | CWE-664 Improper Resource Lifetime Control | 2022-12-13 | 2022-12-13 | Y | N |
| [CVE-2023-3519](https://nvd.nist.gov/vuln/detail/CVE-2023-3519) | 9.8 | CWE-94 Code Injection | 2023-07-19 | 2023-07-19 | Y | Y |
| [CVE-2023-4966](https://nvd.nist.gov/vuln/detail/CVE-2023-4966) | 9.4 | CWE-119 Buffer Overflow | 2023-10-10 | 2023-10-18 | Y | Y |
| [CVE-2023-6548](https://nvd.nist.gov/vuln/detail/CVE-2023-6548) | 5.5 | CWE-94 Code Injection | 2024-01-17 | 2024-01-17 | Y | N |
| [CVE-2023-6549](https://nvd.nist.gov/vuln/detail/CVE-2023-6549) | 8.2 | CWE-119 Buffer Overflow | 2024-01-17 | 2024-01-17 | Y | N |
| [CVE-2025-6543](https://nvd.nist.gov/vuln/detail/CVE-2025-6543) | -- | CWE-119 Buffer Overflow | 2025-06-25 | 2025-06-30 | N | N |
| [CVE-2025-5777](https://nvd.nist.gov/vuln/detail/CVE-2025-5777) | -- | CWE-125 Out-of-bounds Read | 2025-06-17 | 2025-07-10 | N | Y |

**Summary statistics:** 11 KEV entries. 6 confirmed zero-days (55%) -- exploitation observed before or simultaneously with patch availability. 4 flagged by CISA for known ransomware campaigns (36%). The dominant CWE pattern is memory safety (CWE-119/CWE-125, 3 instances) and code injection (CWE-94, 2 instances), with access control (CWE-284) and path traversal (CWE-22) completing the picture. The record includes two of the most impactful edge CVEs ever documented: CVE-2019-19781 (33-day unpatched window, 80,000+ companies exposed) and CVE-2023-4966 (CitrixBleed -- Boeing, ICBC, DP World, Allen & Overy breached via LockBit).

---

## Market Position

NetScaler ADC and NetScaler Gateway are among the most widely deployed SSL-VPN and remote-access platforms in enterprise and government environments globally. Alongside Ivanti Connect Secure and Fortinet FortiGate, Citrix/NetScaler completes the dominant trio of edge remote-access products with sustained CISA KEV representation. The product is embedded deeply in healthcare, financial services, and federal agencies -- the same sectors repeatedly targeted by ransomware groups and nation-state actors hunting these devices specifically.

Cloud Software Group (the post-acquisition entity) reported approximately $1.7 billion in NetScaler-related revenue. The installed base skews toward large enterprises and government agencies with complex remote-access requirements, placing NetScaler in the same high-value-target category as F5 BIG-IP but with a stronger focus on virtual desktop infrastructure (VDI) and application virtualization gateways.

---

## Timeline

### 2019: CVE-2019-19781 -- The Original Citrix Mass Exploitation

**CVE-2019-19781** (CVSS 9.8, path traversal) is one of the most impactful edge appliance CVEs ever documented and a defining event in the history of enterprise perimeter security. The flaw -- a path traversal vulnerability in Citrix ADC, Gateway, and SD-WAN WANOP -- enables unauthenticated remote code execution via directory traversal to write arbitrary files to the web-accessible directory, then execute them as Perl scripts.

Citrix disclosed it on [December 17, 2019](https://support.citrix.com/article/CTX267027). A patch did not exist until January 19, 2020 -- a **33-day window** during which tens of thousands of devices were exposed with no vendor-supplied fix. During this window, Citrix provided only mitigation guidance (a responder policy configuration), not a patch.

[Mass exploitation began in January 2020](https://unit42.paloaltonetworks.com/threat-brief-cve-2019-19781-citrix-adc-and-citrix-gateway-vulnerability/) before patches were available, making this a confirmed zero-day. Multiple threat actors deployed webshells, cryptominers, and backdoors at scale. [CISA issued an advisory](https://www.cisa.gov/news-events/alerts/2020/01/13/critical-vulnerability-unpatched-citrix-application-delivery-controller) warning of active exploitation. Researchers estimated [over 80,000 companies in 158 countries were vulnerable](https://www.zdnet.com/article/over-80000-companies-may-be-affected-by-citrix-vulnerability/) at peak exposure. FireEye documented exploitation by [APT41](https://www.mandiant.com/resources/blog/apt41-dual-espionage-and-cyber-crime-operation) (China-nexus dual espionage/criminal group) within the first week of mass exploitation.

The 33-day unpatched window combined with trivial exploitation prerequisites enabled a level of opportunistic compromise that defined the threat model for the entire edge appliance product category. CISA added it to KEV on November 3, 2021 -- retroactively, as the catalog did not exist during the initial exploitation. CISA flagged it for known ransomware use.

EPSS score: 0.99999 (99.998th percentile) -- among the highest in the entire EPSS database.

### 2020: The Access Control Trio

Three CVEs disclosed simultaneously on [July 10, 2020](https://support.citrix.com/article/CTX276688) affect the Citrix ADC and Gateway management interface:

**CVE-2020-8193** (CVSS 6.5, improper access control) allows unauthenticated access to certain URL endpoints in the management interface through improper access control enforcement.

**CVE-2020-8195** (CVSS 6.5, improper input validation) allows authenticated low-privilege users to access sensitive information through improperly validated input in the management interface -- effectively an information-disclosure primitive usable after CVE-2020-8193 provides unauthenticated access.

**CVE-2020-8196** (CVSS 4.3, improper access control) allows authenticated low-privilege users to retrieve sensitive data from the management interface, complementing CVE-2020-8195 through a different access-control bypass path.

All three were added to KEV on November 3, 2021 (the catalog launch date). While individually moderate in severity, the trio forms a chain: CVE-2020-8193 provides unauthenticated entry, and CVE-2020-8195/8196 escalate access to sensitive information. The pattern mirrors the [Juniper J-Web chain](./Juniper.md) dynamic where individually moderate CVEs combine to meaningful operational impact.

EPSS scores: CVE-2020-8193 (0.884, 99.75th), CVE-2020-8195 (0.333, 98.15th), CVE-2020-8196 (0.263, 97.75th).

### 2022: CVE-2022-27518 -- NSA-Attributed Zero-Day

**CVE-2022-27518** (CVSS 9.8, improper control of a resource through its lifetime) is an unauthenticated remote code execution vulnerability in Citrix ADC and Gateway when configured as a SAML service provider or identity provider. Citrix disclosed and patched it on [December 13, 2022](https://support.citrix.com/article/CTX474995); [CISA added it to KEV the same day](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- same-day KEV listing confirms exploitation was already active at disclosure, making this a confirmed zero-day.

The [NSA issued a dedicated advisory](https://media.defense.gov/2022/Dec/13/2003131586/-1/-1/0/CSA-APT5-CITRIXADC-V1.PDF) attributing exploitation to **APT5** (also known as Manganese / Keyhole Panda / UNC2630), a China-nexus espionage group with a long history of targeting telecommunications and technology companies. The NSA advisory provided specific indicators of compromise and detection guidance, including looking for unauthorized modifications to NetScaler configuration files and unexpected SAML configuration changes.

The APT5 attribution makes CVE-2022-27518 the most precisely attributed nation-state exploitation of a Citrix product in the KEV record.

### 2023: The Year of Citrix Zero-Days

2023 produced four exploited Citrix vulnerabilities in approximately six months -- the densest cluster in the product line's KEV history.

#### CVE-2023-3519 -- Pre-Patch Zero-Day, Thousands Backdoored (July 2023)

**CVE-2023-3519** (CVSS 9.8, code injection) is an unauthenticated remote code execution vulnerability in NetScaler ADC and Gateway. Citrix patched it on [July 18, 2023](https://support.citrix.com/article/CTX561482). CISA added it to the KEV catalog the following day -- the simultaneous KEV listing confirmed the vulnerability had been exploited before the patch was released.

[CISA issued a dedicated advisory](https://www.cisa.gov/news-events/alerts/2023/07/20/cisa-releases-cybersecurity-advisory-threat-actors-exploiting-citrix-software-as-zero-day) reporting that threat actors had backdoored at least **2,000 NetScaler devices** before a patch existed, planting webshells and PHP backdoors. [Mandiant tracked the exploitation](https://www.mandiant.com/resources/blog/citrix-bleed-exploitation) to China-nexus actors designated UNC5027 and associated clusters. [Fox-IT (NCC Group)](https://www.fox-it.com/) independently scanned for webshells and identified approximately **1,900 backdoored devices** still compromised weeks after patches were available. Post-patch, Shadowserver and others documented exploitation attempts continuing at scale against unpatched devices.

The pre-patch exploitation window for CVE-2023-3519 mirrors CVE-2019-19781 but in a more compressed timeframe -- adversaries had clearly established active access to zero-days affecting this product line. CISA flagged it for known ransomware campaign use.

EPSS score: 0.993 (99.93rd percentile).

#### CVE-2023-4966 -- CitrixBleed: Boeing, ICBC, DP World, Allen & Overy (October 2023)

**CVE-2023-4966** (CVSS 9.4, buffer overflow / information disclosure), publicly named **CitrixBleed**, is the most consequential Citrix vulnerability in terms of documented downstream impact. The flaw enables unauthenticated session token leakage from NetScaler ADC and Gateway memory. An attacker can hijack any authenticated session without credentials, **bypassing MFA entirely** -- making it functionally equivalent to possessing every user's session cookie simultaneously.

Citrix disclosed and patched it on [October 10, 2023](https://support.citrix.com/article/CTX579459), initially assigning a "High" severity rating. [Mandiant reported](https://www.mandiant.com/resources/blog/citrix-bleed-exploitation) that exploitation had been active since at least late August 2023 -- approximately six weeks before the patch -- making this a confirmed zero-day. [CISA added it to KEV on October 18, 2023](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

The severity rating controversy is notable: Citrix initially characterized CVE-2023-4966 as "High" rather than "Critical," a classification [widely criticized by researchers](https://www.bleepingcomputer.com/news/security/critical-citrix-bleed-vulnerability-exploited-by-lockbit-ransomware/) given that session hijack with MFA bypass in a gateway product is functionally equivalent to a critical compromise primitive. The mismatch between initial vendor severity and real-world impact contributed to slower organizational prioritization during the window that mattered most.

Within weeks of public disclosure, **LockBit ransomware operators leveraged CitrixBleed** in a series of high-profile attacks:

- **Boeing:** LockBit affiliate exploited CitrixBleed for initial access, leading to data exfiltration and ransomware deployment ([SecurityWeek](https://www.securityweek.com/lockbit-ransomware-exploiting-citrix-bleed-vulnerability/))
- **Industrial and Commercial Bank of China (ICBC):** The breach caused disruption to **U.S. Treasury bond markets** -- one of the most significant financial infrastructure impacts from a ransomware incident ([Reuters](https://www.reuters.com/))
- **DP World Australia:** Port operations disrupted, affecting shipping container logistics ([BleepingComputer](https://www.bleepingcomputer.com/))
- **Allen & Overy:** Major international law firm breached via CitrixBleed ([BleepingComputer](https://www.bleepingcomputer.com/))

[CISA, FBI, and ACSC issued a joint advisory (AA23-325A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) in November 2023 detailing exploitation patterns and urging immediate patching. The speed from public patch to mass ransomware exploitation -- measured in days -- reflects CitrixBleed's accessibility as an exploitation primitive once PoC code circulated.

EPSS score: 0.99999 (99.993rd percentile).

#### CVE-2023-6548 and CVE-2023-6549 -- Year-End Zero-Days (January 2024)

**CVE-2023-6548** (CVSS 5.5, code injection) is an authenticated remote code execution vulnerability in the NetScaler ADC and Gateway management interface. It requires access to NSIP, CLIP, or SNIP with management interface access -- a lower-impact primitive than the pre-auth bugs but still dangerous when chained with credential theft.

**CVE-2023-6549** (CVSS 8.2, buffer overflow) is an unauthenticated denial-of-service and potential information-disclosure vulnerability when the appliance is configured as a Gateway or AAA virtual server. The buffer overflow can cause service disruption and may enable further exploitation.

Both were disclosed on [January 16, 2024](https://support.citrix.com/article/CTX584986) and added to KEV the following day -- same-day confirmation of active exploitation, making both confirmed zero-days. Citrix's advisory acknowledged active exploitation in the wild. These two CVEs close out a six-month period (July 2023 -- January 2024) in which Citrix disclosed four actively exploited zero-days, three of which enabled pre-auth compromise.

### 2025: Continued Exploitation

**CVE-2025-6543** (CWE-119, buffer overflow) was published on June 25, 2025 and [added to KEV on June 30, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). CVSS score is pending NVD assignment. The vulnerability affects NetScaler ADC and Gateway, continuing the memory-safety pattern documented in CVE-2023-4966 and CVE-2023-6549.

**CVE-2025-5777** (CWE-125, out-of-bounds read) was published on June 17, 2025 and [added to KEV on July 10, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). CVSS score is pending NVD assignment. CISA flagged it for known ransomware campaign use. The out-of-bounds read (CWE-125) is a related but distinct memory-safety weakness from the buffer overflows (CWE-119) that dominate the Citrix record, potentially enabling sensitive data leakage from process memory -- an exploitation pattern analogous to CitrixBleed's session-token exfiltration.

EPSS score for CVE-2025-5777: 0.999 (99.96th percentile) -- among the highest scores in the dataset, reflecting active exploitation.

---

## CWE Weakness Profile

| Category | Count | CVEs |
|----------|------:|------|
| **Memory Safety** (CWE-119, CWE-125) | 3 | CVE-2023-4966, CVE-2023-6549, CVE-2025-6543 (+ CWE-125: CVE-2025-5777) |
| **Code Injection** (CWE-94) | 2 | CVE-2023-3519, CVE-2023-6548 |
| **Access Control** (CWE-284) | 2 | CVE-2020-8193, CVE-2020-8196 |
| **Path Traversal** (CWE-22) | 1 | CVE-2019-19781 |
| **Input Validation** (CWE-20) | 1 | CVE-2020-8195 |
| **Resource Lifetime** (CWE-664) | 1 | CVE-2022-27518 |

**Pattern:** Memory safety dominates the 2023--2025 window, with buffer overflows and out-of-bounds reads producing the highest-impact exploitation events (CitrixBleed's session-token leakage is a buffer over-read). Code injection appeared in both the most-compromised zero-day (CVE-2023-3519) and the management-interface variant (CVE-2023-6548). The foundational CVE-2019-19781 is a path traversal -- the same CWE class that anchors [Fortinet's CVE-2018-13379](./Fortinet.md) and [Ivanti's CVE-2019-11510](./Ivanti.md), suggesting that path traversal in web-facing management interfaces is a cross-vendor systemic weakness in this product category. See [CWE-ANALYSIS.md](CWE-ANALYSIS.md) for cross-vendor comparison.

---

## Threat Actor Attribution

### China-Nexus Actors

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **APT5** (Manganese / Keyhole Panda / UNC2630) | CVE-2022-27518 | [NSA advisory](https://media.defense.gov/2022/Dec/13/2003131586/-1/-1/0/CSA-APT5-CITRIXADC-V1.PDF) |
| **APT41** (Winnti / Wicked Panda) | CVE-2019-19781 | [Mandiant / FireEye](https://www.mandiant.com/resources/blog/apt41-dual-espionage-and-cyber-crime-operation) |
| **UNC5027** and associated clusters | CVE-2023-3519 | [Mandiant](https://www.mandiant.com/resources/blog/citrix-bleed-exploitation) |

Citrix products have been targeted by at least three distinct China-nexus clusters, each exploiting different CVEs across different years. APT5's exploitation of CVE-2022-27518 is the most precisely attributed, with NSA providing a dedicated advisory -- a level of specificity typically reserved for the highest-priority espionage operations.

### Ransomware Operators

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **LockBit** | CVE-2023-4966 (CitrixBleed) | [CISA AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a), [SecurityWeek](https://www.securityweek.com/lockbit-ransomware-exploiting-citrix-bleed-vulnerability/) |
| **Multiple operators** | CVE-2019-19781 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **Multiple operators** | CVE-2023-3519 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **Multiple operators** | CVE-2025-5777 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

LockBit's exploitation of CitrixBleed produced the most consequential downstream impacts in the entire edge-security dataset: disruption to U.S. Treasury bond markets (ICBC), port operations (DP World), and data exfiltration from a major law firm (Allen & Overy) and aerospace manufacturer (Boeing). The breadth and severity of these impacts from a single vulnerability-ransomware combination is unmatched by any other entry in this repository.

See [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md) for cross-vendor attribution analysis.

---

## EPSS Context

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2019-19781 | 0.99999 | 99.998th |
| CVE-2023-4966 | 0.99999 | 99.993rd |
| CVE-2025-5777 | 0.99897 | 99.963rd |
| CVE-2023-3519 | 0.99343 | 99.933rd |
| CVE-2020-8193 | 0.88411 | 99.750th |
| CVE-2023-6549 | 0.57633 | 98.961st |
| CVE-2020-8195 | 0.33263 | 98.152nd |
| CVE-2020-8196 | 0.26333 | 97.745th |
| CVE-2025-6543 | 0.09756 | 94.920th |
| CVE-2022-27518 | 0.06931 | 93.281st |
| CVE-2023-6548 | 0.03191 | 86.446th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

The two historically defining CVEs (CVE-2019-19781 and CVE-2023-4966) carry maximum EPSS scores, reflecting near-universal exploit availability and sustained scanning activity years after disclosure. CVE-2022-27518's relatively lower EPSS (0.069) despite its CVSS 9.8 rating reflects the SAML-specific configuration prerequisite -- not all NetScaler deployments use SAML.

---

## Disclosure Assessment

### Positive Indicators

- **No documented silent patching.** Citrix has not been documented shipping security fixes without issuing corresponding advisories.
- **Coordinated multi-agency response.** The CVE-2023-4966 (CitrixBleed) response involved simultaneous advisories from CISA, FBI, and ACSC. The CVE-2022-27518 response included an NSA advisory.
- **Advisory availability for all KEV entries.** All 11 CVEs have corresponding vendor advisories with affected-version matrices.

### Concerns

- **33-day unpatched window (CVE-2019-19781).** The gap between December 17, 2019 disclosure and January 19, 2020 patch is the longest advisory-to-patch gap for a Critical-severity edge CVE in this dataset. Citrix provided only mitigation guidance during this window -- no patch.
- **Severity miscalibration (CVE-2023-4966).** Citrix initially rated CitrixBleed as "High" rather than "Critical" despite the vulnerability enabling unauthenticated session hijack with MFA bypass on a remote-access gateway. Researchers and downstream incident responders [publicly criticized this characterization](https://www.bleepingcomputer.com/news/security/critical-citrix-bleed-vulnerability-exploited-by-lockbit-ransomware/). The understatement likely contributed to slower patching during the critical window.
- **Zero-day cluster density (2023).** Four exploited zero-days in six months (July 2023 -- January 2024) suggests either sustained adversary investment in Citrix zero-day research or systemic weaknesses in the codebase that yield exploitable bugs at high rates. Either interpretation is concerning for defenders relying on the product.
- **Ownership transition uncertainty.** Cloud Software Group's acquisition introduced new organizational complexity. The impact on PSIRT response times, patch cadence, and security investment is not yet clearly visible in the data.

---

## Defender Implications

**1. Treat NetScaler as a persistent high-value target with a documented zero-day cadence.** Six of 11 KEV entries were zero-days. The 2023 cluster produced four zero-days in six months. Organizations running NetScaler for remote access should maintain pre-positioned incident response playbooks, assume that the next advisory may disclose exploitation already in progress, and plan for emergency patching within hours -- not days -- of any Critical advisory.

**2. Invalidate all sessions after any Citrix patch cycle.** CitrixBleed (CVE-2023-4966) demonstrated that session tokens can be stolen from device memory before patching, and those tokens remain valid after the patch is applied. [CISA's advisory (AA23-325A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) recommends invalidating all active sessions and rotating all credentials after patching any NetScaler vulnerability -- not just CitrixBleed. This should be standard operating procedure for all NetScaler patch events.

**3. Hunt for webshells on every NetScaler device in the fleet.** CVE-2023-3519 resulted in at least 2,000 backdoored devices with webshells that survived patching. [Fox-IT's scanning](https://www.fox-it.com/) found approximately 1,900 compromised devices weeks after patches were available. Run file-integrity checks on the web-accessible directories of all NetScaler appliances, looking for unexpected PHP files, modified configuration files, and unauthorized cron jobs. The Citrix Integrity Checker Tool should be supplemented with external validation.

**4. Segment the management interface and restrict SAML configurations.** CVE-2022-27518 required SAML SP/IdP configuration; CVE-2023-6548 required management interface access; the 2020 trio targeted the management interface. Restrict management access to dedicated out-of-band networks with strict ACLs. Audit SAML configurations and disable unused authentication methods. Ensure that no management interface is reachable from the internet.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [Advisory on CVE-2019-19781](https://www.cisa.gov/news-events/alerts/2020/01/13/critical-vulnerability-unpatched-citrix-application-delivery-controller); [Advisory on CVE-2023-3519](https://www.cisa.gov/news-events/alerts/2023/07/20/cisa-releases-cybersecurity-advisory-threat-actors-exploiting-citrix-software-as-zero-day); [AA23-325A (CitrixBleed + LockBit)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a)
- **NSA:** [APT5 exploitation of CVE-2022-27518](https://media.defense.gov/2022/Dec/13/2003131586/-1/-1/0/CSA-APT5-CITRIXADC-V1.PDF)
- **Mandiant / Google Threat Intelligence Group:** [Citrix Bleed exploitation analysis](https://www.mandiant.com/resources/blog/citrix-bleed-exploitation); [APT41 campaign reporting](https://www.mandiant.com/resources/blog/apt41-dual-espionage-and-cyber-crime-operation)
- **Citrix PSIRT:** [CTX267027](https://support.citrix.com/article/CTX267027) (CVE-2019-19781); [CTX276688](https://support.citrix.com/article/CTX276688) (2020 trio); [CTX474995](https://support.citrix.com/article/CTX474995) (CVE-2022-27518); [CTX561482](https://support.citrix.com/article/CTX561482) (CVE-2023-3519); [CTX579459](https://support.citrix.com/article/CTX579459) (CVE-2023-4966); [CTX584986](https://support.citrix.com/article/CTX584986) (CVE-2023-6548/6549)
- **Unit 42:** [CVE-2019-19781 threat brief](https://unit42.paloaltonetworks.com/threat-brief-cve-2019-19781-citrix-adc-and-citrix-gateway-vulnerability/)
- **Fox-IT / NCC Group:** CVE-2023-3519 webshell scanning
- **SecurityWeek:** [LockBit ransomware exploiting CitrixBleed](https://www.securityweek.com/lockbit-ransomware-exploiting-citrix-bleed-vulnerability/)
- **BleepingComputer:** [CitrixBleed LockBit exploitation](https://www.bleepingcomputer.com/news/security/critical-citrix-bleed-vulnerability-exploited-by-lockbit-ransomware/); DP World and Allen & Overy reporting
- **ZDNet:** [80,000+ companies affected by CVE-2019-19781](https://www.zdnet.com/article/over-80000-companies-may-be-affected-by-citrix-vulnerability/)
- **Reuters:** ICBC Treasury market disruption reporting
- **NVD:** CVSS scoring and CWE classification for all 11 CVEs
- **FIRST.org EPSS:** [Exploit Prediction Scoring System data](https://api.first.org/data/v1/epss)
