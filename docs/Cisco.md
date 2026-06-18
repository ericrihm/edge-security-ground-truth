# Cisco

**Scope: Cisco ASA / FTD firewalls.** Cisco's portfolio-wide KEV total spans IOS, switches, routers, and SD-WAN -- it is *not* attributed to ASA/FTD here. *(13 ASA/FTD edge KEV entries, 2014--2025.)*

---

## Market Position

Cisco is the world's dominant enterprise networking and perimeter security vendor. Its Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) product lines are embedded in government agencies, critical infrastructure operators, and Fortune 500 networks on every continent. That ubiquity is a double-edged sword: any exploitable vulnerability carries an outsized blast radius, and Cisco ASA/FTD in particular has become a high-value target for state-sponsored threat actors willing to invest in custom, product-specific tooling.

---

## Complete KEV CVE Table

All 13 CISA KEV-listed vulnerabilities affecting Cisco ASA/FTD edge appliances, ordered by KEV date:

| CVE | CVSS | CWE Class | KEV Added | Zero-Day | Ransomware |
|-----|------|-----------|-----------|:--------:|:----------:|
| [CVE-2014-2120](https://nvd.nist.gov/vuln/detail/CVE-2014-2120) | 5.4 (Medium) | CWE-79 XSS | 2024-11-12 | N | N |
| [CVE-2016-6366](https://nvd.nist.gov/vuln/detail/CVE-2016-6366) | 8.8 (High) | CWE-120 Buffer Overflow | 2022-05-24 | Y | N |
| [CVE-2016-6367](https://nvd.nist.gov/vuln/detail/CVE-2016-6367) | 7.8 (High) | CWE-77 Command Injection | 2022-05-24 | Y | N |
| [CVE-2018-0296](https://nvd.nist.gov/vuln/detail/CVE-2018-0296) | 7.5 (High) | CWE-20 Improper Input Validation | 2021-11-03 | N | N |
| [CVE-2020-3259](https://nvd.nist.gov/vuln/detail/CVE-2020-3259) | 7.5 (High) | CWE-200 Information Disclosure | 2024-02-15 | N | N |
| [CVE-2020-3452](https://nvd.nist.gov/vuln/detail/CVE-2020-3452) | 7.5 (High) | CWE-20 Improper Input Validation | 2021-11-03 | N | N |
| [CVE-2020-3580](https://nvd.nist.gov/vuln/detail/CVE-2020-3580) | 6.1 (Medium) | CWE-79 XSS | 2021-11-03 | N | N |
| [CVE-2023-20269](https://nvd.nist.gov/vuln/detail/CVE-2023-20269) | 5.0 (Medium) | CWE-288 Auth Bypass (Alt Path) | 2023-09-13 | Y | Y |
| [CVE-2024-20353](https://nvd.nist.gov/vuln/detail/CVE-2024-20353) | 8.6 (High) | CWE-835 Infinite Loop | 2024-04-24 | Y | N |
| [CVE-2024-20359](https://nvd.nist.gov/vuln/detail/CVE-2024-20359) | 6.0 (Medium) | CWE-94 Code Injection | 2024-04-24 | Y | N |
| [CVE-2024-20481](https://nvd.nist.gov/vuln/detail/CVE-2024-20481) | 5.8 (Medium) | CWE-772 Resource Leak | 2024-10-24 | N | N |
| [CVE-2025-20333](https://nvd.nist.gov/vuln/detail/CVE-2025-20333) | 9.9 (Critical) | CWE-120 Buffer Overflow | 2025-09-25 | Y | N |
| [CVE-2025-20362](https://nvd.nist.gov/vuln/detail/CVE-2025-20362) | 6.5 (Medium) | CWE-862 Missing Authorization | 2025-09-25 | Y | N |

**Summary:** 13 edge KEV entries spanning 2014--2025. Seven were exploited as zero-days (before or simultaneous with disclosure). One CVE (CVE-2023-20269) has confirmed ransomware exploitation. CVSS ranges from 5.0 to 9.9; CWE classes include buffer overflow (3), input validation (2), XSS (2), command/code injection (3), authentication bypass (1), information disclosure (1), and resource management (1).

---

## Timeline

### Pre-2020: The Shadow Brokers and Legacy ASA

The earliest CVEs in Cisco's edge KEV record trace to the ASA platform's exposure during the Shadow Brokers leak era.

**CVE-2016-6366** (CVSS 8.8) and **CVE-2016-6367** (CVSS 7.8) were disclosed on August 18, 2016, after the Shadow Brokers group [leaked offensive tools attributed to the NSA's Equation Group](https://arstechnica.com/information-technology/2016/08/cisco-confirms-nsa-linked-zeroday-targeted-its-firewalls-for-years/). CVE-2016-6366 (EXTRABACON) is a buffer overflow in the SNMP implementation of ASA that enables unauthenticated remote code execution. CVE-2016-6367 (EPICBANANA) is a CLI command injection that enables local privilege escalation. Both were true zero-days -- actively used in espionage operations before Cisco was aware of them. Cisco [confirmed the vulnerabilities and released patches in August 2016](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp); CISA added them to the KEV catalog retroactively on May 24, 2022.

**CVE-2014-2120** (CVSS 5.4) is a cross-site scripting flaw in the ASA WebVPN login page, [originally disclosed in March 2014](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa). Despite its age and moderate severity, it was not added to the KEV catalog until November 12, 2024 -- a decade later -- after [CISA confirmed renewed exploitation in the wild](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), likely against legacy unpatched ASA deployments. This is a case study in the long tail of edge device vulnerability: low-severity bugs on internet-facing infrastructure remain exploitable for years when devices are not upgraded.

**CVE-2018-0296** (CVSS 7.5) is an improper input validation flaw in the ASA web interface that enables [unauthenticated directory traversal and denial-of-service](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd). Disclosed June 7, 2018, it was added to KEV on November 3, 2021 after Cisco confirmed active exploitation. At the time of disclosure, [researchers observed mass scanning of ASA devices](https://www.bleepingcomputer.com/news/security/cisco-patches-actively-exploited-bug-in-asa-and-ftd-devices/) within days.

### 2020--2022: Information Leaks and Credential Harvesting

The 2020-era vulnerabilities share a common pattern: information leakage from the ASA/FTD web services interface, creating a credential-harvesting surface.

**CVE-2020-3452** (CVSS 7.5) is a [path traversal in the ASA/FTD web services interface](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86) allowing unauthenticated read access to sensitive files on the target system. Disclosed July 22, 2020; added to KEV November 3, 2021. EPSS score of 0.999 reflects near-universal exploit availability. Rapid7 and others documented [widespread scanning immediately after disclosure](https://www.rapid7.com/blog/post/2020/07/23/cve-2020-3452-cisco-asa-ftd-read-only-path-traversal-vulnerability-what-you-need-to-know/).

**CVE-2020-3580** (CVSS 6.1) is a [stored cross-site scripting vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-FCB3vPZe) in the ASA/FTD web management interface. Disclosed October 21, 2020; added to KEV November 3, 2021. While lower-severity than the path traversal, XSS on a firewall management interface enables session hijacking and configuration exfiltration.

**CVE-2020-3259** (CVSS 7.5) is an [information disclosure vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB) in ASA/FTD that could allow an unauthenticated remote attacker to retrieve memory contents, potentially including credentials and session tokens. Originally disclosed May 6, 2020, it was not added to KEV until February 15, 2024 -- nearly four years later. The delayed KEV addition coincided with [Truesec reporting](https://www.truesec.com/hub/blog/akira-ransomware-and-exploitation-of-cisco-anyconnect-vulnerability-cve-2020-3259) that the Akira ransomware group was weaponizing CVE-2020-3259 to harvest VPN credentials from Cisco AnyConnect/ASA deployments.

### 2023--2024: Brute-Force VPN Abuse and the ArcaneDoor Campaign

This period marks the escalation from opportunistic scanning to targeted state-actor campaigns against ASA/FTD.

**CVE-2023-20269** (CVSS 5.0) is an [authentication bypass in the remote access VPN feature of ASA and FTD](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC). It allows an unauthenticated remote attacker to conduct brute-force credential attacks or establish a clientless SSL VPN session using an unauthorized account. Disclosed September 6, 2023; added to KEV September 13, 2023 -- a seven-day gap confirming exploitation was already active at disclosure. [Rapid7 documented](https://www.rapid7.com/blog/post/2023/09/07/etr-exploitation-of-cisco-asa-ssl-vpn/) multiple ransomware groups (including Akira and LockBit affiliates) leveraging CVE-2023-20269 for initial access, making this the only Cisco ASA/FTD KEV entry with confirmed ransomware utilization.

**CVE-2024-20353** (CVSS 8.6) and **CVE-2024-20359** (CVSS 6.0) -- the **ArcaneDoor** zero-days. Disclosed simultaneously on April 24, 2024, both were already being exploited by the state-sponsored actor cluster designated **UAT4356** (Cisco Talos) / **STORM-1849** (Microsoft). The ArcaneDoor campaign is the defining incident in Cisco's recent security record.

CVE-2024-20353 is an [infinite loop in the ASA/FTD management and VPN web server](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-websrvs-dos-X8gNucA2) that enables an unauthenticated remote attacker to trigger a device reload. CVE-2024-20359 enables [local code execution that persists across reboots](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-rce-FLsNXF4h) via a legacy VPN client pre-load hook. Chained together, the actor deployed:

- **Line Dancer** -- a memory-resident shellcode interpreter that evades disk-based forensics, enabling command execution, packet capture, and logging manipulation without writing to disk.
- **Line Runner** -- a persistent backdoor that survived device reboots by writing to `disk0` and loading via CVE-2024-20359's VPN client pre-load mechanism.

The campaign targeted government networks globally. [Cisco Talos](https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/) published an extensive technical analysis, and the disclosure was coordinated with [CISA, Australia's ASD ACSC, Canada's CCCS, and the UK NCSC](https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_attacks_event_response). Both CVEs were added to KEV the same day.

**CVE-2024-20481** (CVSS 5.8) is a [resource exhaustion vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-bf-dos-BdsGWfDx) in the RAVPN service of ASA/FTD. A remote unauthenticated attacker can exhaust resources through mass authentication attempts, causing a denial-of-service condition. Disclosed October 23, 2024; added to KEV October 24, 2024. Cisco's advisory noted this was exploited as part of [large-scale brute-force campaigns against VPN services](https://www.bleepingcomputer.com/news/security/cisco-asa-and-ftd-software-ravpn-dos-vulnerability-exploited-in-attacks/) across multiple vendors, not uniquely targeting Cisco.

### 2025: UAT4356 Returns

**CVE-2025-20333** (CVSS 9.9, Critical) and **CVE-2025-20362** (CVSS 6.5, Medium) were [disclosed September 25, 2025](https://www.tenable.com/blog/cve-2025-20333-cve-2025-20362-faq-cisco-asa-ftd-zero-days-uat4356) -- both confirmed exploited as zero-days by the same UAT4356/STORM-1849 actor cluster responsible for ArcaneDoor.

CVE-2025-20333 is a [buffer overflow in the ASA/FTD VPN web server](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-multi-vulns) enabling unauthenticated remote code execution -- the most severe Cisco ASA/FTD CVE by CVSS score in this dataset. CVE-2025-20362 is a missing authorization flaw chained with CVE-2025-20333 for full unauthenticated device takeover.

The 2025 campaign introduced a new generation of implants:

- **RayInitiator** -- a bootkit persisting at the firmware level, surviving not just reboots but standard reimaging procedures.
- **LINE VIPER** -- a shellcode loader succeeding Line Dancer, with improved evasion capabilities.

Both CVEs were added to KEV the same day as disclosure (September 25, 2025). The iterating toolset -- from Line Dancer/Line Runner (2024) to RayInitiator/LINE VIPER (2025) -- demonstrates continued, dedicated investment in Cisco ASA/FTD-specific offensive capability by this actor cluster.

---

## Threat Actor Attribution

### UAT4356 / STORM-1849 -- The Cisco Specialist

The dominant threat actor in Cisco's edge security record is the cluster designated UAT4356 by [Cisco Talos](https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/) and STORM-1849 by [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/). This actor has now burned **four ASA/FTD zero-days across two confirmed campaigns** (2024 and 2025), each accompanied by iterating custom implant toolsets.

- **Suspected nexus:** China (moderate confidence). [Censys research](https://censys.com/) identified links between ArcaneDoor infrastructure and Chinese network ranges, though neither Cisco Talos nor Microsoft has publicly confirmed a national attribution.
- **Targeting:** Government networks globally, with telecommunications and energy sectors flagged as additional areas of concern.
- **Implant evolution:** Line Dancer/Line Runner (2024) to RayInitiator/LINE VIPER (2025) -- bootkit-level persistence and improved evasion across iterations.
- **Sources:** [Cisco Talos](https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/), [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/), CISA, [MITRE ATT&CK C0046](https://attack.mitre.org/campaigns/C0046/), Five Eyes partner agencies (ASD ACSC, CCCS, UK NCSC).

### Broader China-Nexus Activity

Beyond UAT4356, other China-nexus actors have documented operations involving Cisco products:

- **Volt Typhoon** (VANGUARD PANDA / Bronze Silhouette) -- PRC state-sponsored group focused on [pre-positioning in US critical infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a). While Volt Typhoon's documented exploitation primarily targets Fortinet and Ivanti, [CISA's joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) lists Cisco among the vendors whose devices were compromised in this campaign.
- **Earth Estries / Salt Typhoon** -- a China-nexus group conducting [large-scale telecommunications breaches](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html) across 80+ countries; Cisco infrastructure was among the affected vendor platforms per [Trend Micro](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html) and [Microsoft reporting](https://www.microsoft.com/en-us/security/blog/).
- **APT41** (Winnti / Wicked Panda) -- a dual-purpose espionage and criminal group with [documented Cisco exploitation](https://www.mandiant.com/) as part of broader campaigns.

### Ransomware Activity

Ransomware operators have leveraged Cisco VPN vulnerabilities as initial access vectors:

- **Akira** and **LockBit** affiliates exploited [CVE-2023-20269](https://www.rapid7.com/blog/post/2023/09/07/etr-exploitation-of-cisco-asa-ssl-vpn/) for VPN brute-force and session establishment.
- **Akira** also leveraged [CVE-2020-3259](https://www.truesec.com/hub/blog/akira-ransomware-and-exploitation-of-cisco-anyconnect-vulnerability-cve-2020-3259) for credential harvesting from AnyConnect/ASA deployments.

Unlike SonicWall (where ransomware is the dominant threat), Cisco's ASA/FTD ransomware exposure is secondary to its state-actor risk profile. The ransomware activity targets the VPN credential surface rather than exploiting zero-day capabilities.

---

## Disclosure Assessment: Above Average

Cisco PSIRT's handling of ArcaneDoor is a credible example of coordinated responsible disclosure. The April 2024 advisory was developed over months in collaboration with [CISA, Australia's ASD ACSC, Canada's CCCS, and the UK NCSC](https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_attacks_event_response), releasing actionable indicators of compromise simultaneously with the patch. The retroactive elevation of CVE-2024-20359's severity to reflect real-world persistence impact reflects honest post-hoc reassessment rather than minimization.

Notable disclosure characteristics:

- **No documented silent patching.** Unlike [Fortinet's XORtigate episode](./Fortinet.md) (firmware pushed 3--4 days before advisory) or [Zyxel's CVE-2022-30525](./Zyxel.md) (silent patch before coordinated disclosure date), no comparable pattern has been identified in Cisco's ASA/FTD disclosure record.
- **Coordinated multi-agency disclosure.** Both the 2024 ArcaneDoor and 2025 ArcaneDoor II campaigns were disclosed with simultaneous advisories from multiple Five Eyes agencies, maximizing defender reach.
- **Retroactive KEV additions for legacy bugs.** CVE-2014-2120 (2014 XSS) and CVE-2020-3259 (2020 info disclosure) were added to KEV years after original disclosure when new exploitation evidence surfaced -- CISA's catalog reflects the ongoing threat, not just initial disclosure.
- **Proactive advisory cadence.** The November 3, 2021 batch addition of CVE-2018-0296, CVE-2020-3452, and CVE-2020-3580 coincided with the inaugural KEV catalog release; their inclusion signals Cisco shared exploitation evidence with CISA.

The disclosure record is not flawless. CVE-2023-20269's advisory language did not emphasize the ransomware exploitation context that Rapid7 and others documented concurrently, and the severity of 5.0 (Medium) understates the real-world impact when used as a brute-force entry point for ransomware operators. But structurally, Cisco's disclosure posture compares favorably to the documented practices of several peers in this dataset.

---

## The KEV Count -- Label It Correctly

Cisco leads the CISA KEV catalog among network vendors with approximately [82 known-exploited vulnerabilities across all product lines](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=Cisco), placing it third overall (behind Microsoft and Apple) and first among pure-play network security vendors. **This figure spans all Cisco products** -- IOS/IOS XE, Small Business routers, Catalyst switches, VPN concentrators, and collaboration platforms -- not ASA/FTD firewalls alone. Attributing the full 82 to "Cisco firewalls" is a common misread that inflates the firewall-specific risk picture. The 13 edge KEV entries documented above are the relevant measure for firewall-to-firewall comparison.

---

## EPSS Context

EPSS (Exploit Prediction Scoring System) scores for Cisco's ASA/FTD KEV CVEs show wide variation. The highest-probability CVEs for future exploitation:

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2020-3452 | 0.999 | 99.99th |
| CVE-2018-0296 | 0.999 | 99.96th |
| CVE-2016-6366 | 0.875 | 99.73rd |
| CVE-2020-3580 | 0.854 | 99.69th |
| CVE-2020-3259 | 0.718 | 99.35th |
| CVE-2024-20353 | 0.633 | 99.10th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

The older information-disclosure and input-validation CVEs (CVE-2020-3452, CVE-2018-0296) carry the highest EPSS scores, reflecting widespread public exploit availability and continued scanning activity years after disclosure. The ArcaneDoor CVEs (CVE-2024-20353, CVE-2024-20359) carry somewhat lower EPSS scores because exploitation was targeted rather than mass-market -- EPSS measures probability of exploitation broadly, not severity of consequences.

---

## Defender Implications

**1. Treat Cisco ASA/FTD as a state-actor target, not just a patching exercise.** The UAT4356/STORM-1849 actor has now burned four zero-days and iterated its implant toolkit twice. Patching addresses known vulnerabilities; it does not address the offensive R&D pipeline targeting this specific platform. Organizations running ASA/FTD in government, critical infrastructure, or telecom environments should scope incident response plans that assume post-exploitation persistence survives standard remediation -- the RayInitiator bootkit (2025) specifically survives reimaging.

**2. Audit legacy ASA deployments aggressively.** Three of 13 KEV entries (CVE-2014-2120, CVE-2016-6366, CVE-2016-6367) are over eight years old and still being exploited. CVE-2014-2120 was added to KEV in 2024 -- a decade after disclosure. End-of-life ASA hardware running unpatched firmware is a permanent attack surface; [VulnCheck's 2026 State of Exploitation report](https://vulncheck.com/) found that 42.5% of exploited vulnerabilities in 2025 hit end-of-life devices. If hardware cannot receive patches, replace it.

**3. Segment the VPN credential surface from the management plane.** CVE-2023-20269 (brute-force VPN authentication bypass) and CVE-2020-3259 (memory content disclosure including credentials) demonstrate that the remote-access VPN interface is an active ransomware entry point distinct from the state-actor exploitation surface. Enforce MFA on all VPN authentication, rate-limit authentication attempts, and monitor for bulk failed-authentication patterns that precede Akira/LockBit intrusions documented by [Rapid7](https://www.rapid7.com/blog/post/2023/09/07/etr-exploitation-of-cisco-asa-ssl-vpn/) and [Arctic Wolf](https://arcticwolf.com/resources/blog/).

---

## Sources

- [Cisco Talos -- ArcaneDoor campaign analysis](https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/)
- [Cisco PSIRT -- ASA/FTD attack event response](https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_attacks_event_response)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Advisory AA24-038A -- Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [MITRE ATT&CK C0046 -- ArcaneDoor](https://attack.mitre.org/campaigns/C0046/)
- [Tenable -- CVE-2025-20333/CVE-2025-20362 FAQ](https://www.tenable.com/blog/cve-2025-20333-cve-2025-20362-faq-cisco-asa-ftd-zero-days-uat4356)
- [Microsoft Threat Intelligence -- STORM-1849](https://www.microsoft.com/en-us/security/blog/)
- [Censys -- ArcaneDoor infrastructure analysis](https://censys.com/)
- [Rapid7 -- CVE-2023-20269 exploitation](https://www.rapid7.com/blog/post/2023/09/07/etr-exploitation-of-cisco-asa-ssl-vpn/)
- [Truesec -- Akira ransomware and CVE-2020-3259](https://www.truesec.com/hub/blog/akira-ransomware-and-exploitation-of-cisco-anyconnect-vulnerability-cve-2020-3259)
- [Trend Micro -- Earth Estries/Salt Typhoon](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html)
- [NVD](https://nvd.nist.gov/) and [FIRST EPSS API](https://api.first.org/data/v1/epss) for CVSS and EPSS data
- [VulnCheck -- 2026 State of Exploitation](https://vulncheck.com/)
- Sophos Pacific Rim report (Oct 2024), Mandiant/GTIG, Five Eyes partner agencies (ASD ACSC, CCCS, UK NCSC)
