# Juniper Networks

**Scope: Juniper SRX Series firewalls, EX Series switches, and MX Series routers -- J-Web management interface and Junos OS.** *(8 edge KEV entries, 2015--2025.)*

---

## KEV CVE Summary Table

All 8 CISA KEV-listed CVEs for Juniper edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Published | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|-----------|----------|:--------:|:----------:|
| [CVE-2020-1631](https://nvd.nist.gov/vuln/detail/CVE-2020-1631) | 8.8 | CWE-22 Path Traversal | 2020-05-04 | 2022-03-25 | N | N |
| [CVE-2023-36844](https://nvd.nist.gov/vuln/detail/CVE-2023-36844) | 5.3 | CWE-473 PHP External Variable Modification | 2023-08-17 | 2023-11-13 | N | N |
| [CVE-2023-36845](https://nvd.nist.gov/vuln/detail/CVE-2023-36845) | 9.8 | CWE-473 PHP External Variable Modification | 2023-08-17 | 2023-11-13 | N | N |
| [CVE-2023-36846](https://nvd.nist.gov/vuln/detail/CVE-2023-36846) | 5.3 | CWE-306 Missing Authentication | 2023-08-17 | 2023-11-13 | N | N |
| [CVE-2023-36847](https://nvd.nist.gov/vuln/detail/CVE-2023-36847) | 5.3 | CWE-306 Missing Authentication | 2023-08-17 | 2023-11-13 | N | N |
| [CVE-2023-36851](https://nvd.nist.gov/vuln/detail/CVE-2023-36851) | 5.3 | CWE-306 Missing Authentication | 2023-09-26 | 2023-11-13 | N | N |
| [CVE-2025-21590](https://nvd.nist.gov/vuln/detail/CVE-2025-21590) | 4.4 | CWE-653 Insufficient Compartmentalization | 2025-03-12 | 2025-03-13 | Y | N |
| [CVE-2015-7755](https://nvd.nist.gov/vuln/detail/CVE-2015-7755) | 9.8 | CWE-287 Improper Authentication | 2015-12-19 | 2025-10-02 | Y | N |

**Summary statistics:** 8 KEV entries. 2 confirmed zero-days (exploitation before patch/disclosure). 0 flagged by CISA for known ransomware campaigns -- Juniper's threat profile is overwhelmingly espionage-driven, not criminal. The dominant CWE pattern is missing authentication (CWE-306, 3 instances) and PHP variable manipulation (CWE-473, 2 instances). CVSS scores are deceptive: five of eight CVEs scored 5.3 or lower individually, but chain to 9.8 Critical when combined. The record includes one of the most historically significant edge CVEs ever cataloged (CVE-2015-7755, the ScreenOS hardcoded backdoor).

---

## Market Position

Juniper's SRX Series firewalls, EX Series switches, and MX Series routers are deployed across Fortune 500 data centers, major ISPs, and federal networks. The company holds roughly 10--15% of the enterprise edge/firewall market -- smaller than Cisco or Fortinet by volume, but concentrated in high-value carrier and government environments where the impact of a successful compromise is disproportionately severe. Juniper's MX Series routers form backbone infrastructure for major telecommunications providers globally, making them strategic targets for nation-state espionage operations focused on traffic interception.

HPE completed its [acquisition of Juniper Networks in early 2025](https://www.hpe.com/us/en/newsroom/press-release/2024/01/hewlett-packard-enterprise-to-acquire-juniper-networks.html) for approximately $14 billion, placing Juniper's product lines under HPE Aruba Networking. The security implications of this acquisition -- integration complexity, PSIRT process changes, and potential shifts in patch cadence -- remain to be seen.

---

## Timeline

### 2015: The ScreenOS Hardcoded Backdoor -- A Historically Significant Edge CVE

**CVE-2015-7755** (CVSS 9.8, improper authentication) is among the most significant edge device vulnerabilities ever disclosed -- not because of its technical complexity, but because of what it represents: a hardcoded authentication backdoor in a commercial firewall product that went undetected for at least three years.

In December 2015, during an internal code audit, Juniper [disclosed](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10713) that unauthorized code had been inserted into ScreenOS -- the operating system running on its NetScreen firewalls. The backdoor consisted of a hardcoded master password (`<<< %s(un='%s') = %u`) that allowed any remote attacker to gain administrative access to any ScreenOS device via SSH or Telnet. A second component modified the Dual EC DRBG random number generator implementation in a way that could enable passive VPN traffic decryption.

The backdoor was present in ScreenOS versions 6.2.0r15 through 6.2.0r18 and 6.3.0r12 through 6.3.0r20, spanning firmware released from at least 2012 through 2015. The identity of the actor who inserted the code has never been publicly confirmed. [Multiple](https://www.wired.com/2015/12/researchers-solve-juniper-backdoor-mystery-and-they-say-its-partially-the-nsas-fault/) [investigations](https://arstechnica.com/information-technology/2015/12/unauthorized-code-in-juniper-firewalls-decrypts-encrypted-vpn-traffic/) pointed to the involvement of a nation-state actor -- with credible reporting suggesting that the original Dual EC DRBG constants were placed by NSA as part of the BULLRUN program, and that a second actor (potentially Chinese intelligence) subsequently modified those constants to redirect the decryption capability to themselves.

CISA added CVE-2015-7755 to the KEV catalog retroactively on [October 2, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- nearly a decade after disclosure -- confirming that exploitation evidence warranted its inclusion even at that remove. The retroactive addition coincides with renewed focus on supply-chain integrity in edge devices following the UNC3886 Junos backdoor campaign (CVE-2025-21590).

**Why this CVE matters for the dataset:** The ScreenOS backdoor is a fundamentally different threat category from the vulnerability-and-patch cycle that defines most entries in this repository. It is not a coding error that an adversary discovered; it is deliberately inserted malicious code in a shipping product. Its inclusion in the KEV catalog validates a threat model where edge device firmware integrity itself is a security question, not just the absence of exploitable bugs. EPSS score: 0.614 (99.05th percentile).

### 2020: J-Web Path Traversal

**CVE-2020-1631** (CVSS 8.8, path traversal) affects the J-Web management interface and the HTTP/HTTPS services used for device management, DHCPv6, and other functions on Junos OS devices. An unauthenticated attacker can exploit a path traversal to read arbitrary files, exfiltrate device configurations and credentials, or upload malicious files to the device. [Juniper disclosed it on May 4, 2020](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA11021); [CISA added it to KEV on March 25, 2022](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

The nearly two-year gap between disclosure and KEV listing suggests that exploitation evidence accumulated gradually rather than in a mass-exploitation event. EPSS score: 0.047 (90.68th percentile).

### 2023: The J-Web PHP Chain -- Severity Laundering Through Per-CVE Scoring

On August 17, 2023, Juniper issued an [out-of-cycle security bulletin (JSA72300)](https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US) covering four J-Web vulnerabilities affecting SRX firewalls and EX switches. This incident is a case study in how per-CVE CVSS scoring can systematically understate real-world risk.

**The individual scores:**
- **CVE-2023-36844** (CVSS 5.3): PHP external variable modification in J-Web
- **CVE-2023-36845** (CVSS 9.8): PHP external variable modification in J-Web (separately scored Critical due to a different attack path)
- **CVE-2023-36846** (CVSS 5.3): Missing authentication for critical function in J-Web
- **CVE-2023-36847** (CVSS 5.3): Missing authentication for critical function in J-Web

**The combined chain: CVSS 9.8 Critical.** CVE-2023-36846 allowed arbitrary file upload without authentication; CVE-2023-36845 allowed PHP environment variable injection via the GoAhead web server embedded in J-Web. Chaining them executed attacker-supplied code with no credentials required on any SRX firewall or EX switch with J-Web enabled.

Eight days after the advisory, on August 25, 2023, [watchTowr Labs published a working proof-of-concept](https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/) demonstrating unauthenticated pre-auth RCE. Exploitation began [the same day the PoC dropped](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-juniper-rce-bug-chain-after-poc-release/). Shadowserver reported attacks against the `/webauth_operation.php` endpoint from 29+ IPs and counted approximately 8,200 exposed J-Web instances; [Rapid7 and VulnCheck scans](https://www.rapid7.com/blog/post/2023/08/31/etr-exploitation-of-juniper-networks-srx-series-and-ex-series-devices/) put the vulnerable internet-exposed population closer to 12,000.

**CVE-2023-36851** (CVSS 5.3, missing authentication for critical function) was disclosed separately on [September 26, 2023](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA73174) as a closely related missing-authentication flaw in the same J-Web component. It was added to KEV alongside the other four on November 13, 2023, completing the five-CVE J-Web cluster.

CISA added all five to the [Known Exploited Vulnerabilities catalog on November 13, 2023](https://www.cisa.gov/news-events/alerts/2023/11/13/cisa-adds-six-known-exploited-vulnerabilities-catalog) with a four-day remediation deadline (November 17) -- one of the shortest deadlines CISA has assigned, reflecting the urgency of active exploitation against internet-facing firewall management interfaces.

**Key lesson:** Per-unit CVSS scores are an unreliable risk signal when a vendor ships a cluster of individually medium-severity bugs that chain to critical-severity RCE. Three of five CVEs in this chain scored 5.3 Medium -- a score that would not trigger emergency patching in most organizations' vulnerability management programs. The 8-day advisory-to-mass-exploitation interval is among the fastest recorded for enterprise perimeter gear. This pattern -- what the dataset calls "severity laundering" -- is documented in [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md).

EPSS scores for the chain are uniformly high despite the moderate individual CVSS ratings: CVE-2023-36846 (0.942), CVE-2023-36845 (0.935), CVE-2023-36844 (0.896), CVE-2023-36847 (0.847). The EPSS model correctly identifies mass-exploitation risk even when CVSS does not.

### 2025: UNC3886 -- Nation-State Backdoors on Carrier-Grade Routers

The threat picture sharpened dramatically in early 2025 when [Mandiant disclosed](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) that **UNC3886** -- a China-nexus espionage group previously documented for targeting [VMware ESXi hypervisors and Fortinet FortiGate devices](./Fortinet.md) -- had deployed six custom TINYSHELL-based backdoors on Juniper MX Series routers running end-of-life Junos OS versions.

**CVE-2025-21590** (CVSS 4.4, insufficient compartmentalization) is the local vulnerability UNC3886 leveraged after gaining initial access via stolen legitimate credentials. The flaw allows a local attacker with shell access to inject arbitrary code into the memory of legitimate Junos OS processes, bypassing the Veriexec integrity enforcement mechanism without leaving disk-resident artifacts. The low CVSS score (4.4 Medium) reflects the local-access prerequisite, but the real-world impact -- undetectable code injection into a carrier-grade router's operating system -- is far more severe than the score implies.

[CISA added CVE-2025-21590 to KEV on March 13, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- one day after Juniper's disclosure -- confirming zero-day status (exploitation was active before the advisory). Mandiant's investigation revealed:

- **Six custom TINYSHELL variants** deployed across compromised MX routers, each with distinct capabilities including active and passive backdoor modes
- **Logging explicitly disabled** by some implants to evade detection
- **Process injection** into legitimate Junos OS daemons, surviving process restarts
- **Targets:** ISPs, telecom carriers, and U.S. defense contractors
- **End-of-life hardware:** The affected devices were running unsupported Junos OS versions, compounding the risk -- Juniper could not provide patches for the specific firmware versions in use

UNC3886's operational pattern is vendor-agnostic edge-device specialization: the same group deployed [BOLDMOVE malware on FortiOS](./Fortinet.md) (CVE-2022-42475) and purpose-built implants for VMware ESXi, demonstrating deep investment in understanding the internals of each target platform. The [Singapore CSA/IMDA advisory (February 2026)](https://www.csa.gov.sg/) and [Five Eyes partner agencies](https://www.cisa.gov/) issued joint warnings about UNC3886's Juniper operations.

---

## CWE Weakness Profile

| Category | Count | CVEs |
|----------|------:|------|
| **Missing Authentication** (CWE-306) | 3 | CVE-2023-36846, CVE-2023-36847, CVE-2023-36851 |
| **PHP Variable Modification** (CWE-473) | 2 | CVE-2023-36844, CVE-2023-36845 |
| **Authentication Bypass** (CWE-287) | 1 | CVE-2015-7755 |
| **Path Traversal** (CWE-22) | 1 | CVE-2020-1631 |
| **Insufficient Compartmentalization** (CWE-653) | 1 | CVE-2025-21590 |

**Pattern:** Juniper's CWE fingerprint is dominated by the J-Web management interface: five of eight CVEs (63%) target J-Web's PHP-based web management layer, exposing a systemic architectural weakness in using PHP with the GoAhead embedded web server for firewall management. The missing-authentication pattern (CWE-306, 3 instances) indicates repeated failures to enforce authentication on critical J-Web endpoints. CWE-653 (CVE-2025-21590) represents a qualitatively different class -- an OS-level compartmentalization failure that enables kernel-adjacent code injection. See [CWE-ANALYSIS.md](CWE-ANALYSIS.md) for cross-vendor comparison.

---

## Threat Actor Attribution

### UNC3886 -- The Edge-Device Specialist

| Attribute | Detail |
|-----------|--------|
| **Nexus** | China (high confidence) |
| **CVEs exploited** | CVE-2025-21590 (Juniper MX), plus CVE-2022-42475 and CVE-2022-41328 (Fortinet FortiGate), VMware ESXi zero-days |
| **Tooling** | 6 custom TINYSHELL variants for Junos OS, BOLDMOVE for FortiOS, custom ESXi backdoors |
| **Targets** | ISPs, telecom carriers, U.S. defense contractors |
| **Operational pattern** | Vendor-agnostic edge-device specialization; builds platform-specific implants for each target OS |
| **Sources** | [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers), [MITRE ATT&CK](https://attack.mitre.org/), [Singapore CSA/IMDA](https://www.csa.gov.sg/) |

UNC3886 is the only publicly attributed threat actor targeting Juniper's edge products in this dataset. The absence of ransomware exploitation across all eight Juniper KEV entries reinforces that Juniper's threat model is overwhelmingly espionage-driven -- the product line's concentration in carrier and government environments makes it a strategic intelligence target rather than a financial-crime target.

### The ScreenOS Backdoor Actor (Unknown)

The entity responsible for inserting the CVE-2015-7755 backdoor into ScreenOS has never been publicly identified with certainty. Credible reporting points to nation-state involvement, potentially involving both NSA (original Dual EC DRBG manipulation) and a second intelligence service (modification of the constants). This remains one of the most significant unsolved attribution questions in edge device security.

---

## EPSS Context

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2023-36846 | 0.942 | 99.84th |
| CVE-2023-36845 | 0.935 | 99.83rd |
| CVE-2023-36844 | 0.896 | 99.77th |
| CVE-2023-36847 | 0.847 | 99.68th |
| CVE-2015-7755 | 0.614 | 99.05th |
| CVE-2020-1631 | 0.047 | 90.68th |
| CVE-2025-21590 | 0.017 | 73.57th |
| CVE-2023-36851 | 0.011 | 61.38th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

The J-Web chain CVEs carry uniformly high EPSS scores (0.847--0.942) that correctly reflect mass-exploitation risk even where individual CVSS scores are moderate. CVE-2025-21590's low EPSS (0.017) reflects its local-access prerequisite -- but the KEV listing confirms nation-state exploitation regardless of broad-based scanning probability.

---

## Disclosure Assessment

### Positive Indicators

- **Timely out-of-cycle advisory (2023).** Juniper's out-of-cycle bulletin JSA72300 for the J-Web chain preceded public PoC by eight days, and the PSIRT process functioned as intended. There is no documented evidence of silent patching comparable to [Fortinet's behavior on CVE-2023-27997](./Fortinet.md).
- **Coordinated disclosure with Mandiant (2025).** CVE-2025-21590 was disclosed in coordination with Mandiant's threat intelligence publication, providing defenders with both the patch and the threat context simultaneously.
- **Retroactive CVE-2015-7755 acknowledgment.** Juniper's 2015 disclosure of the ScreenOS backdoor was voluntary -- discovered through internal audit rather than external pressure.

### Concerns

- **Severity framing of the J-Web chain.** Releasing four individually "Medium" CVEs without immediately surfacing the 9.8-rated combined-chain risk in the advisory headline created a patch-urgency deficit that exploitation filled within eight days. Organizations that triaged based on individual CVSS scores would not have triggered emergency patching. The advisory body mentioned the chain, but the per-CVE framing dominated the communication.
- **End-of-life exposure (2025).** UNC3886 targeted Juniper MX routers running unsupported Junos OS versions. The affected devices could not receive patches for CVE-2025-21590. While this is an operator responsibility, the vendor bears some accountability for not providing clearer end-of-life security guidance and migration pressure for devices in critical infrastructure.
- **PHP in firewall management (architectural).** The use of PHP with the GoAhead embedded web server as J-Web's management framework produced five KEV entries from a single architectural surface. This is a design-level concern, not a point-vulnerability issue.

---

## Defender Implications

**1. Disable J-Web on all internet-facing Juniper devices.** Five of eight KEV entries target the J-Web management interface. The 2023 chain demonstrated that mass exploitation begins within eight days of advisory and same-day upon PoC publication. J-Web should never be exposed to the internet. Use console access, SSH, or a dedicated out-of-band management network. If J-Web is required, restrict it to internal management VLANs with strict ACLs.

**2. Do not rely on individual CVSS scores for Juniper patch prioritization.** The J-Web chain proved that a cluster of CVSS 5.3 Medium bugs can combine to CVSS 9.8 Critical RCE. Evaluate Juniper advisories for chainability, not just individual severity. When Juniper issues multiple CVEs in the same component simultaneously, treat the batch as critical regardless of per-CVE scores.

**3. Audit MX Series routers for UNC3886 indicators.** Organizations running Juniper MX routers -- particularly in ISP, telecom, or defense environments -- should conduct forensic analysis for TINYSHELL variants and process-injection artifacts. UNC3886's implants explicitly disabled logging, so log-based detection alone is insufficient. Check for unauthorized modifications to Junos OS processes, unexpected network connections from router management interfaces, and anomalous process memory footprints. Mandiant's [public indicators](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) should be ingested into detection pipelines.

**4. Treat CVE-2015-7755 as a permanent trust question.** If your organization ever ran ScreenOS 6.2.0r15--6.2.0r18 or 6.3.0r12--6.3.0r20, the device's integrity was compromised at the firmware level. These devices should have been replaced, not just patched. More broadly, the ScreenOS incident validates the threat model where edge device firmware integrity -- not just the absence of exploitable bugs -- is a security requirement.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [November 2023 KEV additions](https://www.cisa.gov/news-events/alerts/2023/11/13/cisa-adds-six-known-exploited-vulnerabilities-catalog); [March 2025 KEV addition](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Juniper PSIRT:** [JSA72300](https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US) (2023 J-Web chain); [JSA10713](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10713) (ScreenOS backdoor); [JSA11021](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA11021) (CVE-2020-1631)
- **Mandiant / Google Threat Intelligence Group:** [China-nexus espionage targets Juniper routers](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) (UNC3886)
- **watchTowr Labs:** [CVE-2023-36844 and friends -- RCE in Juniper firewalls](https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/)
- **Rapid7:** [Exploitation of Juniper SRX and EX devices](https://www.rapid7.com/blog/post/2023/08/31/etr-exploitation-of-juniper-networks-srx-series-and-ex-series-devices/)
- **BleepingComputer:** [Hackers exploit critical Juniper RCE bug chain after PoC release](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-juniper-rce-bug-chain-after-poc-release/)
- **Shadowserver:** J-Web scanning and exploitation telemetry (August 2023)
- **Wired:** [Researchers solve Juniper backdoor mystery](https://www.wired.com/2015/12/researchers-solve-juniper-backdoor-mystery-and-they-say-its-partially-the-nsas-fault/)
- **Ars Technica:** [Unauthorized code in Juniper firewalls decrypts VPN traffic](https://arstechnica.com/information-technology/2015/12/unauthorized-code-in-juniper-firewalls-decrypts-encrypted-vpn-traffic/)
- **Singapore CSA / IMDA:** UNC3886 Juniper advisory (February 2026)
- **NVD:** CVSS scoring and CWE classification for all 8 CVEs
- **FIRST.org EPSS:** [Exploit Prediction Scoring System data](https://api.first.org/data/v1/epss)
