# Ivanti (Connect Secure / Pulse Connect Secure)

**Scope: Ivanti Connect Secure, Pulse Connect Secure, and Policy Secure SSL-VPN / ZTNA gateways.** Ivanti acquired Pulse Secure in December 2020 and rebranded Pulse Connect Secure to Ivanti Connect Secure. All Pulse Secure CVEs in the CISA KEV catalog are listed under the Ivanti vendor name. *(13 edge KEV entries, 2019--2025.)*

## Market Position

Ivanti Connect Secure (formerly Pulse Secure) is a dominant SSL-VPN and zero-trust network access platform deployed across government agencies, financial institutions, and critical infrastructure worldwide. Its pervasive presence in U.S. federal civilian agencies elevated the strategic value of its vulnerabilities -- and the consequences when they were exploited. This federal concentration is what drove CISA's rare [Emergency Directive ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities), requiring all FCEB agencies to disconnect affected appliances.

---

## KEV CVE Table

All 13 CISA KEV-listed CVEs for Ivanti Connect Secure / Pulse Connect Secure / Policy Secure, ordered by KEV date. CVSS, CWE, and EPSS data sourced from NVD and FIRST.org EPSS API. Zero-day status from `TIME-TO-EXPLOIT.md` and Mandiant/CISA reporting. Ransomware association from CISA KEV `knownRansomwareCampaignUse` field.

| CVE ID | CVSS | CWE Class | KEV Date | Zero-Day | Ransomware | Product |
|--------|-----:|-----------|----------|:--------:|:----------:|---------|
| [CVE-2019-11510](https://nvd.nist.gov/vuln/detail/CVE-2019-11510) | 9.9 | CWE-22 (Path Traversal) | 2021-11-03 | Y | Y | Pulse Connect Secure |
| [CVE-2019-11539](https://nvd.nist.gov/vuln/detail/CVE-2019-11539) | 8.0 | CWE-78 (OS Command Injection) | 2021-11-03 | N | Y | Pulse Connect Secure / Policy Secure |
| [CVE-2020-8243](https://nvd.nist.gov/vuln/detail/CVE-2020-8243) | 7.2 | CWE-94 (Code Injection) | 2021-11-03 | Y | N | Pulse Connect Secure |
| [CVE-2020-8260](https://nvd.nist.gov/vuln/detail/CVE-2020-8260) | 7.2 | CWE-434 (Unrestricted File Upload) | 2021-11-03 | Y | N | Pulse Connect Secure |
| [CVE-2021-22893](https://nvd.nist.gov/vuln/detail/CVE-2021-22893) | 10.0 | CWE-287 (Improper Authentication) | 2021-11-03 | Y | N | Pulse Connect Secure |
| [CVE-2021-22894](https://nvd.nist.gov/vuln/detail/CVE-2021-22894) | 8.8 | CWE-94 (Code Injection) | 2021-11-03 | N | N | Pulse Connect Secure |
| [CVE-2021-22899](https://nvd.nist.gov/vuln/detail/CVE-2021-22899) | 8.8 | CWE-77 (Command Injection) | 2021-11-03 | N | N | Pulse Connect Secure |
| [CVE-2021-22900](https://nvd.nist.gov/vuln/detail/CVE-2021-22900) | 7.2 | CWE-94 (Code Injection) | 2021-11-03 | N | N | Pulse Connect Secure |
| [CVE-2023-46805](https://nvd.nist.gov/vuln/detail/CVE-2023-46805) | 8.2 | Authentication Bypass | 2024-01-10 | Y | Y | Connect Secure / Policy Secure |
| [CVE-2024-21887](https://nvd.nist.gov/vuln/detail/CVE-2024-21887) | 9.1 | CWE-77 (Command Injection) | 2024-01-10 | Y | Y | Connect Secure / Policy Secure |
| [CVE-2024-21893](https://nvd.nist.gov/vuln/detail/CVE-2024-21893) | 8.2 | CWE-918 (SSRF) | 2024-01-31 | Y | Y | Connect Secure / Policy Secure / Neurons |
| [CVE-2025-0282](https://nvd.nist.gov/vuln/detail/CVE-2025-0282) | 9.0 | CWE-121 (Stack Buffer Overflow) | 2025-01-08 | Y | N | Connect Secure / Policy Secure / ZTA Gateways |
| [CVE-2025-22457](https://nvd.nist.gov/vuln/detail/CVE-2025-22457) | 9.0 | CWE-121 (Stack Buffer Overflow) | 2025-04-04 | Y | N | Connect Secure / Policy Secure / ZTA Gateways |

**Summary:** 13 KEV entries. 9 confirmed zero-days (69%). 5 with documented ransomware use. EPSS scores for recent CVEs are extreme: CVE-2019-11510 (0.99999), CVE-2024-21887 (0.99999), CVE-2024-21893 (0.99999), CVE-2025-0282 (0.99971), CVE-2025-22457 (0.99961).

---

## Timeline

### Pre-2020: The Pulse Secure Era

**CVE-2019-11510** (CVSS 9.9, path traversal) is the foundational Ivanti/Pulse Secure vulnerability. Disclosed in May 2019, it allowed unauthenticated remote attackers to read arbitrary files -- including cached plaintext credentials and session tokens -- from Pulse Connect Secure appliances via a crafted URI. [CISA Alert AA20-010A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-010a) documented widespread exploitation from August 2019 onward. The vulnerability was trivially exploitable: a single HTTP request to a known path. Exploitation was confirmed against U.S. government agencies, critical infrastructure operators, and defense contractors ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/)).

**CVE-2019-11539** (CVSS 8.0, OS command injection) is a post-authentication command injection in the admin web interface of both Pulse Connect Secure and Pulse Policy Secure. It was typically chained with CVE-2019-11510 to achieve unauthenticated remote code execution: the file-read gave attackers admin credentials, and the command injection converted those credentials to shell access. [NSA and CISA joint advisories](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_EXPLOITING_PULSE_CONNECT_SECURE_VULNERABILITIES.PDF) cited this chain in nation-state exploitation.

Both CVEs were added to CISA's KEV catalog on November 3, 2021 -- the catalog's launch date -- indicating retroactive recognition of their severity. CVE-2019-11510's TTE of 910 days in the KEV data is an artifact of KEV backdating; real-world mass exploitation began within approximately 3 months of disclosure ([Bad Packets, August 2019](https://badpackets.net/over-14500-pulse-secure-vpn-endpoints-vulnerable-to-cve-2019-11510/)).

### 2020--2022: Ongoing Pulse Secure Exploitation

**CVE-2020-8243** (CVSS 7.2, code injection) and **CVE-2020-8260** (CVSS 7.2, unrestricted file upload) were disclosed in September and October 2020 respectively. Both required administrative authentication, but in environments where CVE-2019-11510 or credential harvesting had already provided admin access, they functioned as persistence and re-compromise mechanisms. [CISA Alert AA21-110A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-110a) (April 2021) documented threat actors using CVE-2020-8243 to deploy webshells on Pulse Connect Secure appliances, maintaining access even after patches were applied for the original 2019 vulnerabilities. Mandiant attributed exploitation to [China-nexus actors](https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day/).

**CVE-2021-22893** (CVSS 10.0, authentication bypass) marked a significant escalation. Disclosed in April 2021 as a true zero-day, it allowed unauthenticated remote code execution via Pulse Connect Secure's license server component. [FireEye/Mandiant reported](https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day/) that at least two China-nexus threat groups had been exploiting it since at least January 2021 -- three months before disclosure. CISA issued [Emergency Directive 21-03](https://www.cisa.gov/news-events/directives/ed-21-03-mitigate-pulse-connect-secure-product-vulnerabilities) requiring federal agencies to run the Pulse Connect Secure Integrity Tool and report results. [CISA Alert AA21-110A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-110a) confirmed that threat actors deployed at least 12 malware families on compromised appliances, including SLOWPULSE (authentication logic bypass), RADIALPULSE, THINBLOOD, ATRIUM, PACEMAKER, and SLIGHTPULSE.

**CVE-2021-22894** (CVSS 8.8, buffer overflow via code injection), **CVE-2021-22899** (CVSS 8.8, command injection), and **CVE-2021-22900** (CVSS 7.2, code injection via file upload) were disclosed in May 2021 as part of the same response cycle. All three required some level of authentication but expanded the attack surface available to threat actors who had already established a foothold through CVE-2021-22893 or harvested credentials. They were added to KEV on November 3, 2021, alongside the older Pulse Secure CVEs.

### 2023--2024: The January 2024 Crisis

On [January 10, 2024](https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-releases-security-update-connect-secure-and-policy-secure-gateways), Ivanti disclosed two chained vulnerabilities in Connect Secure and Policy Secure:

- **CVE-2023-46805** (CVSS 8.2): Authentication bypass in the web component -- an unauthenticated remote attacker bypasses access control checks entirely.
- **CVE-2024-21887** (CVSS 9.1): Command injection executable by any authenticated administrator -- but when chained with CVE-2023-46805, authentication is not required.

Both were already being exploited before the advisory dropped. [Volexity discovered the exploitation](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/) in December 2023 during incident response at a customer site. [Mandiant and Google Threat Intelligence attributed the initial campaign](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/) to **UNC5221**, a China-nexus espionage group, which deployed webshells and custom malware families (LIGHTWIRE, WIREFIRE, ZIPLINE, WARPWIRE) across approximately **1,700 Ivanti appliances by mid-January** ([Volexity](https://www.volexity.com/blog/2024/01/15/ivanti-connect-secure-vpn-exploitation-goes-global/)).

On January 19, 2024, CISA issued [Emergency Directive ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities) -- a rare authority requiring all federal civilian executive branch agencies to immediately disconnect Ivanti Connect Secure and Policy Secure products or apply Ivanti's XML-based mitigation. No patch existed yet; Ivanti distributed mitigations only through a private customer portal. The first patches were not available until January 31, 2024 -- **21 days after advisory, and weeks after confirmed exploitation had begun**.

**CVE-2024-21893** (CVSS 8.2, SSRF) -- the third zero-day -- was disclosed on January 31, 2024, the same day as the first patches. This SSRF in the SAML component allowed unauthenticated access to restricted resources and was immediately chained with CVE-2024-21887 for code execution. [Shadowserver tracked 170+ distinct attacking IPs](https://securityaffairs.com/158677/hacking/ivanti-ssrf-cve-2024-21893-under-attack.html) exploiting it within days.

The disclosure sequence exposed compounding problems:

1. **Defeated integrity checking.** CISA [found that Ivanti's Integrity Checker Tool (ICT)](https://www.cisa.gov/news-events/alerts/2024/01/30/updated-new-software-updates-and-mitigations-defend-against-exploitation-ivanti-connect-secure-and) could be defeated by sophisticated adversaries who modified the tool's expected baseline.
2. **Disputed factory reset effectiveness.** CISA further found that **factory resets may not remove root-level persistence** on compromised appliances. Ivanti [publicly disputed this finding](https://www.bankinfosecurity.com/ivanti-disputes-cisa-findings-post-factory-reset-hacking-a-24492), creating an unusual public disagreement with the U.S. government's cybersecurity agency during an active crisis.
3. **Patch quality issues.** watchTowr researchers discovered a fourth vulnerability (CVE-2024-22024, XXE) while [auditing Ivanti's patch for CVE-2024-21893](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/), indicating that the patch itself introduced or failed to address an adjacent flaw.

### 2025: Pattern Repeats

**CVE-2025-0282** (CVSS 9.0, stack-based buffer overflow) was [added to CISA KEV on January 8, 2025](https://www.cisa.gov/news-events/alerts/2025/01/08/cisa-adds-one-vulnerability-kev-catalog) -- the same day as Ivanti's advisory. It enabled unauthenticated remote code execution on Connect Secure, Policy Secure, and ZTA Gateways. A [joint Mandiant/Ivanti investigation](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-zero-day-espionage/) confirmed exploitation going back to **mid-December 2024**, with post-exploitation malware families SPAWN (SPAWNANT, SPAWNSNARE, SPAWNSLOTH), DRYHOOK, and PHASEJAM deployed on compromised appliances. Mandiant attributed the activity to **UNC5337**, assessed as a China-nexus cluster potentially overlapping with UNC5221.

**CVE-2025-22457** (CVSS 9.0, stack-based buffer overflow) was [added to CISA KEV on April 4, 2025](https://www.cisa.gov/news-events/alerts/2025/04/04/cisa-adds-one-known-exploited-vulnerability-to-catalog). [Mandiant confirmed](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-ivanti-connect-secure-vulnerability/) that UNC5221 had exploited this vulnerability since at least mid-March 2025, deploying new malware families TRAILBLAZE (in-memory dropper) and BRUSHFIRE (passive backdoor), alongside the previously documented SPAWN ecosystem. Ivanti initially assessed CVE-2025-22457 as a low-risk denial-of-service bug not exploitable for code execution. [Mandiant's analysis](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-ivanti-connect-secure-vulnerability/) revealed that UNC5221 had developed a working RCE exploit for a vulnerability the vendor had classified as non-critical -- demonstrating that attacker capability can outpace vendor triage.

---

## CWE Weakness Profile

Ivanti's 13 KEV CVEs break down into the following weakness categories (per NVD CWE assignments):

| Category | Count | CVEs |
|----------|------:|------|
| **Injection** (CWE-77, CWE-78, CWE-94) | 6 | CVE-2019-11539, CVE-2020-8243, CVE-2021-22894, CVE-2021-22899, CVE-2021-22900, CVE-2024-21887 |
| **Authentication / Access Control** (CWE-287, CWE-918) | 3 | CVE-2021-22893, CVE-2023-46805, CVE-2024-21893 |
| **Memory Safety** (CWE-121) | 2 | CVE-2025-0282, CVE-2025-22457 |
| **Path Traversal** (CWE-22) | 1 | CVE-2019-11510 |
| **File Upload** (CWE-434) | 1 | CVE-2020-8260 |

**Pattern:** Injection dominates the Pulse Secure / early Connect Secure era (2019--2024), with 6 of 13 CVEs (46%) being code or command injection through admin interfaces and template engines. The 2025 CVEs shift to stack-based buffer overflows (CWE-121) in the Connect Secure SSL-VPN engine -- a memory-safety pattern consistent with the broader industry trend documented in [CWE-ANALYSIS.md](CWE-ANALYSIS.md). The presence of path traversal (CVE-2019-11510) and SSRF (CVE-2024-21893) indicates weakness diversity rather than a single systemic flaw.

---

## Attribution

Ivanti Connect Secure / Pulse Connect Secure is the most persistently targeted VPN platform by a single threat actor cluster in this dataset. Attribution is based on Mandiant/Google Threat Intelligence Group, Volexity, CrowdStrike, and CISA reporting.

### UNC5221 / Warp Panda

- **Nexus:** China (high confidence) ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/), [CrowdStrike](https://www.crowdstrike.com/adversaries/))
- **CVEs exploited:** CVE-2023-46805 + CVE-2024-21887 (January 2024), CVE-2024-21893 (January 2024), CVE-2025-0282 (December 2024), CVE-2025-22457 (March 2025)
- **Profile:** Persistent, single-vendor-focused espionage group. Responsible for the January 2024 crisis (~1,700 appliances compromised) that triggered CISA Emergency Directive ED 24-01. Returned with new exploits at least three more times through April 2025. Also linked to the [F5 BIG-IP corporate breach](https://cloud.google.com/blog/topics/threat-intelligence/) (August 2025) via BRICKSTORM malware, where source code and undisclosed vulnerability information were exfiltrated after 12+ months of persistent access.
- **Malware families:** SPAWN (SPAWNANT, SPAWNSNARE, SPAWNSLOTH), DRYHOOK, PHASEJAM, TRAILBLAZE, BRUSHFIRE, BRICKSTORM, LIGHTWIRE, WIREFIRE, ZIPLINE, WARPWIRE
- **Sources:** [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/), [CISA ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities), [CrowdStrike](https://www.crowdstrike.com/adversaries/), [Unit 42](https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2023-46805-cve-2024-21887/)

### UNC5337

- **Nexus:** China (high confidence) ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-zero-day-espionage/))
- **CVEs exploited:** CVE-2025-0282
- **Profile:** Potentially a subcluster of UNC5221 or an operationally distinct group sharing infrastructure and tooling. Deployed the same SPAWN malware ecosystem. Whether UNC5221 and UNC5337 represent the same cluster at different operational phases or genuinely distinct actors is not resolved in public reporting.
- **Sources:** [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-zero-day-espionage/)

### Volt Typhoon / VANGUARD PANDA

- **Nexus:** China (high confidence) ([Microsoft](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/), [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a))
- **CVEs exploited:** No specific Ivanti CVEs publicly enumerated, but Ivanti is listed as a targeted vendor in the [Five Eyes joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) on Volt Typhoon's critical infrastructure pre-positioning campaign.
- **Sources:** [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)

### Earth Estries / Salt Typhoon

- **Nexus:** China (high confidence) ([Trend Micro](https://www.trendmicro.com/en_us/research.html), [Microsoft](https://www.microsoft.com/en-us/security/blog/))
- **CVEs exploited:** Not publicly enumerated at CVE level for Ivanti, but Ivanti is listed among targeted vendors in the 600+ organization, 80+ country campaign reported by Trend Micro.
- **Sources:** [Trend Micro](https://www.trendmicro.com/en_us/research.html), [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/)

### Pre-Acquisition Pulse Secure Campaign Actors (2019--2021)

Exploitation of CVE-2019-11510 was attributed to multiple distinct threat groups including China-nexus, Iran-nexus, and criminal actors. [CISA AA20-010A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-010a) and [NSA advisory](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_EXPLOITING_PULSE_CONNECT_SECURE_VULNERABILITIES.PDF) documented exploitation by nation-state actors without specifying individual groups. The breadth of exploitation was wide: CVE-2019-11510 had an EPSS score of 0.99999 (99th percentile) and was exploited by actors ranging from nation-state espionage groups to ransomware operators ([FBI/CISA joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-010a)).

---

## Disclosure Assessment

### Positive Indicators

- **No documented silent patching.** Unlike some peers in this dataset, Ivanti has not been documented shipping security fixes in firmware without issuing a corresponding CVE or advisory. Advisories have been published for all 13 KEV-listed CVEs.
- **No vendor infrastructure breach.** Ivanti's own corporate infrastructure has not been publicly documented as breached through its edge products (unlike SonicWall's MySonicWall incident).
- **Cooperation with researchers.** Ivanti credited Mandiant, Volexity, and CISA in its advisory cycle and collaborated on joint investigations, particularly for the 2024--2025 CVEs.

### Concerns

- **Patch lag during active exploitation.** The January 2024 crisis had a 21-day gap between advisory (January 10) and first available patches (January 31), during which mitigations were the only option. Mitigations were distributed through a private customer portal rather than a public advisory. [CISA ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities) noted the mitigation-only posture as a constraint.
- **Defeated integrity tooling.** CISA [determined](https://www.cisa.gov/news-events/alerts/2024/01/30/updated-new-software-updates-and-mitigations-defend-against-exploitation-ivanti-connect-secure-and) that Ivanti's Integrity Checker Tool (ICT) could be defeated by sophisticated adversaries who modified the tool's expected baselines. This meant the vendor's recommended detection mechanism was unreliable against the specific threat actors targeting the platform.
- **Disputed government findings.** Ivanti [publicly disputed CISA's finding](https://www.bankinfosecurity.com/ivanti-disputes-cisa-findings-post-factory-reset-hacking-a-24492) that factory resets may not remove root-level persistence from compromised appliances. This created a public disagreement with the government's lead cybersecurity agency during an active mass-exploitation event -- an unusual posture that complicated defender decision-making.
- **Severity misclassification.** CVE-2025-22457 was initially assessed by Ivanti as a low-risk denial-of-service bug not exploitable for remote code execution. [Mandiant subsequently demonstrated](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-ivanti-connect-secure-vulnerability/) that UNC5221 had already developed and deployed a working RCE exploit for it. The initial triage communicated lower urgency to defenders than the actual risk warranted.
- **Patch quality.** watchTowr's discovery of CVE-2024-22024 (XXE) while [auditing the patch for CVE-2024-21893](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/) suggested that the patch development and review process under crisis conditions introduced or failed to address adjacent flaws.

---

## Defender Implications

### 1. Treat Ivanti Connect Secure as a persistent high-value target requiring pre-positioned incident response

UNC5221 is the most publicly documented example of a single threat actor cluster persistently targeting a single vendor's SSL-VPN product. They have burned at least four distinct exploit chains against Connect Secure across 2024--2025 (CVE-2023-46805+CVE-2024-21887, CVE-2024-21893, CVE-2025-0282, CVE-2025-22457), deploying at least 10 distinct malware families purpose-built for the platform ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/)). The operational cadence -- new zero-day roughly every 3--6 months -- means patching alone cannot keep pace. Organizations running Connect Secure should maintain continuous IOC monitoring against known UNC5221 TTPs, pre-stage incident response playbooks for device reimage (not just patch), and plan for a world where the next zero-day is already being exploited when the advisory drops.

### 2. Do not rely on the vendor-supplied Integrity Checker Tool (ICT) as a sole detection mechanism

CISA's [January 2024 finding](https://www.cisa.gov/news-events/alerts/2024/01/30/updated-new-software-updates-and-mitigations-defend-against-exploitation-ivanti-connect-secure-and) that the ICT could be defeated by sophisticated adversaries, combined with the disputed effectiveness of factory resets, means the vendor's own detection and remediation tooling is insufficient against state-level threats. Defenders should supplement ICT with network-based detection (monitoring for known C2 domains and anomalous outbound connections from VPN appliances), memory forensics where feasible, and external integrity validation that does not depend on the appliance's own filesystem.

### 3. Assume post-exploitation persistence survives patching and plan for full device replacement

Across both the 2021 Pulse Secure campaign ([CISA AA21-110A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-110a)) and the 2024 Connect Secure crisis ([CISA ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities)), threat actors demonstrated persistence mechanisms that survived standard patching and potentially survived factory resets. The CISA supplemental direction to ED 24-01 required agencies to perform full device reimaging -- not just patching or factory reset -- before reconnecting appliances. For organizations in threat models that include nation-state adversaries, device replacement rather than remediation may be the appropriate response to confirmed compromise.

---

## Sources

- **CISA:** [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [Emergency Directive ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities); [Alert AA20-010A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-010a) (Pulse Secure); [Alert AA21-110A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-110a) (Pulse Secure); [Updated mitigations Jan 30 2024](https://www.cisa.gov/news-events/alerts/2024/01/30/updated-new-software-updates-and-mitigations-defend-against-exploitation-ivanti-connect-secure-and); [CVE-2025-0282 alert](https://www.cisa.gov/news-events/alerts/2025/01/08/cisa-adds-one-vulnerability-kev-catalog); [CVE-2025-22457 alert](https://www.cisa.gov/news-events/alerts/2025/04/04/cisa-adds-one-known-exploited-vulnerability-to-catalog)
- **Mandiant / Google Threat Intelligence Group:** [Investigating Ivanti exploitation and persistence](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/); [Ivanti Connect Secure zero-day espionage (CVE-2025-0282)](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-zero-day-espionage/); [China-nexus exploiting CVE-2025-22457](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-ivanti-connect-secure-vulnerability/); [Suspected APT actors leverage bypass techniques (2021)](https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day/)
- **Volexity:** [Active exploitation of Ivanti Connect Secure VPN (Jan 10 2024)](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/); [Ivanti exploitation goes global (Jan 15 2024)](https://www.volexity.com/blog/2024/01/15/ivanti-connect-secure-vpn-exploitation-goes-global/)
- **Unit 42:** [Threat brief: Ivanti CVE-2023-46805 and CVE-2024-21887](https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2023-46805-cve-2024-21887/)
- **watchTowr:** [Welcome to 2024: the SSLVPN chaos continues](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/)
- **NSA:** [Exploiting Pulse Connect Secure vulnerabilities (Apr 2021)](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_EXPLOITING_PULSE_CONNECT_SECURE_VULNERABILITIES.PDF)
- **BankInfoSecurity:** [Ivanti disputes CISA findings post factory-reset hacking](https://www.bankinfosecurity.com/ivanti-disputes-cisa-findings-post-factory-reset-hacking-a-24492)
- **SecurityAffairs:** [Ivanti SSRF CVE-2024-21893 under attack](https://securityaffairs.com/158677/hacking/ivanti-ssrf-cve-2024-21893-under-attack.html)
- **BleepingComputer:** [Newest Ivanti SSRF zero-day now under mass exploitation](https://www.bleepingcomputer.com/news/security/newest-ivanti-ssrf-zero-day-now-under-mass-exploitation/)
- **Bad Packets:** [Over 14,500 Pulse Secure VPN endpoints vulnerable to CVE-2019-11510](https://badpackets.net/over-14500-pulse-secure-vpn-endpoints-vulnerable-to-cve-2019-11510/)
- **Microsoft:** [Volt Typhoon advisory](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)
- **Censys:** [CVE-2025-0282 advisory](https://censys.com/advisory/cve-2025-0282)
- **NVD / FIRST.org EPSS:** CVSS and EPSS data for all 13 CVEs
