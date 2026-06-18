# Check Point Software

**Scope: Check Point Quantum Security Gateways (SSL VPN / Remote Access VPN / Mobile Access blade).** *(2 edge KEV entries -- the lowest count of any vendor in this repo. Both are confirmed zero-days. One is confirmed ransomware-associated.)*

---

## KEV CVE Summary Table

All 2 CISA KEV-listed CVEs for Check Point edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Published | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|-----------|----------|:--------:|:----------:|
| [CVE-2024-24919](https://nvd.nist.gov/vuln/detail/CVE-2024-24919) | 8.6 | CWE-200 Information Disclosure | 2024-05-28 | 2024-05-30 | Y | Y |
| [CVE-2026-50751](https://nvd.nist.gov/vuln/detail/CVE-2026-50751) | 9.3 | CWE-287 Improper Authentication | 2026-06-08 | 2026-06-08 | Y | Y |

**Summary statistics:** 2 KEV entries -- the smallest vendor count in this dataset. Both are confirmed zero-days (100% zero-day rate). Both are flagged by CISA for known ransomware campaign use (100% ransomware rate). The zero-day and ransomware rates are the highest of any vendor in the dataset, though the sample size is too small for statistical significance. CWE classes are information disclosure (CWE-200) and improper authentication (CWE-287) -- both attack the authentication/credential surface rather than achieving direct RCE, a pattern distinct from Fortinet's memory-corruption or Ivanti's injection-chain profiles.

---

## Market Position

Check Point is a [Gartner Magic Quadrant Leader for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336) and one of the three incumbents that dominate enterprise firewall revenue alongside Fortinet and Palo Alto Networks. Market analysts estimate Check Point holds roughly **10--12% enterprise firewall revenue share**. Its flagship line -- the **Quantum Security Gateway** family -- is widely deployed in financial services, government, and critical infrastructure, particularly in Europe and the Middle East.

Check Point reported approximately [$2.4 billion in annual revenue](https://www.checkpoint.com/press-releases/) for fiscal year 2025, with the Quantum Gateway product line representing a significant portion of network security revenue. The installed base skews toward regulated enterprises and government agencies with mature security programs -- organizations that tend to patch faster than the general population, which may contribute to the lower KEV count by reducing the window for mass exploitation.

---

## Timeline

### 2024: CVE-2024-24919 -- Nation-State Discovery, Mass Exploitation

**CVE-2024-24919** (CVSS 8.6, information disclosure / path traversal) is the most significant Check Point edge vulnerability in the KEV record and one of the defining VPN gateway incidents of 2024. The flaw allows an **unauthenticated remote attacker to read arbitrary files** from the Quantum Security Gateway -- including local account password hashes, SSH keys, certificate private keys, and Active Directory credentials cached on the device -- on any gateway with the Remote Access VPN or Mobile Access blade enabled.

#### Discovery and Disclosure Timeline

The vulnerability was discovered through a convergence of nation-state exploitation monitoring and independent security research:

- **Late April 2024:** [Mnemonic](https://www.mnemonic.io/resources/blog/advisory-check-point-remote-access-vpn-vulnerability-cve-2024-24919/), a Norwegian cybersecurity firm, detected suspicious activity on Check Point gateways in customer environments and began investigating. They identified that attackers were extracting local account credentials and using them for lateral movement.
- **May 22, 2024:** Check Point published an initial blog post warning of VPN attacks targeting devices with "old local accounts with unrecommended password-only authentication." The framing suggested a configuration weakness rather than a product vulnerability.
- **May 28, 2024:** Check Point issued a [formal advisory (sk182337)](https://support.checkpoint.com/results/sk/sk182337) assigning CVE-2024-24919 and releasing a security hotfix. The advisory acknowledged exploitation in the wild.
- **May 29, 2024:** [watchTowr Labs](https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/) published a detailed analysis demonstrating that the vulnerability was a trivial path traversal -- a single HTTP POST request to the gateway's web interface could extract any file. The PoC was simple enough to fit in a single `curl` command.
- **May 30, 2024:** [CISA added CVE-2024-24919 to the KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

#### Exploitation Scope

Within **48 hours of PoC publication**, over [10,000 internet-facing Check Point devices were observed being actively scanned](https://www.bleepingcomputer.com/news/security/check-point-warns-of-vpn-attacks-exploiting-their-zero-day-vulnerability/) by opportunistic actors beyond the initial targeted campaigns. [Censys identified approximately 13,800 internet-exposed Check Point gateways](https://censys.com/) with Remote Access VPN enabled at the time of disclosure.

The exploitation profile was distinctive: unlike Fortinet or Ivanti zero-days that were primarily attributed to China-nexus espionage groups, CVE-2024-24919's initial exploitation was attributed by multiple researchers to **Iran-nexus threat actors** who used extracted credentials to move laterally into enterprise environments. The credential-extraction primitive -- password hashes and SSH keys readable without authentication -- made the vulnerability particularly dangerous because the extracted data remained useful even after the gateway was patched, unless organizations rotated all credentials.

[Mnemonic's advisory](https://www.mnemonic.io/resources/blog/advisory-check-point-remote-access-vpn-vulnerability-cve-2024-24919/) specifically noted that attackers had been exploiting the vulnerability **since at least April 30, 2024** -- approximately four weeks before the public advisory -- confirming zero-day status with a substantial pre-disclosure exploitation window.

#### The Framing Controversy

Check Point's initial communication (May 22) characterized the issue as involving "old local accounts with unrecommended password-only authentication" -- framing that implied the problem was a configuration weakness rather than a product vulnerability. External researchers at [watchTowr](https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/) and [Mnemonic](https://www.mnemonic.io/resources/blog/advisory-check-point-remote-access-vpn-vulnerability-cve-2024-24919/) subsequently confirmed that the scope was broader than this framing implied: the path traversal primitive was trivially weaponizable against any file on the system, not limited to "old local accounts." CISA's KEV listing and a follow-on [Check Point hardening guide (sk182336)](https://support.checkpoint.com/results/sk/sk182336) both recommend treating any affected device as potentially compromised, not merely patched.

EPSS score: 0.99978 (99.98th percentile) -- reflecting near-universal exploit availability and sustained scanning activity.

### 2026: CVE-2026-50751 -- Zero-Day, Ransomware-Associated

**CVE-2026-50751** (CVSS 9.3, improper authentication) was added to the CISA KEV catalog on [June 8, 2026](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- the same day as publication, confirming exploitation was already active at disclosure. This is Check Point's second zero-day KEV entry and the first to carry a Critical CVSS score.

The vulnerability affects the Quantum Security Gateway product line. CISA flagged it for known ransomware campaign use -- a significant escalation from CVE-2024-24919, which was primarily espionage-associated at initial exploitation. The ransomware association suggests that either the initial access was sold by nation-state-affiliated access brokers to ransomware operators, or that ransomware groups have developed independent capability to exploit Check Point zero-days.

The CVSS jump from 8.6 (CVE-2024-24919, information disclosure) to 9.3 (CVE-2026-50751, authentication bypass) reflects a qualitative escalation in vulnerability class: from reading files to bypassing authentication entirely. Combined with the ransomware association, CVE-2026-50751 signals that Check Point's relatively clean historical record is not a reliable predictor of future risk.

CISA assigned a **three-day remediation deadline** (June 11, 2026) -- one of the shortest deadlines in the KEV catalog, comparable to the three-day deadline assigned to [Fortinet's CVE-2026-24858](./Fortinet.md).

EPSS score: 0.412 (98.49th percentile).

---

## CWE Weakness Profile

| Category | Count | CVEs |
|----------|------:|------|
| **Information Disclosure** (CWE-200) | 1 | CVE-2024-24919 |
| **Authentication Bypass** (CWE-287) | 1 | CVE-2026-50751 |

**Pattern:** With only two data points, a CWE pattern is suggestive rather than definitive. Both CVEs attack the authentication/credential surface: CVE-2024-24919 extracts credentials (password hashes, SSH keys) enabling lateral movement; CVE-2026-50751 bypasses authentication directly. Neither achieves RCE through memory corruption -- a pattern distinct from [Fortinet's](./Fortinet.md) buffer overflow chains, [Ivanti's](./Ivanti.md) injection chains, or [F5's](./F5.md) management-plane auth bypasses. The credential-extraction + auth-bypass pairing suggests that Check Point's vulnerability surface may center on the authentication and access-control logic of its VPN/gateway implementation rather than on memory-safety bugs in the data plane. See [CWE-ANALYSIS.md](CWE-ANALYSIS.md) for cross-vendor comparison.

---

## Threat Actor Attribution

### Nation-State Exploitation

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Iran-nexus (unspecified clusters)** | CVE-2024-24919 | [Mnemonic](https://www.mnemonic.io/resources/blog/advisory-check-point-remote-access-vpn-vulnerability-cve-2024-24919/), multiple threat intel firms |

CVE-2024-24919 is notable for being one of the few edge-device zero-days in this dataset with primary attribution to Iran-nexus actors rather than China-nexus groups. The exploitation pattern -- credential extraction for lateral movement rather than direct implant deployment on the device -- is consistent with Iranian APT operational patterns documented by [Mandiant](https://www.mandiant.com/) and [CrowdStrike](https://www.crowdstrike.com/).

### Ransomware Operators

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Multiple operators (unspecified)** | CVE-2024-24919 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **Multiple operators (unspecified)** | CVE-2026-50751 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

Both Check Point KEV entries carry CISA's ransomware association flag -- a 100% ransomware rate. For CVE-2024-24919, ransomware use likely followed the credential-harvesting phase: operators extracted VPN credentials, then used them as initial access for ransomware deployment in the target environment. For CVE-2026-50751, the ransomware association at KEV listing suggests faster operationalization, potentially through access-broker chains or independent ransomware operator capability.

See [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md) for cross-vendor attribution analysis.

---

## EPSS Context

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2024-24919 | 0.99978 | 99.98th |
| CVE-2026-50751 | 0.41152 | 98.49th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

CVE-2024-24919's near-maximum EPSS score reflects the trivial exploitability (single `curl` command) and massive scanning activity that followed PoC publication. CVE-2026-50751's lower but still elevated EPSS score (98.49th percentile) reflects its recency -- scores typically increase as exploit tooling matures and scanning broadens.

---

## The Low Count: Context, Not Comfort

Check Point has the **lowest edge KEV count (2) of all vendors in this repo**. That figure invites a default interpretation of "Check Point is safer" -- an interpretation that is incomplete and potentially dangerous. The low count reflects multiple confounding factors:

### 1. Installed Base and Research Attention

Check Point's Quantum Gateway has a smaller internet-exposed installed base than Fortinet FortiGate (which ships in vastly higher unit volumes) or Ivanti Connect Secure (which is concentrated in high-value federal targets that attract dedicated adversary research). Raw KEV counts partly reflect how intensively a product family is analyzed -- a factor [METHODOLOGY.md](../METHODOLOGY.md) calls the "popularity tax." A product with a smaller researcher community generates fewer public CVE disclosures, which can suppress counts without reflecting genuine security improvement.

### 2. Zero-Day Rate as the Corrective Signal

While the absolute count is 2, both entries are zero-days -- a 100% zero-day rate. Compare this to Fortinet (7/18 = 39%) or Cisco (4/13 = 31%). A 100% zero-day rate means that every time Check Point has appeared in the KEV catalog, it was because adversaries were already exploiting the vulnerability before the vendor could patch it. This is the most dangerous exploitation pattern: defenders have zero lead time.

### 3. Ransomware Rate

Both entries carry CISA's ransomware flag -- a 100% ransomware association rate. Compare to Fortinet (12/18 = 67%) or Cisco (1/13 = 8%). While the sample is too small for statistical confidence, the signal is that Check Point's KEV entries are operationally consequential, not theoretical.

### 4. What a Low Count Does Not Mean

A low count does not mean:
- Check Point's codebase has fewer vulnerabilities (it means fewer have been found and weaponized publicly)
- Check Point's gateway is architecturally more secure (it means fewer researchers have published chains against it)
- Organizations running Check Point face less risk (CVE-2024-24919 alone exposed 13,000+ gateways and enabled nation-state lateral movement)

A low count **does** mean:
- Fewer confirmed, cataloged exploitation events exist for this product line
- The historical data provides less signal for predicting future exploitation patterns
- Defenders have fewer case studies to inform detection and response playbooks

---

## Disclosure Assessment

### Positive Indicators

- **Patches available at advisory time (CVE-2024-24919).** Check Point released a security hotfix simultaneously with the formal advisory on May 28, 2024. There was no extended unpatched window comparable to [Citrix's 33-day CVE-2019-19781 gap](./Citrix.md).
- **No documented silent patching.** There are no documented episodes of silent patching comparable to [Fortinet's XORtigate disclosure failure](./Fortinet.md).
- **PSIRT portal accessibility.** Check Point publishes security advisories via its [PSIRT portal (sk-articles)](https://support.checkpoint.com/) with affected-version matrices and hotfix availability.

### Concerns

- **Initial framing underestimated exploitation scope (CVE-2024-24919).** The May 22 blog post characterized the issue as involving "old local accounts with unrecommended password-only authentication" -- implying a configuration problem rather than a product vulnerability. External researchers, not Check Point, confirmed the mass-scanning activity and full reach of the path traversal. This framing gap created a false sense of security during the critical pre-advisory window.
- **Pre-disclosure exploitation window.** Mnemonic documented exploitation since at least April 30, 2024 -- approximately four weeks before the public advisory. Whether Check Point was aware of exploitation during this window and the timeline of internal triage is not publicly documented.
- **Limited post-compromise guidance.** CISA and Check Point's hardening guide recommend treating affected devices as potentially compromised, but Check Point's own advisory focused primarily on patching rather than on the credential-rotation and forensic-investigation steps that the nature of the vulnerability (file-read including password hashes) demanded.

---

## Defender Implications

**1. Treat every Check Point advisory as potentially pre-compromised.** Both KEV entries were zero-days. Every Check Point patch event should be paired with a compromise assessment: check for unauthorized local accounts, unexpected VPN sessions, modified gateway configurations, and evidence of credential extraction. Patching alone is insufficient when adversaries may have already harvested credentials weeks before the advisory.

**2. Rotate all credentials after any Check Point VPN vulnerability patch.** CVE-2024-24919 specifically enabled extraction of password hashes and SSH keys. These remain valid after patching unless rotated. Treat any Check Point VPN gateway vulnerability as a credential-compromise event: rotate local account passwords, revoke and reissue SSH keys, invalidate Active Directory credentials cached on the gateway, and review all VPN session logs for suspicious lateral movement.

**3. Restrict Remote Access VPN and Mobile Access blade exposure.** CVE-2024-24919 required the Remote Access VPN or Mobile Access blade to be enabled. Audit which blades are active on each gateway and disable any that are not required. For gateways that must provide VPN access, enforce certificate-based authentication rather than password-only, and deploy MFA that does not depend on credentials stored on the gateway itself.

**4. Do not confuse low CVE count with low risk.** Check Point's 2 KEV entries represent a 100% zero-day rate, 100% ransomware rate, and demonstrated nation-state exploitation with credential extraction at scale. Organizations running Check Point should maintain the same patch-urgency posture and incident-response readiness as those running Fortinet or Ivanti -- the lower historical frequency does not reduce the severity of each individual event.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Check Point PSIRT:** [sk182337 (CVE-2024-24919 advisory)](https://support.checkpoint.com/results/sk/sk182337); [sk182336 (hardening guide)](https://support.checkpoint.com/results/sk/sk182336)
- **Mnemonic:** [Advisory: Check Point Remote Access VPN vulnerability CVE-2024-24919](https://www.mnemonic.io/resources/blog/advisory-check-point-remote-access-vpn-vulnerability-cve-2024-24919/)
- **watchTowr Labs:** [Check Point -- Wrong Check Point -- CVE-2024-24919](https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/)
- **BleepingComputer:** [Check Point warns of VPN attacks exploiting zero-day vulnerability](https://www.bleepingcomputer.com/news/security/check-point-warns-of-vpn-attacks-exploiting-their-zero-day-vulnerability/)
- **Censys:** Internet-exposed Check Point gateway enumeration
- **Gartner:** [2025 Magic Quadrant for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336)
- **NVD:** CVSS scoring and CWE classification for both CVEs
- **FIRST.org EPSS:** [Exploit Prediction Scoring System data](https://api.first.org/data/v1/epss)
