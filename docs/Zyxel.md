# Zyxel

**Scope: Zyxel ATP / USG FLEX / USG / ZyWALL / VPN series firewalls.** A significant SMB firewall vendor whose edge products have been targeted by both nation-state actors and botnet operators. *(6 edge KEV entries, 2020--2024.)*

---

## KEV CVE Summary Table

All 6 CISA KEV-listed CVEs for Zyxel edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | KEV Date | EPSS | Ransomware |
|-----|------|-----------|----------|------|:----------:|
| [CVE-2020-29583](https://nvd.nist.gov/vuln/detail/CVE-2020-29583) | 9.8 | CWE-522 Insufficiently Protected Credentials | 2021-11-03 | 90.0% | Unknown |
| [CVE-2022-30525](https://nvd.nist.gov/vuln/detail/CVE-2022-30525) | 9.8 | CWE-78 OS Command Injection | 2022-05-16 | 99.9% | Unknown |
| [CVE-2023-28771](https://nvd.nist.gov/vuln/detail/CVE-2023-28771) | 9.8 | CWE-78 OS Command Injection | 2023-05-31 | 99.3% | Unknown |
| [CVE-2023-33009](https://nvd.nist.gov/vuln/detail/CVE-2023-33009) | 9.8 | CWE-120 Buffer Overflow | 2023-06-05 | 28.1% | Unknown |
| [CVE-2023-33010](https://nvd.nist.gov/vuln/detail/CVE-2023-33010) | 9.8 | CWE-120 Buffer Overflow | 2023-06-05 | 28.8% | Unknown |
| [CVE-2024-11667](https://nvd.nist.gov/vuln/detail/CVE-2024-11667) | 7.5 | CWE-22 Path Traversal | 2024-12-03 | 3.0% | Known |

**Summary statistics:** 6 KEV entries. 5 of 6 rated CRITICAL (CVSS 9.8). 0 confirmed zero-days -- all 6 were exploited after patches existed. 1 entry (CVE-2024-11667) flagged by CISA for known ransomware campaign use. CWE-78 (OS Command Injection) appears twice and accounts for the two highest EPSS scores in the set.

---

## Market Position

Zyxel is a Taiwan-based networking vendor with a strong presence in SMB and SOHO firewall deployments, particularly in Europe and Asia-Pacific. Its firewall product lines -- ATP, USG FLEX, USG, ZyWALL, and VPN series -- are positioned as cost-effective unified threat management (UTM) appliances for small and mid-sized organizations. Zyxel does not appear in the Gartner Magic Quadrant for enterprise firewalls, but its installed base in the SMB segment is substantial.

That installed base is a structural risk multiplier. SMB customers typically operate with smaller IT teams, less mature patch-management processes, and longer mean-time-to-patch than enterprise accounts. The 2023 botnet campaign (see below) measured that gap empirically: Censys identified approximately 24,500 internet-exposed Zyxel devices still vulnerable to CVE-2023-28771 after the patch was available, and mass exploitation via Mirai variants followed within days. The SMB market that makes Zyxel's product attractive also makes its installed base disproportionately exposed once exploitation is automated.

---

## Timeline

### CVE-2020-29583: Hardcoded Credential

**[CVE-2020-29583](https://nvd.nist.gov/vuln/detail/CVE-2020-29583)** (CVSS 9.8, CWE-522, KEV 2021-11-03) is a hardcoded plaintext credential in the undocumented account `zyfwp` shipped in Zyxel firmware for ATP, USG, USG FLEX, VPN, and ZyWALL series devices. The password -- `PrOw!aN_fXp` -- was shipped in plaintext in the firmware binary, granting SSH and web-console access at an administrator privilege level to anyone who discovered it. The account could not be renamed, disabled, or have its password changed by the operator. The flaw was [disclosed by Eye Control researchers in December 2020](https://www.eyecontrol.nl/blog/undiscovered-zyxel-vulnerabilities.html); Zyxel released a patch in the same month.

CISA added it to the KEV catalog on [November 3, 2021](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- nearly a year after disclosure -- confirming sustained exploitation of unpatched devices well into 2021. The EPSS score (90.0%, 99.78th percentile) reflects the enduring exploit probability of a trivially weaponizable credential.

The hardcoded `zyfwp` account is the most elementary possible security failure in a device whose purpose is to enforce network access control. Hardcoded credentials (CWE-798 / CWE-522) are on the [OWASP Top 10 for IoT](https://owasp.org/www-pdf-archive/OWASP-IoT-Top-10-2018-final.pdf) and have been a documented vulnerability class since the 1980s. Their presence in a production security appliance shipped in 2020 indicates that Zyxel's firmware development lacked basic credential hygiene controls at the time.

---

### CVE-2022-30525: Silent Patch

**[CVE-2022-30525](https://nvd.nist.gov/vuln/detail/CVE-2022-30525)** (CVSS 9.8, CWE-78, KEV 2022-05-16) is an unauthenticated OS command injection in the CGI program of Zyxel firewall firmware, affecting ATP, USG FLEX, and VPN series devices. The flaw allowed a remote attacker without credentials to execute arbitrary OS commands on the underlying Linux system via the `setWanPortSt` function of the `zhttpd` web management interface.

Rapid7 researcher Jake Baines discovered the vulnerability and reported it to Zyxel on April 13, 2022, proposing coordinated disclosure for June 21. [Zyxel silently released a firmware patch on April 28](https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/) -- without issuing a CVE, publishing an advisory, or notifying the reporting researcher. Rapid7 discovered the silent patch on May 9 by monitoring firmware releases and [publicly disclosed the vulnerability on May 12](https://www.helpnetsecurity.com/2022/05/13/cve-2022-30525/), noting that silent patching "tends to only help active attackers, and leaves defenders in the dark about the true risk." Zyxel attributed the lapse to "miscommunication during the disclosure coordination process." CISA added it to the KEV catalog four days later, on May 16.

The vulnerability carries an EPSS score of 99.94% (99.97th percentile) -- the highest of any Zyxel entry in this dataset, reflecting both technical severity and demonstrated weaponization. Exploitation was subsequently linked to threat actors deploying persistent access to edge devices using Sandworm-associated tooling.

The CVE-2022-30525 episode is directly comparable to [Fortinet's XORtigate silent patch (CVE-2023-27997)](Fortinet.md): in both cases, a vendor released firmware containing a critical security fix without disclosure, firmware-diffing by external researchers forced the issue into the open, and CISA added the CVE within days of forced disclosure. The structural problem is the same -- firmware-only patching without discrete security advisories means adversaries can reverse-engineer the fix before defenders know the vulnerability exists.

---

### CVE-2023-28771 / 33009 / 33010: The 2023 Botnet Campaign

In spring 2023, three critical vulnerabilities in Zyxel firewalls were exploited in rapid succession by Mirai-variant botnets in what constituted a mass-exploitation campaign against Zyxel's SMB installed base.

**[CVE-2023-28771](https://nvd.nist.gov/vuln/detail/CVE-2023-28771)** (CVSS 9.8, CWE-78, KEV 2023-05-31) is a command injection vulnerability in the IKE (Internet Key Exchange) packet handler of Zyxel ZLD firmware. A remote unauthenticated attacker could execute arbitrary OS commands by sending a crafted IKE packet to the UDP 500 port -- no authentication, no user interaction required. Zyxel patched it on [April 25, 2023](https://www.zyxel.com/global/en/support/security-advisories). By late May, [Censys identified approximately 24,500 potentially vulnerable Zyxel devices](https://censys.com/blog/zyxel-vulnerabilities/) still exposed to the internet. CISA added it to the KEV catalog on May 31, 2023. An EPSS score of 99.28% (99.93rd percentile) reflects confirmed mass exploitation.

**[CVE-2023-33009](https://nvd.nist.gov/vuln/detail/CVE-2023-33009) and [CVE-2023-33010](https://nvd.nist.gov/vuln/detail/CVE-2023-33010)** (both CVSS 9.8, CWE-120, KEV 2023-06-05) are two buffer overflow vulnerabilities in Zyxel ZLD firmware's notification function and ID processing handler, respectively. Both allow unauthenticated remote attackers to cause denial-of-service conditions and potentially execute arbitrary code. Both were patched by Zyxel on May 24, 2023, and added to the KEV catalog on June 5. EPSS scores of 28.1% and 28.8% (97.9th percentile) are lower than CVE-2023-28771's, consistent with their more complex exploitation requirements.

All three CVEs were [weaponized by DDoS botnets targeting Zyxel devices](https://www.fortinet.com/blog/threat-research/ddos-botnets-target-zyxel-vulnerability-cve-2023-28771) in May-June 2023, with [Arctic Wolf](https://arcticwolf.com/resources/blog/cve-2023-33009-and-cve-2023-33010/) documenting active exploitation of all three within days of patch availability. The PoC-to-mass-exploitation timeline for CVE-2023-28771 was under two weeks. For an SMB customer base without dedicated security operations, a sub-two-week window between patch availability and mass botnet exploitation is not a realistic remediation window.

The 2023 campaign is significant beyond the Zyxel context: it is Mirai-variant operators -- originally associated with consumer IoT devices -- applying IoT-style mass exploitation techniques to "security" appliances. The attack pattern (scan internet for exposed management port, inject command via unauthenticated pre-auth interface, enroll in botnet) maps directly from compromised home routers to compromised enterprise-adjacent firewalls. The presence of ~24,500 unpatched devices on the internet weeks after patch availability is the key data point: the SMB firewall market is, in practice, exploited at IoT-like scale.

---

### CVE-2024-11667: Helldown Ransomware

**[CVE-2024-11667](https://nvd.nist.gov/vuln/detail/CVE-2024-11667)** (CVSS 7.5, CWE-22, KEV 2024-12-03) is a directory traversal vulnerability in the web management interface of Zyxel ZLD firmware, allowing unauthenticated attackers to read or write arbitrary files via crafted URLs. Zyxel patched it on November 27, 2024. CISA added it to the KEV catalog on December 3 and flagged it for known ransomware campaign use.

The [Helldown ransomware group](https://thecyberexpress.com/helldown-ransomware-targets-zyxel-firewalls/) weaponized the path traversal to steal VPN credential files from the device filesystem, then used those credentials to establish backdoor VPN connections into targeted networks. Helldown listed 31 victims on its data extortion portal within months of first documentation in August 2024, targeting small and medium-sized businesses primarily in the United States and Europe. A detailed analysis was published by [Qualys](https://threatprotect.qualys.com/2024/12/03/zyxel-firewall-directory-traversal-vulnerability-exploited-in-ransomware-attack-cve-2024-11667/) and [Sekoia](https://blog.sekoia.io/helldown-ransomware-an-overview-of-this-new-threat-actor/).

CVE-2024-11667's EPSS score (3.0%, 85.4th percentile) is the lowest in the Zyxel KEV set -- a reminder that EPSS reflects exploit probability across the full CVE population, not absolute risk to a specific organization. A 7.5 CVSS path traversal that Helldown operationalized into a full ransomware campaign entry vector is not a low-risk vulnerability for Zyxel customers regardless of its population-level EPSS.

This entry marks Zyxel's transition from botnet target (2023) to ransomware operator target (2024) -- the same trajectory seen in Sophos, Ivanti, and Citrix when their device populations became sufficiently attractive to ransomware-as-a-service operators.

---

## Transparency Assessment

Zyxel's disclosure record is mixed. The CVE-2022-30525 episode -- where Zyxel released a firmware patch without a CVE, advisory, or coordination with the reporting researcher -- is a documented silent-patch failure directly comparable to [Fortinet's XORtigate episode](Fortinet.md). Zyxel attributed it to a process failure; the structural root cause (firmware-only patching with no discrete security advisory mechanism) is the same as Fortinet's and creates the same information asymmetry: attackers can diff firmware immediately, defenders cannot act without an advisory.

For the 2023 vulnerability cluster (CVE-2023-28771, 33009, 33010), Zyxel issued advisories within standard timelines, and the disclosure process functioned. However, the April-to-June 2023 timeline also shows that timely disclosure is insufficient when the SMB customer base cannot absorb patches within the exploitation window.

Zyxel publishes security advisories via its [support portal](https://www.zyxel.com/global/en/support/security-advisories). It does not maintain a transparent CVE numbering authority (CNA) database equivalent to Fortinet's FortiGuard PSIRT, making external verification of completeness difficult.

**A notable distinction from the other vendors in this dataset:** Zyxel has zero confirmed zero-days across its 6 KEV entries. Every CVE was patched before confirmed exploitation. This is the best disclosure performance in the dataset by that specific metric -- though the silent patch on CVE-2022-30525 complicates a straightforward positive interpretation.

---

## Risk Summary

Zyxel's 6 edge KEV entries place it in the middle of the vendor distribution in this dataset. Four characteristics make the profile particularly concerning:

1. **Severity concentration:** 5 of 6 entries are CVSS 9.8 Critical -- all carrying the maximum network-accessible, no-privileges-required, no-user-interaction CVSS base score. The attack vectors are pre-auth command injection and pre-auth buffer overflow, the most reliably weaponizable primitive classes.

2. **SMB customer base as structural risk multiplier:** The 2023 botnet campaign measured this directly. ~24,500 devices remained unpatched on the internet after CVE-2023-28771 patch availability; Mirai-variant operators exploited them at scale before most SMB customers could respond. This pattern -- automated exploitation outrunning SMB patch cycles -- is more dangerous than the raw CVE count suggests.

3. **Diverse threat actor targeting:** Zyxel edge devices have been exploited by nation-state-linked operators (Sandworm-associated tooling, CVE-2022-30525), commodity botnets (Mirai variants, 2023 campaign), and ransomware groups (Helldown, CVE-2024-11667). The full spectrum of threat actor motivation -- espionage, DDoS infrastructure, and data extortion -- is represented across 6 CVEs spanning 4 years.

4. **Hardcoded credential (CVE-2020-29583):** The `zyfwp` account is a category failure that should be architecturally impossible in a product designed to enforce network access policy. Its presence in production firmware -- with a plaintext password in the binary, non-configurable by operators -- is not a single engineering error; it is evidence of absent credential hygiene controls in the firmware development process at the time.

The single positive differentiator from vendor peers: no confirmed zero-days. All 6 CVEs were exploited after patch availability. For defenders, this means the Zyxel KEV list is entirely a patch management problem -- one that the SMB customer base structurally struggles to execute.

---

## Defender Implications

**1. Zyxel patch urgency is measured in days, not weeks.** The 2023 botnet campaign demonstrated sub-two-week PoC-to-mass-exploitation timelines for CVSS 9.8 pre-auth command injection. SMB organizations managing Zyxel devices should treat any Zyxel critical advisory as a same-week emergency -- not a next-maintenance-window task -- and disable internet-accessible management interfaces until the patch is applied.

**2. Disable internet-exposed management as a baseline posture.** CVE-2022-30525 (CGI command injection), CVE-2023-28771 (IKE command injection), and CVE-2024-11667 (web management path traversal) all require access to management interfaces. The 24,500 devices Censys identified exposed during the 2023 campaign had no operational reason for their management interfaces to be internet-accessible. Restrict management access to dedicated management VLANs or VPN tunnels and firewall management ports from the internet at the perimeter.

**3. CVE-2024-11667 warrants full incident response, not just patching.** Helldown's attack chain -- path traversal to credential extraction to backdoor VPN connection -- means that any Zyxel device that was internet-accessible while running vulnerable ZLD firmware should be treated as potentially compromised. Rotate all VPN credentials, audit VPN connection logs for unauthorized sessions, and check for VPN user accounts that were not provisioned by your organization before treating the incident as closed.

**4. Monitor Zyxel firmware releases independent of advisories.** The CVE-2022-30525 silent patch demonstrates that firmware releases can contain security fixes before advisories exist. Subscribe to Zyxel's [security advisory feed](https://www.zyxel.com/global/en/support/security-advisories) and treat unexpected ZLD firmware releases in the ATP/USG FLEX line as candidates for immediate review -- following the same firmware-diffing posture that Rapid7 used to detect the silent patch.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **NVD:** CVSS scoring and CWE classification for all 6 CVEs
- **FIRST.org EPSS:** Exploit Prediction Scoring System data via [api.first.org](https://api.first.org/data/v1/epss)
- **Rapid7:** [CVE-2022-30525 disclosure and silent patch analysis](https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/)
- **Eye Control:** [CVE-2020-29583 discovery and disclosure](https://www.eyecontrol.nl/blog/undiscovered-zyxel-vulnerabilities.html)
- **Censys:** [CVE-2023-28771 exposure analysis (~24,500 vulnerable devices)](https://censys.com/blog/zyxel-vulnerabilities/)
- **Fortinet Threat Research:** [DDoS botnets targeting Zyxel CVE-2023-28771](https://www.fortinet.com/blog/threat-research/ddos-botnets-target-zyxel-vulnerability-cve-2023-28771)
- **Arctic Wolf:** [CVE-2023-33009 and CVE-2023-33010 exploitation documentation](https://arcticwolf.com/resources/blog/cve-2023-33009-and-cve-2023-33010/)
- **Qualys Threat Protection:** [CVE-2024-11667 Helldown ransomware analysis](https://threatprotect.qualys.com/2024/12/03/zyxel-firewall-directory-traversal-vulnerability-exploited-in-ransomware-attack-cve-2024-11667/)
- **Sekoia:** [Helldown ransomware overview](https://blog.sekoia.io/helldown-ransomware-an-overview-of-this-new-threat-actor/)
- **The Cyber Express:** [Helldown targeting Zyxel firewalls](https://thecyberexpress.com/helldown-ransomware-targets-zyxel-firewalls/)
- **Help Net Security:** [CVE-2022-30525 forced disclosure](https://www.helpnetsecurity.com/2022/05/13/cve-2022-30525/)
- **Zyxel PSIRT:** [Security advisory portal](https://www.zyxel.com/global/en/support/security-advisories)

---

> **Note on raw counts:** Zyxel's count of 6 should be interpreted in context. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. Zyxel attracts less researcher scrutiny than Fortinet or Palo Alto Networks, which may suppress the count relative to the actual vulnerability surface. The concentration of critical-severity pre-auth flaws, the IoT-scale botnet exploitation pattern, and the progression from botnet target to ransomware target between 2023 and 2024 suggest the risk profile is not fully captured by the count alone.
