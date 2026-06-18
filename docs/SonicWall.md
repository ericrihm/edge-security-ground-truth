# SonicWall

**Scope: SonicOS firewall / SSL-VPN and SMA remote-access appliances.** A major mid-market and SMB firewall vendor whose edge products have been systematically targeted by ransomware operators and, in one documented case, state-sponsored actors. *(12 edge KEV entries, 2019--2026 -- see [the comparison](../README.md).)*

---

## Market Position

SonicWall holds significant share in mid-market and SMB firewall/SSL-VPN deployments, with devices widely used in financial services, healthcare, and local government. Its SMB-first installed base is structurally slower to patch than enterprise peers -- a risk multiplier that attackers have actively exploited. SonicWall operates two distinct product families in scope: **SonicOS** (TZ, NSa, NSsp series firewalls with integrated SSL-VPN) and **SMA** (Secure Mobile Access 100/1000 series remote-access gateways).

---

## KEV Summary Table

| CVE | CVSS | CWE Class | Product | KEV Added | Zero-Day | Ransomware |
|-----|------|-----------|---------|-----------|:--------:|:----------:|
| [CVE-2019-7481](https://nvd.nist.gov/vuln/detail/CVE-2019-7481) | 7.5 | CWE-89 SQL Injection | SMA100 | Nov 3 2021 | N | Y |
| [CVE-2019-7483](https://nvd.nist.gov/vuln/detail/CVE-2019-7483) | 7.5 | CWE-22 Path Traversal | SMA100 | Mar 28 2022 | N | N |
| [CVE-2020-5135](https://nvd.nist.gov/vuln/detail/CVE-2020-5135) | 9.8 | CWE-120 Buffer Overflow | SonicOS | Mar 15 2022 | N | N |
| [CVE-2021-20016](https://nvd.nist.gov/vuln/detail/CVE-2021-20016) | 9.8 | CWE-89 SQL Injection | SMA100 SSL-VPN | Nov 3 2021 | Y | Y |
| [CVE-2021-20028](https://nvd.nist.gov/vuln/detail/CVE-2021-20028) | 9.8 | CWE-89 SQL Injection | SRA | Mar 28 2022 | N | Y |
| [CVE-2021-20035](https://nvd.nist.gov/vuln/detail/CVE-2021-20035) | 6.5 | CWE-78 OS Command Injection | SMA100 | Apr 16 2025 | N | N |
| [CVE-2021-20038](https://nvd.nist.gov/vuln/detail/CVE-2021-20038) | 9.8 | CWE-121 Stack Buffer Overflow | SMA100 | Jan 28 2022 | N | Y |
| [CVE-2023-44221](https://nvd.nist.gov/vuln/detail/CVE-2023-44221) | 7.2 | CWE-78 OS Command Injection | SMA100 | May 1 2025 | N | N |
| [CVE-2024-40766](https://nvd.nist.gov/vuln/detail/CVE-2024-40766) | 9.3 | CWE-284 Improper Access Control | SonicOS | Sep 9 2024 | N | Y |
| [CVE-2024-53704](https://nvd.nist.gov/vuln/detail/CVE-2024-53704) | 8.2 | CWE-287 Improper Authentication | SonicOS SSL-VPN | Feb 18 2025 | N | Y |
| [CVE-2025-23006](https://nvd.nist.gov/vuln/detail/CVE-2025-23006) | 9.8 | CWE-502 Deserialization of Untrusted Data | SMA1000 | Jan 24 2025 | Y | Y |
| [CVE-2025-40602](https://nvd.nist.gov/vuln/detail/CVE-2025-40602) | 6.6 | CWE-862 Missing Authorization | SMA1000 | Dec 17 2025 | N | N |

**12 edge KEV entries.** Seven carry a "Known" ransomware campaign designation in CISA's catalog. Two were confirmed zero-days (exploited before patches existed). Five are rated Critical (CVSS >= 9.0). The CWE distribution is dominated by injection classes: SQL injection (3), OS command injection (2), buffer overflow (2), authentication/authorization flaws (3), deserialization (1), and path traversal (1).

---

## Timeline

### Pre-2020: Legacy SMA Vulnerabilities

Two CVEs from 2019 -- both affecting the SMA100 product line -- were cataloged by CISA years after their initial disclosure, reflecting ongoing exploitation of unpatched legacy devices:

**[CVE-2019-7481](https://nvd.nist.gov/vuln/detail/CVE-2019-7481)** (CVSS 7.5, SQL injection) was published in December 2019 but not added to the KEV catalog until November 2021. The vulnerability allows unauthenticated read-only access to the SMA100 database. Its EPSS score of 0.999 (99.9th percentile) reflects sustained mass-exploitation against the long tail of unpatched SMA devices. [CrowdStrike documented](https://www.crowdstrike.com/blog/how-ecrime-groups-leverage-sonicwall-vulnerability-cve-2019-7481/) that eCrime groups were leveraging this vulnerability for initial access to corporate networks well into 2021.

**[CVE-2019-7483](https://nvd.nist.gov/vuln/detail/CVE-2019-7483)** (CVSS 7.5, path traversal) in the SMA100's `handleWAFRedirect` CGI handler enables unauthenticated directory traversal. Added to KEV in March 2022.

### 2020--2022: The SMA100 Crisis and SonicWall's Own Breach

This period saw a concentration of critical vulnerabilities in SonicWall's SMA remote-access line and SonicOS firewalls, including one that was used to breach SonicWall itself.

**[CVE-2020-5135](https://nvd.nist.gov/vuln/detail/CVE-2020-5135)** (CVSS 9.8, buffer overflow) is a stack-based buffer overflow in SonicOS, reachable pre-authentication via the HTTP/HTTPS service. [Tripwire's VERT team](https://www.tripwire.com/state-of-security/vert-threat-alert-sonicwall-vpn-portal-critical-flaw-cve-2020-5135) reported it in October 2020. At the time of disclosure, approximately 795,000 SonicWall VPN devices were internet-facing per Shodan scans cited in multiple reports. CISA added it to KEV in March 2022.

**[CVE-2021-20016](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)** (CVSS 9.8, SQL injection) is the vulnerability used to breach SonicWall's own internal systems. In January 2021, SonicWall disclosed that attackers had exploited a zero-day SQL injection in its SMA100 SSL-VPN product to compromise SonicWall's internal network. [SonicWall's advisory](https://www.sonicwall.com/support/notices/urgent-security-notice-netextender-vpn-client-10-x-sma-100-series-vulnerability-updated-feb-19-2-p-m-cst/210122173415410/) confirmed that the vulnerability was exploited in the wild before any patch was available -- a true zero-day. [NCC Group's analysis](https://research.nccgroup.com/2021/04/20/technical-advisory-sonicwall-sma-100-series-cve-2021-20016/) provided technical details. Patches were released in February 2021; CISA added it to KEV in November 2021.

**[CVE-2021-20028](https://nvd.nist.gov/vuln/detail/CVE-2021-20028)** (CVSS 9.8, SQL injection) affects the older SRA (Secure Remote Access) product line, which had already reached end-of-life. This unauthenticated SQL injection was added to KEV in March 2022 with the "Known" ransomware flag.

**[CVE-2021-20038](https://nvd.nist.gov/vuln/detail/CVE-2021-20038)** (CVSS 9.8, stack buffer overflow) in the SMA100's Apache httpd `mod_cgi` module provides unauthenticated remote code execution. [Rapid7's AttackerKB entry](https://attackerkb.com/topics/QyXRC65szE/cve-2021-20038) documented the severity. CISA added it in January 2022 with the ransomware flag. Its EPSS score of 0.999 reflects mass-exploitation.

### 2023--2024: From SMA to SonicOS -- CVE-2024-40766 and the Akira/Fog Campaign

**[CVE-2023-44221](https://nvd.nist.gov/vuln/detail/CVE-2023-44221)** (CVSS 7.2, OS command injection) affects the SMA100 SSL-VPN management interface. Published in December 2023 but not added to KEV until May 2025, indicating a delayed recognition of in-the-wild exploitation. Requires admin-level authentication, which limits the attack surface but does not eliminate it -- compromised admin credentials or credential-stuffing attacks against management interfaces are standard techniques. Its EPSS score of 0.751 reflects active exploitation.

**[CVE-2024-40766](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)** (CVSS 9.3, improper access control) is an improper access control flaw in the SonicOS management interface and SSL-VPN, affecting Gen 5, Gen 6, and Gen 7 devices. SonicWall disclosed it on August 22, 2024. [CISA added it to the KEV catalog on September 9, 2024](https://www.helpnetsecurity.com/2024/09/10/cve-2024-40766-exploited/).

Within weeks, Akira and Fog ransomware affiliates were operating a sustained campaign through unpatched SonicWall SSL VPNs. [Arctic Wolf documented over 30 Akira and Fog ransomware intrusions exploiting CVE-2024-40766 (roughly three-quarters Akira)](https://securityaffairs.com/170359/cyber-crime/fog-akira-ransomware-sonicwall-vpn-flaw.html), with full network encryption achieved in under ten hours in documented cases. A structural contributor accelerated the attacks: operators who migrated from Gen 6 to Gen 7 hardware frequently reused credentials without resetting passwords, leaving accounts exposed even on nominally updated hardware. [Rapid7's September 2024 analysis](https://www.rapid7.com/blog/post/2024/09/09/etr-cve-2024-40766-critical-improper-access-control-vulnerability-affecting-sonicwall-devices/) characterized exploitation evidence at the time as circumstantial but escalating rapidly -- the KEV addition confirmed active exploitation the same day.

The campaign did not end in 2024. Arctic Wolf observed a [renewed uptick in July 2025](https://arcticwolf.com/resources/blog/arctic-wolf-observes-july-2025-uptick-in-akira-ransomware-activity-targeting-sonicwall-ssl-vpn/), and the broader peak followed in August 2025, when [Huntress documented 28 incidents within a single week](https://thehackernews.com/2025/08/sonicwall-confirms-patched.html) and SonicWall clarified publicly that the activity was not a zero-day but exploitation of the same year-old CVE against unpatched or misconfigured devices.

> **Note:** A figure of approximately 438,000 exposed devices has circulated in commentary, but it could not be confirmed against any primary source (CISA, NVD, Rapid7, Huntress, or Arctic Wolf) and is not used as evidence here.

### 2025+: SMA1000 Zero-Day and Continued SMA Exploitation

**[CVE-2025-23006](https://nvd.nist.gov/vuln/detail/CVE-2025-23006)** (CVSS 9.8, deserialization of untrusted data) is a pre-authentication deserialization vulnerability in the SMA1000 Appliance Management Console (AMC) and Central Management Console (CMC). SonicWall disclosed it on January 22, 2025, warning that it had been "exploited in the wild as a zero-day." [CISA added it to KEV on January 24](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-zero-day-flaw-exploited-in-the-wild/) -- two days after disclosure. [Microsoft Threat Intelligence Center](https://twitter.com/MsftSecIntel) attributed exploitation activity, though the specific threat actor was not publicly named. The CISA catalog flags it as associated with known ransomware campaigns.

**[CVE-2024-53704](https://nvd.nist.gov/vuln/detail/CVE-2024-53704)** (CVSS 8.2, improper authentication) is an authentication bypass in the SonicOS SSL-VPN mechanism. Published in January 2025 and added to KEV on February 18, 2025. [Bishop Fox published a proof-of-concept](https://bishopfox.com/blog/sonicwall-sslvpn-authentication-bypass-cve-2024-53704) demonstrating that attackers could hijack active SSL-VPN sessions without credentials. The CISA catalog marks it as associated with known ransomware campaigns.

**[CVE-2021-20035](https://nvd.nist.gov/vuln/detail/CVE-2021-20035)** (CVSS 6.5, OS command injection) in the SMA100 management interface was originally published in September 2021 but not added to KEV until April 2025, nearly four years later. SonicWall initially rated it as a low-severity DoS issue; the scope was later revised upward to include potential code execution, and exploitation in the wild was confirmed. [Arctic Wolf reported](https://arcticwolf.com/resources/blog/arctic-wolf-observes-sonicwall-cve-2021-20035-being-exploited-in-the-wild/) active exploitation in early 2025.

**[CVE-2025-40602](https://nvd.nist.gov/vuln/detail/CVE-2025-40602)** (CVSS 6.6, missing authorization) is a privilege escalation in the SMA1000 appliance management interface. CISA added it to KEV on December 17, 2025. The vulnerability allows an authenticated attacker to escalate to appliance-level management capabilities.

---

## MySonicWall Cloud Backup Breach (September 2025)

In September 2025, SonicWall disclosed suspicious activity targeting its MySonicWall cloud backup service. The root cause was [an API code change introduced in February 2025](https://www.bleepingcomputer.com/news/security/marquis-sues-sonicwall-over-backup-breach-that-led-to-ransomware-attack/) that opened an access gap, subsequently exploited via brute-force attacks. Exposed files contained AES-256-encrypted credentials, MFA scratch codes, VPN configurations, network topology, and firewall rules.

The disclosure pattern is the second story. SonicWall's initial advisory claimed fewer than 5% of customers were affected. After a Mandiant-led investigation concluded on October 8, 2025, [SonicWall revised that figure to all customers who had used the cloud backup service](https://www.cybersecuritydive.com/news/sonicwall-investigation-hackers-access-customer-backup/802598/). Mandiant attributed the intrusion to state-sponsored actors. No public explanation for the 5%-to-100% discrepancy was provided.

The stolen configurations did not sit idle. On August 14, 2025 -- before SonicWall's first public disclosure -- attackers used configuration data extracted from the breach to compromise a SonicWall firewall at Marquis Software Solutions, a vendor serving more than 700 financial institutions. The resulting ransomware attack affected 74 U.S. banks and exposed personal and financial data including Social Security numbers. [Marquis filed suit against SonicWall in February 2026](https://techcrunch.com/2026/02/24/marquis-sonicwall-lawsuit-ransomware-firewall-breach/), alleging gross negligence and misrepresentation. Marquis itself now faces more than 36 consumer class-action lawsuits downstream.

---

## Threat Actor Attribution

### Ransomware: Akira and Fog

SonicWall's primary documented threat is ransomware, not espionage.

**Akira** is a ransomware group that systematically exploited CVE-2024-40766 (SonicOS SSL-VPN access control flaw) for initial access. [Arctic Wolf documented](https://arcticwolf.com/resources/blog/arctic-wolf-observes-july-2025-uptick-in-akira-ransomware-activity-targeting-sonicwall-ssl-vpn/) that Akira was responsible for approximately 75% of the 30+ documented SonicWall ransomware intrusions, with full network encryption achieved in under 10 hours. The campaign ran from September 2024 through at least August 2025.

**Fog** ransomware accounted for roughly 25% of the same intrusion set, also exploiting CVE-2024-40766, with targeting concentrated in education and SMB sectors ([Arctic Wolf](https://securityaffairs.com/170359/cyber-crime/fog-akira-ransomware-sonicwall-vpn-flaw.html)).

### State-Sponsored: MySonicWall Breach Actor (Unnamed)

Mandiant attributed the MySonicWall cloud backup breach to a state-sponsored actor, but neither Mandiant nor SonicWall disclosed the nation of origin. The actor exploited an API access gap (not a CVE-listed vulnerability) in SonicWall's own cloud infrastructure -- targeting the vendor's service platform rather than customer-premise devices directly ([Cybersecurity Dive](https://www.cybersecuritydive.com/news/sonicwall-investigation-hackers-access-customer-backup/802598/)).

### Actor Classification

Per the [Threat Actor analysis](THREAT-ACTORS.md), SonicWall's threat profile is classified as **Ransomware + unattributed state actor**: ransomware is the documented primary threat, and the MySonicWall breach was attributed to a state actor by Mandiant but the nation was not disclosed. SonicWall is one of three vendors in this dataset (alongside Zyxel and Check Point) with no confirmed China-nexus targeting -- its installed base skews toward SMB markets that are less strategically valuable for espionage targeting.

---

## Transparency Assessment: Poor

Two incidents, two instances of minimized initial disclosure:

1. **MySonicWall breach scope understatement.** SonicWall's initial advisory claimed fewer than 5% of customers were affected. Mandiant's completed investigation revised that to 100% of cloud backup customers. The 20x understatement was held for three weeks.

2. **CVE-2024-40766 advisory gaps.** The advisory cycle did not prominently communicate the Gen6-to-Gen7 credential migration risk that contributed to mass exploitation. Organizations upgrading hardware had no vendor guidance to reset credentials during migration.

3. **CVE-2021-20035 severity understatement.** SonicWall initially classified this as a low-severity DoS vulnerability. The scope was later revised to include code execution after exploitation was confirmed in the wild -- nearly four years after the original advisory.

4. **SonicWall's own breach (CVE-2021-20016).** When SonicWall's internal systems were compromised via its own product's zero-day in January 2021, the initial disclosure was terse and the timeline was compressed. [NCC Group](https://research.nccgroup.com/2021/04/20/technical-advisory-sonicwall-sma-100-series-cve-2021-20016/) and external researchers provided more technical detail than SonicWall's own advisories.

Unlike a vendor that patches silently and then issues a retrospective advisory, SonicWall's pattern is to disclose but to disclose inaccurately or incompletely -- which may be worse for operators trying to triage exposure.

---

## CWE Pattern Analysis

The 12 KEV entries break down into three dominant vulnerability classes:

- **Injection (SQL + OS command): 5 of 12.** CVE-2019-7481, CVE-2021-20016, CVE-2021-20028 (SQL injection); CVE-2021-20035, CVE-2023-44221 (OS command injection). Three of the SQL injections are pre-auth and affect the SMA product line, indicating a recurring input validation failure in SMA's web layer.

- **Memory safety (buffer overflow): 2 of 12.** CVE-2020-5135, CVE-2021-20038 -- both stack/heap-based overflows allowing unauthenticated RCE. Both rated CVSS 9.8.

- **Authentication/authorization: 3 of 12.** CVE-2024-40766 (improper access control), CVE-2024-53704 (authentication bypass), CVE-2025-40602 (missing authorization). The 2024-2025 cluster suggests that access control in SonicOS and SMA management interfaces is a systemic weak point.

The SMA product line accounts for **8 of 12 KEV entries** -- a concentration that indicates the SMA remote-access gateway has been SonicWall's most vulnerable edge product over the tracking period.

---

## Defender Implications

**1. Treat SonicWall hardware migrations as security events, not IT projects.** The CVE-2024-40766 campaign demonstrated that credential reuse during Gen 6 to Gen 7 migrations was a documented force multiplier for Akira/Fog ransomware. Any hardware refresh or firmware migration must include a full credential reset for all SSL-VPN accounts, admin interfaces, and local accounts. [Arctic Wolf](https://arcticwolf.com/resources/blog/arctic-wolf-observes-july-2025-uptick-in-akira-ransomware-activity-targeting-sonicwall-ssl-vpn/) documented this explicitly.

**2. Assume SMA appliances are high-priority targets requiring aggressive patch cadence.** Eight of twelve KEV entries target SMA products. The SMA100 and SMA1000 lines have produced SQL injection, buffer overflow, command injection, and deserialization vulnerabilities across a six-year span. Organizations running SMA appliances should prioritize emergency patching of any SMA advisory, enforce MFA on all management and VPN interfaces, and restrict management plane access to trusted networks. CVE-2025-23006 was a confirmed zero-day -- patching speed is the only lever.

**3. Evaluate vendor-side cloud service risk independently from appliance risk.** The MySonicWall cloud backup breach demonstrated that a vendor's cloud infrastructure can become the attack vector against the entire customer base, independent of appliance firmware vulnerabilities. Defenders using SonicWall's cloud backup or management services should assess whether the configurations stored in those services (credentials, VPN configs, firewall rules, network topology) create unacceptable exposure if exfiltrated. The Marquis downstream attack -- 74 banks compromised via stolen firewall configurations -- is the realized scenario.

---

> **Note on raw counts:** SonicWall's count of 12 should be interpreted in context. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. SonicWall's large SMB installed base makes it a high-density target for both vulnerability research and ransomware campaigns. However, the concentration of critical pre-auth vulnerabilities in the SMA product line (8 of 12 entries) and the vendor's own breach via its own product's zero-day indicate risk factors beyond what market share alone explains.
