# Fortinet (FortiGate)

**Scope: FortiOS / FortiProxy firewall and SSL-VPN.** The largest firewall vendor by unit shipment count; the SSL-VPN disclosure record is documented below. *(18 edge KEV entries, 2018-2026 -- the highest count of any vendor in this dataset.)*

---

## KEV CVE Summary Table

All 18 CISA KEV-listed CVEs for FortiOS/FortiProxy edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|----------|:--------:|:----------:|
| [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379) | 9.1 | CWE-22 Path Traversal | 2021-11-03 | N | Y |
| [CVE-2019-5591](https://nvd.nist.gov/vuln/detail/CVE-2019-5591) | 6.5 | CWE-306 Missing Authentication | 2021-11-03 | N | N |
| [CVE-2020-12812](https://nvd.nist.gov/vuln/detail/CVE-2020-12812) | 9.8 | CWE-287 Improper Authentication | 2021-11-03 | N | Y |
| [CVE-2021-44168](https://nvd.nist.gov/vuln/detail/CVE-2021-44168) | 3.3 | CWE-494 Download Without Integrity Check | 2021-12-10 | Y | N |
| [CVE-2018-13382](https://nvd.nist.gov/vuln/detail/CVE-2018-13382) | 9.1 | CWE-863 Incorrect Authorization | 2022-01-10 | N | Y |
| [CVE-2018-13383](https://nvd.nist.gov/vuln/detail/CVE-2018-13383) | 4.3 | CWE-787 Out-of-bounds Write | 2022-01-10 | N | Y |
| [CVE-2018-13374](https://nvd.nist.gov/vuln/detail/CVE-2018-13374) | 4.3 | CWE-732 Incorrect Permission Assignment | 2022-09-08 | N | Y |
| [CVE-2022-40684](https://nvd.nist.gov/vuln/detail/CVE-2022-40684) | 9.8 | CWE-287 Improper Authentication | 2022-10-11 | Y | Y |
| [CVE-2022-42475](https://nvd.nist.gov/vuln/detail/CVE-2022-42475) | 9.3 | CWE-197 Numeric Truncation Error | 2022-12-13 | Y | Y |
| [CVE-2022-41328](https://nvd.nist.gov/vuln/detail/CVE-2022-41328) | 6.5 | CWE-22 Path Traversal | 2023-03-14 | N | N |
| [CVE-2023-27997](https://nvd.nist.gov/vuln/detail/CVE-2023-27997) | 9.2 | CWE-122 Heap-based Buffer Overflow | 2023-06-13 | Y | Y |
| [CVE-2024-21762](https://nvd.nist.gov/vuln/detail/CVE-2024-21762) | 9.6 | CWE-787 Out-of-bounds Write | 2024-02-09 | Y | Y |
| [CVE-2024-23113](https://nvd.nist.gov/vuln/detail/CVE-2024-23113) | 9.8 | CWE-134 Externally-Controlled Format String | 2024-10-09 | N | N |
| [CVE-2024-55591](https://nvd.nist.gov/vuln/detail/CVE-2024-55591) | 9.6 | CWE-288 Auth Bypass via Alternate Path | 2025-01-14 | Y | Y |
| [CVE-2025-24472](https://nvd.nist.gov/vuln/detail/CVE-2025-24472) | 8.1 | CWE-288 Auth Bypass via Alternate Path | 2025-03-18 | N | Y |
| [CVE-2019-6693](https://nvd.nist.gov/vuln/detail/CVE-2019-6693) | 6.5 | CWE-798 Hard-coded Credentials | 2025-06-25 | N | Y |
| [CVE-2025-59718](https://nvd.nist.gov/vuln/detail/CVE-2025-59718) | 9.1 | CWE-347 Improper Crypto Signature Verification | 2025-12-16 | N | N |
| [CVE-2026-24858](https://nvd.nist.gov/vuln/detail/CVE-2026-24858) | 9.4 | CWE-288 Auth Bypass via Alternate Path | 2026-01-27 | Y | N |

**Summary statistics:** 18 KEV entries. 12 of 18 rated CRITICAL or HIGH (CVSS >= 7.0). 7 confirmed zero-days (exploitation observed before patch availability). 12 flagged by CISA as used in known ransomware campaigns. CWE-288 (Authentication Bypass Using an Alternate Path) appears three times -- the most repeated root cause.

---

## Market Position

FortiGate is the most widely deployed network firewall appliance by shipment volume -- Fortinet's own marketing claims [over 50% global unit market share](https://www.fortinet.com/products/next-generation-firewall). Gartner named Fortinet a Leader in the [2025 Magic Quadrant for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336). **Critical framing note:** that 50%+ figure measures appliance shipments, not revenue; revenue share is substantially lower. The large installed base directly inflates both researcher attention and raw CVE/KEV counts -- a high unit denominator is a confounding variable, not a defense.

---

## Timeline

### Pre-2020: The FortiOS SSL-VPN Credential Harvest (2018-2019 CVEs)

Four CVEs disclosed in 2018-2019 established the pattern that would define Fortinet's security posture for years to come. All four affected FortiOS SSL-VPN and were used as a credential-harvesting pipeline by state and criminal actors well into 2025.

**CVE-2018-13379** (CVSS 9.1, path traversal) was the centerpiece: a trivially exploitable flaw allowing unauthenticated attackers to read arbitrary files -- including session files containing plaintext credentials -- from FortiGate SSL-VPN portals. Disclosed [June 2019](https://www.fortiguard.com/psirt/FG-IR-18-384), it became one of the most exploited vulnerabilities in the entire CISA KEV catalog. In November 2020, a threat actor posted credentials for [approximately 50,000 FortiGate VPN devices](https://www.bleepingcomputer.com/news/security/hacker-posts-exploits-for-over-49-000-vulnerable-fortinet-vpns/) harvested via this bug. In September 2021, a second dump of [~87,000 FortiGate SSL-VPN credentials](https://www.bleepingcomputer.com/news/security/hackers-leak-passwords-for-500-000-fortinet-vpn-accounts/) appeared on criminal forums, again sourced from CVE-2018-13379 exploitation. CISA added it to the KEV catalog on [November 3, 2021](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- more than two years after initial disclosure -- alongside [FBI/CISA Alert AA21-321A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a) specifically warning of Iranian APT actors exploiting the Fortinet trifecta of CVE-2018-13379, CVE-2019-5591, and CVE-2020-12812.

**CVE-2018-13382** (CVSS 9.1, incorrect authorization) allowed unauthenticated password changes on SSL-VPN accounts via a "magic token" parameter. **CVE-2018-13383** (CVSS 4.3, heap buffer overflow) enabled authenticated users to crash the SSL-VPN daemon. **CVE-2018-13374** (CVSS 4.3, improper access control) allowed authenticated users to extract LDAP server credentials from FortiGate configurations. All were added to the KEV catalog by September 2022 ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

**CVE-2019-5591** (CVSS 6.5, missing authentication) allowed adjacent-network attackers to impersonate the LDAP server used by FortiOS due to a default configuration that lacked server identity verification. **CVE-2020-12812** (CVSS 9.8, improper authentication) bypassed FortiToken two-factor authentication entirely through a username-case manipulation -- a five-year-old bug that was still being [actively re-exploited in late 2025](https://securityaffairs.com/186117/security/five-year-old-fortinet-fortios-ssl-vpn-flaw-actively-exploited.html).

**CVE-2019-6693** (CVSS 6.5, hard-coded credentials) used a static, hard-coded encryption key to cipher sensitive data in FortiOS configuration backups. Knowledge of the key allowed an attacker to decrypt backup files and extract credentials, certificates, and configuration secrets. Despite being disclosed in [November 2019](https://www.fortiguard.com/psirt/FG-IR-19-007), it was not added to the KEV catalog until [June 25, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- indicating sustained exploitation of a six-year-old flaw. CISA flagged it with a "Known" ransomware campaign association.

### 2020-2022: Authentication Bypass and the First Zero-Days

**CVE-2022-40684** (CVSS 9.8, authentication bypass) was a true zero-day. On [October 3, 2022](https://www.fortiguard.com/psirt/FG-IR-22-377), Fortinet began privately notifying customers of a critical authentication bypass in FortiOS, FortiProxy, and FortiSwitchManager that allowed unauthenticated attackers to perform administrative operations via crafted HTTP/HTTPS requests. [CISA added it to the KEV catalog on October 11, 2022](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). A proof-of-concept exploit was [published by Horizon3.ai on October 13](https://www.horizon3.ai/attack-research/cve-2022-40684-fortinet-authentication-bypass/), and [mass exploitation escalated immediately](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-new-auth-bypass-flaw-affecting-fortigate-and-fortiproxy/). In January 2025, the Belsen Group published data from approximately [15,000 FortiGate devices](https://www.bleepingcomputer.com/news/security/hackers-leak-configs-and-vpn-credentials-for-15-000-fortigate-devices/) -- configuration dumps and VPN credentials collected in 2022 via CVE-2022-40684 exploitation.

**CVE-2022-42475** (CVSS 9.3, heap-based buffer overflow) was the first confirmed zero-day in FortiOS's SSL-VPN daemon (`sslvpnd`). [Fortinet disclosed on December 12, 2022](https://www.fortiguard.com/psirt/FG-IR-22-398), acknowledging active exploitation. CISA added it to the KEV catalog the next day, [December 13, 2022](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). [Mandiant attributed exploitation to UNC3886](https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem), a China-nexus espionage group that deployed purpose-built BOLDMOVE malware -- a custom backdoor with both Windows and FortiOS-native Linux variants, demonstrating deep familiarity with FortiGate internals ([Mandiant, MITRE ATT&CK S1184](https://attack.mitre.org/software/S1184/)).

**CVE-2022-41328** (CVSS 6.5, path traversal) allowed a local privileged attacker to read and write arbitrary files via crafted CLI commands. [CISA added it to KEV on March 14, 2023](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Mandiant attributed exploitation to the same [UNC3886 cluster](https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem), used as part of a multi-stage persistence operation alongside CVE-2022-42475.

**CVE-2021-44168** (CVSS 3.3, download without integrity check) allowed an attacker to use the `execute restore src-vis` command to download arbitrary files without integrity checking. Added to KEV on [December 10, 2021](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), its low CVSS score belies its value as a post-exploitation tool for maintaining persistence on compromised devices.

### 2023-2024: XORtigate, Pre-Auth RCE, and Format String Exploitation

**CVE-2023-27997** (CVSS 9.2, heap-based buffer overflow), dubbed "XORtigate" by researchers, is a pre-authentication remote code execution vulnerability in the FortiOS SSL-VPN daemon. Its disclosure timeline exemplifies the silent-patching problem documented below: Fortinet pushed firmware updates containing the fix approximately **3-4 days before publishing any advisory**. [watchTowr researchers](https://labs.watchtowr.com/xortigate-or-cve-2023-27997/) reproduced the vulnerability on June 11 by diffing the firmware; [Lexfo Security](https://blog.lexfo.fr/xortigate-cve-2023-27997.html) independently teased the bug on June 10. The official advisory appeared June 13, the same day [CISA added it to the KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). CISA flagged it as associated with known ransomware campaigns.

**CVE-2024-21762** (CVSS 9.6, out-of-bounds write) was a pre-authentication remote code execution in the SSL-VPN daemon. [Fortinet disclosed it on February 8, 2024](https://www.fortiguard.com/psirt/FG-IR-24-015), acknowledging it was "potentially being exploited in the wild." CISA added it to the KEV catalog the [next day, February 9](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- a near-simultaneous signal that exploitation was already active. This makes it a confirmed zero-day. CISA marked it as used in known ransomware campaigns. [Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), the China-nexus group pre-positioning in US critical infrastructure, was among the actors exploiting this CVE.

**CVE-2024-23113** (CVSS 9.8, externally-controlled format string) affected FortiOS, FortiPAM, FortiProxy, and FortiWeb. A format string vulnerability in the `fgfmd` daemon allowed unauthenticated remote code execution. [Disclosed February 15, 2024](https://www.fortiguard.com/psirt/FG-IR-24-029), it was not added to the KEV catalog until [October 9, 2024](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -- an eight-month gap suggesting delayed confirmation of in-the-wild exploitation.

### 2025-2026: Authentication Bypass Cascade and FortiCloud SSO

**CVE-2024-55591** (CVSS 9.6, authentication bypass via alternate path) allowed unauthenticated remote attackers to gain super-admin privileges via crafted requests to the Node.js websocket module in FortiOS and FortiProxy. [Arctic Wolf reported observing exploitation as early as November 2024](https://arcticwolf.com/resources/blog/console-chaos-targets-fortinet-fortigate-firewalls/) -- before Fortinet's January 14, 2025 disclosure -- making this a confirmed zero-day. Post-exploitation TTPs included creating local admin accounts, modifying firewall policies, and establishing SSL VPN tunnels. CISA [added it to KEV on January 14, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and flagged known ransomware campaign use.

**CVE-2025-24472** (CVSS 8.1, authentication bypass via alternate path) is a closely related authentication bypass in the same FortiOS/FortiProxy surface, exploitable via crafted CSF proxy requests. [CISA added it to KEV on March 18, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), also flagged for known ransomware use. CWE-288 (Authentication Bypass via Alternate Path or Channel) now accounts for three of the 18 Fortinet KEV entries (CVE-2024-55591, CVE-2025-24472, CVE-2026-24858), indicating a recurring architectural weakness in authentication flow design.

**CVE-2025-59718** (CVSS 9.1, improper verification of cryptographic signature) affected FortiOS, FortiSwitchMaster, FortiProxy, and FortiWeb. An unauthenticated attacker could bypass FortiCloud SSO login authentication via a crafted SAML message. [CISA added it to KEV on December 16, 2025](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). This vulnerability and CVE-2026-24858 together indicate systemic weaknesses in Fortinet's FortiCloud SSO implementation.

**CVE-2026-24858** (CVSS 9.4, authentication bypass via alternate path) is the most recent entry. An attacker with any valid FortiCloud account could authenticate to devices registered to *other* accounts via cross-tenant SSO token reuse -- the SSO implementation did not verify that the authenticating identity matched the device's owning account. [Arctic Wolf](https://arcticwolf.com/resources/blog/) confirmed exploitation from at least January 15, 2026. Patches were not released until January 28 -- a **13-day zero-day window**. CISA added it to the KEV catalog on [January 27](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with a **3-day remediation deadline** (January 30), one of the shortest ever assigned ([CyberScoop](https://cyberscoop.com/fortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-new-zero-day-exploited-to-hijack-firewalls/)). Products affected (Fortinet advisory FG-IR-26-060): FortiOS, FortiManager, FortiAnalyzer, FortiProxy, FortiWeb, FortiSwitchManager, FortiNAC-F. Post-exploitation TTPs documented by Arctic Wolf included config download, local admin account creation (usernames including `audit`, `backup`, `itadmin`, `secadmin`), VPN enablement, and firewall rule modification. Fortinet's emergency response included globally disabling FortiCloud SSO on January 26-27, re-enabling only for devices running patched firmware.

---

## The SSL-VPN Pattern

FortiOS's SSL-VPN daemon (`sslvpnd`) has generated four separate CISA KEV-cataloged critical vulnerabilities across a five-year span, each exploited in the wild:

| CVE | CVSS | Class | KEV Added |
|-----|------|-------|-----------|
| [CVE-2020-12812](https://securityaffairs.com/186117/security/five-year-old-fortinet-fortios-ssl-vpn-flaw-actively-exploited.html) | 9.8 | 2FA bypass (improper auth) | 2021-11-03 |
| [CVE-2022-42475](https://www.sentinelone.com/vulnerability-database/cve-2022-42475/) | 9.3 | Heap overflow pre-auth RCE | 2022-12-13 |
| [CVE-2023-27997](https://nvd.nist.gov/vuln/detail/CVE-2023-27997) (XORtigate) | 9.2 | Heap overflow pre-auth RCE | 2023-06-13 |
| [CVE-2024-21762](https://nvd.nist.gov/vuln/detail/CVE-2024-21762) | 9.6 | OOB write pre-auth RCE | 2024-02-09 |

Four pre-auth RCE-class KEV entries in a single daemon over five years is not explained by market share alone; it indicates a recurring vulnerability pattern in a specific product area.

---

## Post-Exploitation: Patching Is Not Enough

In April 2025, CISA [issued an alert](https://www.bleepingcomputer.com/news/security/fortinet-says-ssl-vpn-pre-auth-rce-bug-is-exploited-in-attacks/) after Fortinet disclosed a post-exploitation persistence technique: threat actors who had previously compromised FortiGate devices via CVE-2022-42475, CVE-2023-27997, or CVE-2024-21762 could maintain **read-only persistent access** -- including to credentials -- via symlink manipulation in the SSL-VPN filesystem, surviving firmware upgrades. Organizations that patched promptly but did not conduct full incident response were still compromised.

---

## FortiBleed Credential Dump (June 18, 2026) -- Developing Incident

On June 18, 2026, security researcher Volodymyr "Bob" Diachenko reported discovery of a credential dump affecting approximately **73,932 Fortinet firewall/VPN URLs** across 194 countries and 21,632 unique domains, found on a misconfigured attacker server. The incident was reported independently by [BleepingComputer](https://www.bleepingcomputer.com/), [Help Net Security](https://www.helpnetsecurity.com/), [Arctic Wolf](https://arcticwolf.com/resources/blog/), [SecurityAffairs](https://securityaffairs.com/), CSO Online, and [HKCERT](https://www.hkcert.org/).

Attack methods reportedly included credential stuffing from prior breach dumps, VPN hash cracking on a 45-GPU Hashtopolis cluster, and configuration file extraction. Fortinet characterized the data as "a resharing of information obtained through previous incidents and brute-force attacks."

**This is distinct from prior incidents:** the 2021 leak (~87,000 SSL-VPN credentials from [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)) and the January 2025 Belsen Group dump (~15,000 devices from [CVE-2022-40684](https://nvd.nist.gov/vuln/detail/CVE-2022-40684) data collected in 2022). Some reports link FortiBleed to CVE-2026-24858 exploitation, but this connection is **claimed, not conclusively established** -- credential stuffing and hash cracking are vendor-agnostic techniques.

**Status as of June 18, 2026:** developing. CISA has not issued a formal advisory. Claims will be re-verified as additional sources confirm or fail to corroborate.

---

## Threat Actor Attribution

Fortinet edge products have been targeted by nation-state espionage groups, ransomware operators, and state-affiliated access brokers. Attribution data from [THREAT-ACTORS.md](./THREAT-ACTORS.md) and [THREAT-ATTRIBUTION.md](./THREAT-ATTRIBUTION.md):

### China-Nexus Actors

| Actor | CVEs Exploited | Tooling | Source |
|-------|---------------|---------|--------|
| **UNC3886** | CVE-2022-42475, CVE-2022-41328 | BOLDMOVE (FortiOS-native backdoor), TINYSHELL variants | [Mandiant](https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem), [MITRE ATT&CK S1184](https://attack.mitre.org/software/S1184/) |
| **Volt Typhoon** | CVE-2024-21762, CVE-2024-23113 | Living-off-the-land techniques | [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), Microsoft, NSA, FBI, Five Eyes |
| **Earth Estries / Salt Typhoon** | Not publicly enumerated at CVE level | -- | [Trend Micro](https://www.trendmicro.com/), Microsoft |
| **BOLDMOVE actor** (unnamed) | CVE-2022-42475 | BOLDMOVE (Windows + FortiOS variants) | [Mandiant](https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem), MITRE ATT&CK |

UNC3886 demonstrated deep knowledge of FortiOS internals -- the BOLDMOVE malware was purpose-built with FortiOS-specific capabilities including disabling logging and manipulating the crash log to evade detection ([Mandiant](https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem)). The same cluster later deployed 6 custom TINYSHELL variants on Juniper MX Series routers (CVE-2025-21590), confirming a vendor-agnostic edge device specialization ([Mandiant, March 2025](https://cloud.google.com/blog/topics/threat-intelligence/); [Singapore CSA/IMDA advisory, Feb 2026](https://www.csa.gov.sg/)).

Volt Typhoon -- the PRC state-sponsored group focused on pre-positioning in US critical infrastructure for potential disruption during a geopolitical conflict -- exploited CVE-2024-21762 and CVE-2024-23113 as part of its multi-vendor campaign. Targets included energy, water, telecommunications, and transportation sectors ([CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), [Five Eyes joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)).

### Iran-Nexus Actors

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Pioneer Kitten** (Fox Kitten / Lemon Sandstorm) | CVE-2018-13379, CVE-2019-5591, CVE-2020-12812 | [FBI/CISA AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a), DC3 |

Pioneer Kitten is operationally distinctive: an Iran state-sponsored group that monetizes access by collaborating with ransomware affiliates (AlphV/BlackCat, RansomHouse, NoEscape). They exploited Fortinet VPN credentials harvested via the 2018-2019 CVE trio ([FBI/CISA AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a)).

### Ransomware Operators

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Cring** (Crypt3r / Ghost / Phantom) | CVE-2018-13379 | [Kaspersky ICS-CERT](https://ics-cert.kaspersky.com/) |
| **LockBit** | Fortinet VPN infrastructure (specific CVE unspecified) | [CISA AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) |

Cring ransomware targeted unpatched FortiGate VPN servers, with a focus on European manufacturing and industrial networks ([Kaspersky ICS-CERT](https://ics-cert.kaspersky.com/)). CISA flagged 12 of 18 Fortinet KEV entries as associated with known ransomware campaigns -- the highest ransomware association rate in the dataset.

### Unattributed

CVE-2026-24858 has no confirmed threat actor attribution as of June 2026. Coalition documented **14 zero-day advisories for critical Fortinet flaws in under four years** -- Fortinet accounts for over 7% of all zero-day advisories Coalition has issued ([CyberScoop](https://cyberscoop.com/fortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/)).

---

## Disclosure Assessment

### Silent Patching: XORtigate as the Documented Example

In June 2023, Fortinet silently pushed firmware updates containing a fix for CVE-2023-27997 -- a CVSS 9.2 pre-auth heap overflow -- approximately **3-4 days before publishing any advisory**. [watchTowr researchers](https://labs.watchtowr.com/xortigate-or-cve-2023-27997/) reproduced the vulnerability on June 11 by diffing the firmware; [Lexfo Security](https://blog.lexfo.fr/xortigate-cve-2023-27997.html) had independently teased the bug on June 10. The official advisory appeared June 13.

The structural problem: Fortinet does not release discrete security patches. Customers must upgrade entire firmware builds. Without a CVE or advisory, administrators had no basis to assess urgency, while adversaries had a reverse-engineering head-start on the same patch delta defenders could not see. For a high-severity vulnerability, that is a poor disclosure design.

### Credential Leak History

Fortinet products have been the source of at least three large-scale credential dumps:

1. **November 2020:** ~50,000 FortiGate VPN credentials posted publicly, harvested via [CVE-2018-13379](https://www.bleepingcomputer.com/news/security/hacker-posts-exploits-for-over-49-000-vulnerable-fortinet-vpns/)
2. **September 2021:** ~87,000 FortiGate SSL-VPN credentials leaked on criminal forums, again from [CVE-2018-13379](https://www.bleepingcomputer.com/news/security/hackers-leak-passwords-for-500-000-fortinet-vpn-accounts/)
3. **January 2025:** ~15,000 FortiGate device configuration dumps and VPN credentials released by the Belsen Group, collected in 2022 via [CVE-2022-40684](https://www.bleepingcomputer.com/news/security/hackers-leak-configs-and-vpn-credentials-for-15-000-fortigate-devices/)

These three incidents collectively exposed credentials for over 150,000 devices. The FortiBleed dump of June 2026 (~73,932 URLs) is potentially a fourth, though its sourcing is contested.

### What the Metrics Show

- **KEV density:** 18 edge KEV entries -- the highest of any vendor in the dataset. While market share is a confounding variable, four pre-auth RCE entries in the SSL-VPN daemon alone is not explained by unit count.
- **Zero-day frequency:** 7 of 18 KEV entries were confirmed zero-days (exploitation before patch). Coalition documented 14 zero-day advisories for Fortinet in under four years ([CyberScoop](https://cyberscoop.com/fortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/)).
- **Ransomware association:** 12 of 18 KEV entries (67%) are flagged by CISA for known ransomware campaign use.
- **Transparency:** Silent patching plus firmware-only distribution is a disclosure anti-pattern. The XORtigate episode is the documented instance; the pattern may be more widespread.
- **Persistent access surviving patches:** Documented by CISA in April 2025 via symlink manipulation across three separate CVEs.

---

## Defender Implications

**1. Treat every FortiGate patch as an incident trigger, not just a maintenance task.** The April 2025 CISA alert on symlink persistence ([BleepingComputer](https://www.bleepingcomputer.com/news/security/fortinet-says-ssl-vpn-pre-auth-rce-bug-is-exploited-in-attacks/)) proved that patching CVE-2022-42475, CVE-2023-27997, or CVE-2024-21762 without conducting forensic investigation left organizations compromised. After applying any critical FortiOS patch, check for post-exploitation artifacts -- specifically symlinks in the SSL-VPN filesystem, unauthorized admin accounts, and modified firewall rules. Fortinet published [guidance on symlink detection](https://www.fortiguard.com/psirt/) alongside the CISA alert.

**2. Monitor firmware releases even before advisories appear.** Fortinet's disclosure pattern -- firmware-first, advisory days later -- means defenders who wait for the CVE or advisory lose time. Subscribe to Fortinet's firmware release RSS/notification channel and treat any unexpected FortiOS build with SSL-VPN changes as a candidate for urgent deployment, then diff the release notes when the advisory surfaces. Researchers at [watchTowr](https://labs.watchtowr.com/) and [Lexfo](https://blog.lexfo.fr/) have demonstrated that adversaries perform the same firmware diffing.

**3. Assume credential exposure and rotate proactively.** Three confirmed large-scale credential dumps (2020, 2021, 2025) plus the contested FortiBleed incident (2026) mean FortiGate VPN credentials should be treated as potentially compromised at the population level. Enforce MFA on all SSL-VPN accounts, rotate local admin credentials on a defined schedule, and audit FortiCloud SSO configurations following CVE-2025-59718 and CVE-2026-24858. The hard-coded encryption key in CVE-2019-6693 means any configuration backup created on a vulnerable firmware version should be treated as extractable -- re-key after upgrading.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [AA21-321A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a) (Iranian APT exploitation of Fortinet); [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) (Volt Typhoon); [AA24-241A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a) (Pioneer Kitten); April 2025 symlink persistence alert
- **Mandiant / Google Threat Intelligence Group:** UNC3886 FortiOS campaign; BOLDMOVE malware analysis; [M-Trends 2025](https://www.mandiant.com/m-trends)
- **Fortinet FortiGuard PSIRT:** [FG-IR-18-384](https://www.fortiguard.com/psirt/FG-IR-18-384) (CVE-2018-13379); [FG-IR-22-377](https://www.fortiguard.com/psirt/FG-IR-22-377) (CVE-2022-40684); [FG-IR-22-398](https://www.fortiguard.com/psirt/FG-IR-22-398) (CVE-2022-42475); [FG-IR-24-015](https://www.fortiguard.com/psirt/FG-IR-24-015) (CVE-2024-21762); FG-IR-26-060 (CVE-2026-24858)
- **Arctic Wolf:** [CVE-2024-55591 zero-day documentation](https://arcticwolf.com/resources/blog/console-chaos-targets-fortinet-fortigate-firewalls/); CVE-2026-24858 zero-day timeline
- **watchTowr Labs:** [XORtigate firmware diffing analysis](https://labs.watchtowr.com/xortigate-or-cve-2023-27997/)
- **Lexfo Security:** [CVE-2023-27997 independent discovery](https://blog.lexfo.fr/xortigate-cve-2023-27997.html)
- **Horizon3.ai:** [CVE-2022-40684 proof-of-concept](https://www.horizon3.ai/attack-research/cve-2022-40684-fortinet-authentication-bypass/)
- **BleepingComputer:** Credential dump reporting (2020, 2021, 2025, 2026)
- **CyberScoop:** [Coalition zero-day advisory statistics](https://cyberscoop.com/fortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/)
- **Kaspersky ICS-CERT:** Cring ransomware / FortiGate VPN exploitation
- **NVD:** CVSS scoring and CWE classification for all 18 CVEs
- **FIRST.org EPSS:** Exploit Prediction Scoring System data via [api.first.org](https://api.first.org/data/v1/epss)
