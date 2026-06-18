# Zyxel

**Scope: Zyxel ATP / USG FLEX / USG / ZyWALL / VPN series firewalls.** A significant SMB firewall vendor whose edge products have been targeted by both nation-state actors and botnet operators. *(6 edge KEV entries, 2020--2026.)*

---

## Market Position

Zyxel is a Taiwan-based networking vendor with a strong presence in SMB and SOHO firewall deployments, particularly in Europe and Asia-Pacific. Its firewall product lines -- ATP, USG FLEX, USG, ZyWALL, and VPN series -- are positioned as cost-effective unified threat management (UTM) appliances for small and mid-sized organizations. Zyxel does not appear in the Gartner Magic Quadrant for enterprise firewalls, but its installed base in the SMB segment is substantial. That installed base -- often managed by smaller IT teams with slower patch cycles -- is a structural risk multiplier that attackers have demonstrably exploited.

---

## Key Incidents

| CVE | CVSS | Class | Product | KEV Added |
|-----|------|-------|---------|-----------|
| [CVE-2020-29583](https://nvd.nist.gov/vuln/detail/CVE-2020-29583) | 9.8 | Hardcoded credentials | Multiple Products (ATP, USG, VM firewalls) | Nov 3 2021 |
| [CVE-2022-30525](https://nvd.nist.gov/vuln/detail/CVE-2022-30525) | 9.8 | OS command injection (pre-auth) | Multiple Firewalls | May 16 2022 |
| [CVE-2023-28771](https://nvd.nist.gov/vuln/detail/CVE-2023-28771) | 9.8 | OS command injection (pre-auth) | Multiple Firewalls | May 31 2023 |
| [CVE-2023-33009](https://nvd.nist.gov/vuln/detail/CVE-2023-33009) | 9.8 | Buffer overflow (pre-auth) | Multiple Firewalls | Jun 5 2023 |
| [CVE-2023-33010](https://nvd.nist.gov/vuln/detail/CVE-2023-33010) | 9.8 | Buffer overflow (pre-auth) | Multiple Firewalls | Jun 5 2023 |
| [CVE-2024-11667](https://nvd.nist.gov/vuln/detail/CVE-2024-11667) | 7.5 | Path traversal | Multiple Firewalls | Dec 3 2024 |

All six edge KEV entries carry a CVSS score of 7.5 or higher; five of the six are rated 9.8 Critical.

---

### CVE-2022-30525: Silent Patch and Nation-State Exploitation

[CVE-2022-30525](https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/) is an unauthenticated OS command injection in the CGI program of Zyxel firewall firmware, affecting ATP, USG FLEX, and VPN series devices. Rapid7 researcher Jake Baines discovered the flaw and reported it to Zyxel on April 13, 2022, proposing coordinated disclosure for June 21.

Zyxel silently released a firmware patch on April 28 -- **without issuing a CVE or advisory** -- and without coordinating with the reporting researcher. Rapid7 discovered the silent patch on May 9 and [publicly disclosed the vulnerability on May 12](https://www.helpnetsecurity.com/2022/05/13/cve-2022-30525/), noting that silent patching "tends to only help active attackers, and leaves defenders in the dark about the true risk." Zyxel attributed the lapse to "miscommunication during the disclosure coordination process." CISA added it to the KEV catalog on May 16 -- four days after public disclosure.

The vulnerability was subsequently linked to exploitation by threat actors with Sandworm-associated tooling, used to establish persistent access to edge devices.

### CVE-2023-28771 / 33009 / 33010: The 2023 Botnet Campaign

In spring 2023, three critical vulnerabilities in Zyxel firewalls were exploited in rapid succession by Mirai-variant botnets in what constituted a mass-exploitation campaign:

- **[CVE-2023-28771](https://www.helpnetsecurity.com/2023/06/01/cve-2023-28771-exploited/)** (patched April 2023, KEV May 31): A command injection via crafted IKE packets allowing unauthenticated remote OS command execution. [Censys identified approximately 24,500 potentially vulnerable Zyxel devices](https://censys.com/blog/zyxel-vulnerabilities/) exposed to the internet at the time of exploitation.

- **[CVE-2023-33009 and CVE-2023-33010](https://arcticwolf.com/resources/blog/cve-2023-33009-and-cve-2023-33010/)** (patched May 24, 2023, KEV June 5): Two buffer overflow vulnerabilities enabling unauthenticated denial-of-service and remote code execution. Both were exploited within days of patch availability.

The three-CVE cluster was exploited by [DDoS botnets targeting Zyxel devices](https://www.fortinet.com/blog/threat-research/ddos-botnets-target-zyxel-vulnerability-cve-2023-28771) within weeks of disclosure. The speed of weaponization -- PoC to mass exploitation in under two weeks for CVE-2023-28771 -- indicates that Zyxel's SMB customer base could not absorb patches fast enough to outrun automated exploitation.

### CVE-2024-11667: Helldown Ransomware

[CVE-2024-11667](https://threatprotect.qualys.com/2024/12/03/zyxel-firewall-directory-traversal-vulnerability-exploited-in-ransomware-attack-cve-2024-11667/) is a directory traversal vulnerability in the web management interface of Zyxel ZLD firewall firmware, allowing attackers to download or upload arbitrary files via crafted URLs. The [Helldown ransomware group](https://thecyberexpress.com/helldown-ransomware-targets-zyxel-firewalls/) weaponized this flaw to steal VPN credentials and establish backdoor VPN connections, primarily targeting small and medium-sized businesses in the United States and Europe. Helldown listed 31 victims on its data extortion portal within months of first documentation in August 2024. CISA added it to the KEV catalog on December 3, 2024.

---

## Transparency Assessment

Zyxel's disclosure record is mixed at best. The CVE-2022-30525 episode -- where Zyxel released a firmware patch without a CVE, advisory, or coordination with the reporting researcher -- is a documented silent-patch failure comparable to [Fortinet's XORtigate episode](Fortinet.md). Zyxel publishes security advisories via its [support portal](https://www.zyxel.com/global/en/support/security-advisories), but the 2022 incident demonstrates that the process has failed under pressure.

For the 2023 vulnerability cluster, Zyxel issued advisories within standard timelines. However, the structural challenge remains: Zyxel's SMB customer base relies heavily on firmware-only patching with no discrete security patch mechanism, and many deployments lack the IT staffing to apply urgent firmware upgrades within the exploitation window.

---

## Risk Summary

Zyxel's 6 edge KEV entries place it in the middle of the vendor distribution in this dataset. Three characteristics make the count particularly concerning:

1. **Severity concentration:** Five of six entries are CVSS 9.8 Critical -- pre-auth command injection or buffer overflow primitives that require no credentials to exploit.

2. **Speed of exploitation:** The 2023 botnet campaign demonstrated PoC-to-mass-exploitation timelines measured in days, not weeks. Zyxel's SMB customer base -- structurally slower to patch than enterprise peers -- is disproportionately exposed to this pattern.

3. **Diverse threat actors:** Zyxel edge devices have been targeted by nation-state operators (Sandworm-linked tooling), ransomware groups (Helldown), and commodity botnets (Mirai variants) -- the full spectrum of threat actors, each exploiting the same class of pre-auth vulnerabilities.

The hardcoded credential vulnerability (CVE-2020-29583) -- a plaintext, unchangeable password in the `zyfwp` account shipped in production firmware -- is a category of deficiency that should not occur in any security appliance.

---

> **Note on raw counts:** Zyxel's count of 6 should be interpreted in context. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. Zyxel attracts less researcher scrutiny than Fortinet or Palo Alto Networks, which may suppress the count relative to the actual vulnerability surface. The concentration of critical-severity pre-auth flaws and the diversity of threat actors exploiting them suggest the risk profile is not fully captured by the count alone.
