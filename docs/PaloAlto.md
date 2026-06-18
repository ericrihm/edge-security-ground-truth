# Palo Alto Networks

**Scope in this repo:** PAN-OS firewall (GlobalProtect / NGFW). Palo Alto is a leading enterprise firewall vendor; its broader platform (Prisma, Cortex) and the Expedition migration utility fall outside the edge-appliance scope and are noted separately where relevant.

---

## 2024 KEV Record: 7 Entries, Two Product Tiers

CISA's Known Exploited Vulnerabilities catalog logged [seven Palo Alto Networks CVEs](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=Palo+Alto) confirmed exploited in 2024 — across two distinct product tiers that are worth separating analytically.

### PAN-OS Firewall (4 KEVs)

| CVE | Severity | Nature | KEV Added |
|-----|----------|--------|-----------|
| [CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400) | CVSS 10.0 | GlobalProtect unauthenticated RCE | Apr 12 2024 |
| [CVE-2024-0012](https://nvd.nist.gov/vuln/detail/cve-2024-0012) | CVSS 9.3 | Management interface auth bypass | Nov 18 2024 |
| [CVE-2024-9474](https://nvd.nist.gov/vuln/detail/cve-2024-9474) | CVSS 6.9 | Privilege escalation to root (chain with above) | Nov 18 2024 |
| [CVE-2024-3393](https://security.paloaltonetworks.com/CVE-2024-3393) | CVSS 8.7 | DNS Security DoS (maintenance-mode trigger) | Dec 30 2024 |

### Expedition Migration Tool (3 KEVs)

| CVE | Nature |
|-----|--------|
| [CVE-2024-5910](https://cyberscoop.com/palo-alto-expedition-firewall-exploit-cisa-kev/) | Missing auth — admin account takeover |
| [CVE-2024-9463](https://nvd.nist.gov/vuln/detail/cve-2024-9463) | OS command injection as root (CVSS 9.9) |
| [CVE-2024-9465](https://nvd.nist.gov/vuln/detail/cve-2024-9465) | SQL injection — credential/config/key dump |

Expedition is an optional, often-overlooked migration utility — not the firewall itself. That distinction matters for per-unit risk but not for vendor accountability: Palo Alto built Expedition, stored customer firewall credentials in it in cleartext, and is responsible for its security posture across the full platform ecosystem.

---

## The Standout: CVE-2024-3400

[CVE-2024-3400](https://www.cisa.gov/news-events/alerts/2024/04/12/palo-alto-networks-releases-guidance-vulnerability-pan-os-cve-2024-3400) is the most severe PAN-OS entry in the window. CVSS 10.0. Unauthenticated. Root on the firewall. Discovered in active exploitation — not reported by the vendor — by Volexity on approximately April 10, 2024, before any patch existed. The campaign, dubbed **Operation MidnightEclipse**, is attributed to a suspected state-nexus actor (UTA0218) who deployed the UPSTYLE backdoor and moved laterally into victim environments. CISA issued an emergency alert within two days; [patches shipped April 14](https://security.paloaltonetworks.com/CVE-2024-3400). Thousands of internet-exposed GlobalProtect instances were subsequently mass-scanned once public proof-of-concept code dropped.

Days-to-mass-exploitation: zero (pre-patch zero-day). That is not a market-share artifact.

---

## The November Chain: CVE-2024-0012 + CVE-2024-9474

These two vulnerabilities chain cleanly: CVE-2024-0012 provides unauthenticated admin access to the management web interface; CVE-2024-9474 escalates that to root. [Wiz observed exploitation surge sharply](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild) within 48 hours of a public PoC on November 19. CISA had already added both to KEV the day before, ordering federal agencies to remediate by December 9. The attack surface — externally exposed management interfaces — is a configuration Palo Alto explicitly documents as inadvisable, yet widely deployed.

---

## Expedition: The Lateral-Pivot Problem

The three Expedition CVEs are [individually documented by CISA](https://www.securityweek.com/cisa-warns-of-two-more-palo-alto-expedition-flaws-exploited-in-attacks/) and confirmed exploited in the wild. The risk is multiplicative: a compromised Expedition server hands an attacker cleartext credentials, API keys, and full device configurations for every PAN-OS firewall that tool ever managed. The vulnerability chain predates KEV listing — CVE-2024-5910 was patched in July 2024 but not added to KEV until November — suggesting the vendor did not communicate exploitation risk proportionally at patch time.

---

## Transparency Assessment

Palo Alto does not have a documented pattern of silent patching (unlike [Fortinet](./Fortinet.md)). Advisories are published. However, initial severity language has occasionally lagged behind what external researchers subsequently confirmed. CVE-2024-3400 was discovered externally; CVE-2024-3393 moved from disclosure to KEV in three days. Reactive, not proactive.

---

## Note on raw counts

Seven KEV entries in one calendar year is a notable concentration, but market incumbents attract proportionally more researcher and adversary attention, which inflates raw counts (see the repo [methodology](../METHODOLOGY.md)). The signal that attention does *not* explain: three of the 2024 entries were pre-patch or near-zero-day exploitation. Weigh that against your own deployment and patch cadence.
