# Fortinet (FortiGate)

**Scope: FortiOS / FortiProxy SSL-VPN.** The largest firewall vendor by unit count; the SSL-VPN disclosure record is documented below. *(18 edge KEV entries, 2020–2026 — including FortiOS bugs CISA lists under a generic "Multiple Products" label.)*

## Market Position

FortiGate is the most widely deployed network firewall appliance by shipment volume — Fortinet's own marketing claims [over 50% global unit market share](https://www.fortinet.com/products/next-generation-firewall). Gartner named Fortinet a Leader in the [2025 Magic Quadrant for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336). **Critical framing note:** that 50%+ figure measures appliance shipments, not revenue; revenue share is substantially lower. The large installed base directly inflates both researcher attention and raw CVE/KEV counts — a high unit denominator is a confounding variable, not a defense.

## The SSL-VPN Pattern

Fortinet's FortiOS SSL-VPN daemon (`sslvpnd`) has generated four separate CISA KEV-cataloged vulnerabilities across a five-year span, each exploited in the wild:

| CVE | CVSS | Class | KEV Added |
|-----|------|-------|-----------|
| [CVE-2020-12812](https://securityaffairs.com/186117/security/five-year-old-fortinet-fortios-ssl-vpn-flaw-actively-exploited.html) | High | 2FA bypass (improper auth) | Nov 2021 |
| [CVE-2022-42475](https://www.sentinelone.com/vulnerability-database/cve-2022-42475/) | Critical | Heap overflow pre-auth RCE | Dec 2022 |
| [CVE-2023-27997](https://nvd.nist.gov/vuln/detail/CVE-2023-27997) (XORtigate) | 9.8 | Heap overflow pre-auth RCE | Jun 2023 |
| [CVE-2024-21762](https://nvd.nist.gov/vuln/detail/CVE-2024-21762) | 9.8 | OOB write pre-auth RCE | Feb 2024 |

CVE-2020-12812 — a 2FA bypass triggered by simple username-case manipulation — was still being [actively re-exploited in late 2025](https://securityaffairs.com/186117/security/five-year-old-fortinet-fortios-ssl-vpn-flaw-actively-exploited.html), five years after initial disclosure.

## Disclosure Transparency: Documented Failure

The common claim that Fortinet is "most transparent" is **false**, directly contradicted by the XORtigate episode.

In June 2023, Fortinet silently pushed firmware updates containing a fix for CVE-2023-27997 — a CVSS 9.8 pre-auth heap overflow — approximately **3–4 days before publishing any advisory**. [watchTowr researchers](https://labs.watchtowr.com/xortigate-or-cve-2023-27997/) reproduced the vulnerability on June 11 by diffing the firmware; [Lexfo Security](https://blog.lexfo.fr/xortigate-cve-2023-27997.html) had independently teased the bug on June 10. The official advisory appeared June 13.

The structural problem: Fortinet does not release discrete security patches. Customers must upgrade entire firmware builds. Without a CVE or advisory, administrators had no basis to assess urgency, while adversaries had a reverse-engineering head-start on the same patch delta defenders couldn't see. For a high-severity vulnerability, that is a poor disclosure design.

## Post-Exploitation: Patching Is Not Enough

In April 2025, CISA [issued an alert](https://www.bleepingcomputer.com/news/security/fortinet-says-ssl-vpn-pre-auth-rce-bug-is-exploited-in-attacks/) after Fortinet disclosed a post-exploitation persistence technique: threat actors who had previously compromised FortiGate devices via CVE-2022-42475, CVE-2023-27997, or CVE-2024-21762 could maintain **read-only persistent access** — including to credentials — via symlink manipulation in the SSL-VPN filesystem, surviving firmware upgrades. Organizations that patched promptly but did not conduct full incident response were still compromised.

## What the Metrics Actually Show

- **KEV density:** Four pre-auth RCE KEV entries in the SSL-VPN daemon alone — out of 18 edge KEV entries total — is not explained by market share alone; it indicates a recurring architectural or SDL failure in a specific product area.
- **Exploitation speed:** CVE-2024-21762's advisory (February 8, 2024) was followed by a CISA KEV listing the [next day, February 9](https://nvd.nist.gov/vuln/detail/CVE-2024-21762) — a near-simultaneous signal that exploitation was already active.
- **Transparency:** Silent patching plus firmware-only distribution is a disclosure anti-pattern — the documented opposite of the "most transparent" claim.

Fortinet's unit-count leadership is real. Its security disclosure posture and SSL-VPN vulnerability recurrence are not defensible on the same grounds.

## Latest development — FortiBleed (June 2026)

In mid-June 2026, a dataset reportedly exposing login credentials for **~74,000 internet-facing FortiGate devices** surfaced in cybercriminal communities ([CyberScoop](https://cyberscoop.com/ortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/)). Researchers attribute it not to a single new zero-day but to a **convergence of already-known issues**: unpatched FortiOS flaws (chiefly [CVE-2026-24858](https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026), the FortiCloud SSO authentication bypass actively exploited since January 2026), legacy SHA-256 password hashing on older FortiOS versions, and recycled credentials already circulating from infostealer campaigns and prior breaches. Included here as context — it is not a new KEV entry.
