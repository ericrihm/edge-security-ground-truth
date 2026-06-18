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

## CVE-2026-24858 — FortiCloud SSO Authentication Bypass (January 2026)

[CVE-2026-24858](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CWE-288, NVD CVSS 9.8) is an authentication bypass in FortiCloud's single sign-on implementation. An attacker with any valid FortiCloud account could authenticate to devices registered to *other* accounts via cross-tenant SSO token reuse — the SSO implementation did not verify that the authenticating identity matched the device's owning account.

**True zero-day:** [Arctic Wolf](https://arcticwolf.com/resources/blog/) confirmed exploitation from at least January 15, 2026. Patches were not released until January 28 — a **13-day zero-day window**. CISA added it to the KEV catalog on January 27 with a **3-day remediation deadline** (January 30), one of the shortest ever assigned ([CyberScoop](https://cyberscoop.com/ortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/fortinet-warns-of-new-zero-day-exploited-to-hijack-firewalls/)).

**Products affected** (Fortinet advisory FG-IR-26-060): FortiOS, FortiManager, FortiAnalyzer, FortiProxy, FortiWeb, FortiSwitchManager, FortiNAC-F. **Post-exploitation TTPs** documented by Arctic Wolf: config download, local admin account creation (usernames including `audit`, `backup`, `itadmin`, `secadmin`), VPN enablement, and firewall rule modification. Fortinet's emergency response included globally disabling FortiCloud SSO on January 26–27, re-enabling only for devices running patched firmware.

No threat actor attribution has been publicly confirmed. Coalition documented **14 zero-day advisories for critical Fortinet flaws in under four years** — Fortinet accounts for >7% of all zero-day advisories Coalition has issued ([CyberScoop](https://cyberscoop.com/ortinet-zero-day-cve-2026-24858-forticloud-sso-auth-bypass/)).

## FortiBleed credential dump (June 18, 2026) — developing incident

On June 18, 2026, security researcher Volodymyr "Bob" Diachenko reported discovery of a credential dump affecting approximately **73,932 Fortinet firewall/VPN URLs** across 194 countries and 21,632 unique domains, found on a misconfigured attacker server. The incident was reported independently by [BleepingComputer](https://www.bleepingcomputer.com/), [Help Net Security](https://www.helpnetsecurity.com/), [Arctic Wolf](https://arcticwolf.com/resources/blog/), [SecurityAffairs](https://securityaffairs.com/), CSO Online, and [HKCERT](https://www.hkcert.org/).

Attack methods reportedly included credential stuffing from prior breach dumps, VPN hash cracking on a 45-GPU Hashtopolis cluster, and configuration file extraction. Fortinet characterized the data as "a resharing of information obtained through previous incidents and brute-force attacks."

**This is distinct from prior incidents:** the 2021 leak (~87,000 SSL-VPN credentials from [CVE-2018-13379](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)) and the January 2025 Belsen Group dump (~15,000 devices from [CVE-2022-40684](https://nvd.nist.gov/vuln/detail/CVE-2022-40684) data collected in 2022). Some reports link FortiBleed to CVE-2026-24858 exploitation, but this connection is **claimed, not conclusively established** — credential stuffing and hash cracking are vendor-agnostic techniques.

**Status as of June 18, 2026:** developing. CISA has not issued a formal advisory. Claims will be re-verified as additional sources confirm or fail to corroborate.
