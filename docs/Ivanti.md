# Ivanti

## Market Position

Ivanti Connect Secure (formerly Pulse Secure) is a dominant SSL-VPN and zero-trust network access platform deployed across government agencies, financial institutions, and critical infrastructure worldwide. Its pervasive presence in federal environments elevated the strategic value of its vulnerabilities — and the consequences when they were exploited.

---

## The January 2024 Crisis: Two Zero-Days, One Emergency Directive

On [January 10, 2024](https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-releases-security-update-connect-secure-and-policy-secure-gateways), Ivanti disclosed two chained vulnerabilities in Connect Secure and Policy Secure:

- **[CVE-2023-46805](https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2023-46805-cve-2024-21887/)** (CVSS 8.2): Authentication bypass in the web component — a remote unauthenticated attacker bypasses control checks entirely.
- **[CVE-2024-21887](https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2023-46805-cve-2024-21887/)** (CVSS 9.1): Command injection executable by any authenticated administrator — but when chained with CVE-2023-46805, authentication is not required.

Both were already being exploited before the advisory dropped. [Mandiant and Google Threat Intelligence attributed the initial campaign](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-exploitation-persistence/) to **UNC5221**, a China-nexus espionage group, which installed webshells and backdoors across approximately **1,700 Ivanti appliances by mid-January**. On January 19, 2024, CISA issued [Emergency Directive ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities) — a rare authority requiring all federal civilian agencies to immediately disconnect or apply mitigations. No patch existed yet; Ivanti distributed mitigations only through a private customer portal.

---

## Third Zero-Day, Defeated Integrity Checker, Disputed Factory Reset

On January 31, 2024, Ivanti disclosed [CVE-2024-21893](https://www.bleepingcomputer.com/news/security/newest-ivanti-ssrf-zero-day-now-under-mass-exploitation/) (CVSS 8.2), an SSRF in the SAML component. Within days, [Shadowserver tracked 170+ distinct IPs](https://securityaffairs.com/158677/hacking/ivanti-ssrf-cve-2024-21893-under-attack.html) exploiting it, chained again with the command injection flaw.

The disclosure pattern exposed a second problem: Ivanti's [Integrity Checker Tool (ICT) could be defeated](https://www.cisa.gov/news-events/alerts/2024/01/30/updated-new-software-updates-and-mitigations-defend-against-exploitation-ivanti-connect-secure-and) by sophisticated adversaries. CISA further found that **factory resets may not remove root-level persistence** — Ivanti [publicly disputed this finding](https://www.bankinfosecurity.com/ivanti-disputes-cisa-findings-post-factory-reset-hacking-a-24492), creating an unusual public disagreement with the U.S. government's cybersecurity agency during an active crisis. Meanwhile, watchTowr researchers discovered a fourth vulnerability (CVE-2024-22024, XXE) while [auditing Ivanti's patch for CVE-2024-21893](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/), suggesting patch quality control gaps.

---

## 2025: Pattern Repeats

In January 2025, [CISA added CVE-2025-0282 to the KEV catalog](https://www.cisa.gov/news-events/alerts/2025/01/08/cisa-adds-one-vulnerability-kev-catalog) — a stack-based buffer overflow (CVSS ~9.0) in Connect Secure enabling **unauthenticated remote code execution**. A [joint Mandiant/Ivanti investigation](https://censys.com/advisory/cve-2025-0282) confirmed exploitation going back to **mid-December 2024**, with post-exploitation malware families SPAWN, DRYHOOK, and PHASEJAM deployed on compromised appliances. A companion local privilege escalation (CVE-2025-0283) was disclosed simultaneously but not confirmed exploited in the wild.

---

## Transparency Assessment

Ivanti's disclosure record across both crises shows consistent patterns that compound risk: delayed patches distributed through private channels, defensive tooling that adversaries could bypass, disputed government findings during an active incident, and patch quality issues caught by third-party researchers. Each new advisory functioned as a partial roadmap for additional threat actors, accelerating exploitation rather than containing it. The recurrence of a critical unauthenticated RCE in 2025 — exploited before disclosure — indicates insufficient proactive vulnerability discovery in a product category that demands it.

---

## Takeaway

The metric that matters here is not raw CVE count but **time from disclosure to mass exploitation**: measured in hours to days across every major Ivanti incident. Organizations running Ivanti Connect Secure should treat it as a persistent high-risk asset requiring aggressive patch hygiene, continuous IOC monitoring against known UNC5221 TTPs, and contingency planning for full device reimage — the vendor-supplied integrity checker is not a reliable detection backstop.