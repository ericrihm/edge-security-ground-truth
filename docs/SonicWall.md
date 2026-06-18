# SonicWall

**Risk rank: #1** — Highest demonstrated risk per incident impact among perimeter vendors reviewed.

## Market Position

SonicWall holds significant share in mid-market and SMB firewall/SSL VPN deployments, with devices widely used in financial services, healthcare, and local government. Its SMB-first installed base is structurally slower to patch than enterprise peers — a risk multiplier that attackers have actively exploited.

---

## CVE-2024-40766: Improper Access Control in SonicOS (CVSS 9.3)

[CVE-2024-40766](https://nvd.nist.gov/vuln/detail/CVE-2024-40766) is an improper access control flaw in the SonicOS management interface and SSL VPN, affecting Gen 5, Gen 6, and Gen 7 devices. SonicWall disclosed it on August 22, 2024. [CISA added it to the KEV catalog on September 9, 2024](https://www.helpnetsecurity.com/2024/09/10/cve-2024-40766-exploited/).

Within weeks, Akira and Fog ransomware affiliates were operating a sustained campaign through unpatched SonicWall SSL VPNs. [Arctic Wolf documented over 30 Akira and Fog ransomware intrusions exploiting CVE-2024-40766 (roughly three-quarters Akira)](https://securityaffairs.com/170359/cyber-crime/fog-akira-ransomware-sonicwall-vpn-flaw.html), with full network encryption achieved in under ten hours in documented cases. A structural contributor accelerated the attacks: operators who migrated from Gen 6 to Gen 7 hardware frequently reused credentials without resetting passwords, leaving accounts exposed even on nominally updated hardware. [Rapid7's September 2024 analysis](https://www.rapid7.com/blog/post/2024/09/09/etr-cve-2024-40766-critical-improper-access-control-vulnerability-affecting-sonicwall-devices/) characterized exploitation evidence at the time as circumstantial but escalating rapidly — the KEV addition confirmed active exploitation the same day.

The campaign did not end in 2024. Arctic Wolf observed a [renewed uptick in July 2025](https://arcticwolf.com/resources/blog/arctic-wolf-observes-july-2025-uptick-in-akira-ransomware-activity-targeting-sonicwall-ssl-vpn/), and the broader peak followed in August 2025, when [Huntress documented 28 incidents within a single week](https://thehackernews.com/2025/08/sonicwall-confirms-patched.html) and SonicWall clarified publicly that the activity was not a zero-day but exploitation of the same year-old CVE against unpatched or misconfigured devices.

> **Note:** A figure of approximately 438,000 exposed devices has circulated in commentary, but it could not be confirmed against any primary source (CISA, NVD, Rapid7, Huntress, or Arctic Wolf) and is not used as evidence here.

---

## MySonicWall Cloud Backup Breach (September 2025)

In September 2025, SonicWall disclosed suspicious activity targeting its MySonicWall cloud backup service. The root cause was [an API code change introduced in February 2025](https://www.bleepingcomputer.com/news/security/marquis-sues-sonicwall-over-backup-breach-that-led-to-ransomware-attack/) that opened an access gap, subsequently exploited via brute-force attacks. Exposed files contained AES-256-encrypted credentials, MFA scratch codes, VPN configurations, network topology, and firewall rules.

The disclosure pattern is the second story. SonicWall's initial advisory claimed fewer than 5% of customers were affected. After a Mandiant-led investigation concluded on October 8, 2025, [SonicWall revised that figure to all customers who had used the cloud backup service](https://www.cybersecuritydive.com/news/sonicwall-investigation-hackers-access-customer-backup/802598/). Mandiant attributed the intrusion to state-sponsored actors. No public explanation for the 5%-to-100% discrepancy was provided.

The stolen configurations did not sit idle. On August 14, 2025 — before SonicWall's first public disclosure — attackers used configuration data extracted from the breach to compromise a SonicWall firewall at Marquis Software Solutions, a vendor serving more than 700 financial institutions. The resulting ransomware attack affected 74 U.S. banks and exposed personal and financial data including Social Security numbers. [Marquis filed suit against SonicWall in February 2026](https://techcrunch.com/2026/02/24/marquis-sonicwall-lawsuit-ransomware-firewall-breach/), alleging gross negligence and misrepresentation. Marquis itself now faces more than 36 consumer class-action lawsuits downstream.

---

## Transparency Assessment: Poor

Two incidents, two instances of minimized initial disclosure. The MySonicWall breach saw a 20x understatement of scope held for three weeks. The CVE-2024-40766 advisory cycle did not prominently communicate the Gen6-to-Gen7 credential migration risk that contributed to mass exploitation. Unlike a vendor that patches silently and then issues a retrospective advisory, SonicWall's pattern is to disclose but to disclose inaccurately — which may be worse for operators trying to triage exposure.

---

## Bottom Line

SonicWall's 2024–2025 record demonstrates a failure mode that goes beyond unpatched vulnerabilities: the vendor's own cloud infrastructure became an attack platform against its entire backup customer base. The 5%-to-100% revision, the Mandiant attribution to state-sponsored actors, and the Marquis lawsuit collectively define what "vendor-side security failure" means in practice. Per-unit KEV density and time-to-mass-exploitation both favor placing SonicWall at the top of this risk ranking.
