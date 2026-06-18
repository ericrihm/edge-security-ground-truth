# Sophos

**Scope: Sophos Firewall (SFOS), XG Firewall, SG UTM, and CyberoamOS edge appliances.** A mid-market UTM vendor whose firewall products were the subject of a documented multi-year nation-state campaign by China-nexus threat actors. *(6 edge KEV entries, 2020--2026.)*

---

## Market Position

Sophos is a UK-based security vendor (acquired by Thoma Bravo in 2020) with historically strong positioning in the SMB and mid-market UTM firewall segment. Gartner named Sophos a Leader in the Magic Quadrant for Unified Threat Management (SMB Multifunction Firewalls) for [seven consecutive years through 2018](https://news.sophos.com/en-us/2018/09/25/sophos-is-named-a-leader-in-the-gartner-utm-magic-quadrant/), and a [Visionary in the 2020 Network Firewall MQ](https://partnernews.sophos.com/en-us/2020/12/resources/gartner-names-sophos-a-visionary-in-the-2020-magic-quadrant-for-network-firewalls/). The product line spans multiple generations: the legacy SG UTM (end-of-sale), the XG Firewall (superseded), and the current Sophos Firewall running SFOS. CyberoamOS is a legacy platform from Sophos's 2014 acquisition of Cyberoam, now end-of-life. The multi-generation product surface is relevant because KEV entries span all four product lines, and EOL products (CyberoamOS, XG v17.x) cannot receive further patches.

---

## Key Incidents

| CVE | CVSS | Class | Product | KEV Added |
|-----|------|-------|---------|-----------|
| [CVE-2020-12271](https://nvd.nist.gov/vuln/detail/CVE-2020-12271) | 9.8 | SQL injection (pre-auth) | SFOS | Nov 3 2021 |
| [CVE-2020-25223](https://nvd.nist.gov/vuln/detail/CVE-2020-25223) | 9.8 | RCE (pre-auth) | SG UTM | Mar 25 2022 |
| [CVE-2022-1040](https://nvd.nist.gov/vuln/detail/CVE-2022-1040) | 9.8 | Authentication bypass | Firewall | Mar 31 2022 |
| [CVE-2022-3236](https://nvd.nist.gov/vuln/detail/CVE-2022-3236) | 9.8 | Code injection (pre-auth) | Firewall | Sep 23 2022 |
| [CVE-2020-15069](https://nvd.nist.gov/vuln/detail/CVE-2020-15069) | 9.8 | Buffer overflow (pre-auth) | XG Firewall | Feb 6 2025 |
| [CVE-2020-29574](https://nvd.nist.gov/vuln/detail/CVE-2020-29574) | 9.8 | SQL injection (pre-auth) | CyberoamOS | Feb 6 2025 |

All six entries are CVSS 9.8 Critical. All six are pre-authentication vulnerabilities -- no credentials required to exploit.

---

### CVE-2020-12271: The Asnarok Campaign

[CVE-2020-12271](https://www.tenable.com/blog/cve-2020-12271-zero-day-sql-injection-vulnerability-in-sophos-xg-firewall-exploited-in-the-wild) is a pre-authentication SQL injection in SFOS affecting versions 17.0 through 18.0 before the April 25, 2020 hotfix. The vulnerability existed in the administration (HTTPS) service and User Portal when exposed on the WAN zone.

The exploitation was not opportunistic. A coordinated campaign -- dubbed "[Asnarok](https://news.sophos.com/en-us/2024/10/31/pacific-rim-timeline/)" by Sophos -- used the SQL injection to deploy a trojan that exfiltrated usernames and hashed passwords from the firewall's local database, specifically targeting credentials used for VPN remote access. The campaign was later attributed to China-nexus threat actors as part of the broader "Pacific Rim" investigation. Sophos deployed an automatic hotfix to all supported firewalls, a response mechanism not available from most firewall vendors.

### CVE-2022-1040 and CVE-2022-3236: China-Nexus Targeted Exploitation

These two vulnerabilities represent the clearest documented evidence of sustained nation-state targeting of a specific firewall vendor's edge products.

**[CVE-2022-1040](https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce)** (authentication bypass in User Portal and Webadmin, CVSS 9.8): Disclosed by Sophos on March 25, 2022. [Volexity researchers confirmed](https://securityaffairs.com/132377/apt/chinese-driftingcloud-apt-exploited-sophos-firewall-zero-day-before-it-was-fixed.html) that a Chinese APT group tracked as "DriftingCloud" had exploited the zero-day since early March 2022, weeks before the patch, to compromise targets and deploy webshells. Separately, [Recorded Future attributed exploitation to TA413](https://www.recordedfuture.com/research/chinese-state-sponsored-group-ta413-adopts-new-capabilities-in-pursuit-of-tibetan-targets), a China-nexus group targeting Tibetan government-in-exile organizations, which deployed a custom backdoor ("LOWZERO") through the compromised firewalls. Sophos's advisory noted exploitation was focused on "a small number of targeted organizations primarily in the South Asia region."

**[CVE-2022-3236](https://www.sophos.com/en-us/security-advisories/sophos-sa-20220923-sfos-rce)** (code injection in User Portal and Webadmin, CVSS 9.8): Disclosed September 23, 2022. The vulnerability's exploitation profile mirrored CVE-2022-1040 -- [targeting a small set of specific organizations, primarily in the South Asia region](https://www.thezdi.com/blog/2022/10/19/cve-2022-3236-sophos-firewall-user-portal-and-web-admin-code-injection), with Sophos directly notifying affected organizations. The pattern -- same product surface (User Portal/Webadmin), same geographic targeting, same attacker profile -- indicates a persistent adversary returning to the same attack surface after the first vulnerability was patched.

### The Pacific Rim Report

In October 2024, Sophos published "[Pacific Rim](https://www.sophos.com/en-us/content/pacific-rim)," a detailed account of a **five-year defensive and counter-offensive operation** against multiple interlinked China-based threat actors targeting Sophos edge devices. The report documented overlapping TTPs with [Volt Typhoon, APT31, and APT41](https://www.sophos.com/en-us/press/press-releases/2024/10/hunter-versus-spy-sophos-pacific-rim-report-details-its-defensive-and), and identified exploit development activity originating from the Sichuan region of China. Targets included nuclear energy suppliers, a national capital's airport, a military hospital, and central government ministries across South and Southeast Asia.

The Pacific Rim disclosure is unprecedented in the firewall industry: no other vendor has published a comparable longitudinal account of nation-state targeting of its own products. Whether this reflects uniquely intense targeting of Sophos or uniquely transparent reporting -- or both -- is an open interpretive question.

### Legacy Products: CVE-2020-15069 and CVE-2020-29574

Both vulnerabilities were disclosed in 2020 but added to the CISA KEV catalog in February 2025, indicating exploitation continued years after disclosure:

- **[CVE-2020-15069](https://www.sophos.com/en-us/security-advisories/sophos-sa-20200625-xg-user-portal-rce)** (XG Firewall v17.x buffer overflow): A buffer overflow in the HTTP/S Bookmarks feature of the User Portal allowing pre-auth RCE on XG Firewall firmware v17.x through MR12. XG Firewall v18 was not affected.

- **[CVE-2020-29574](https://community.sophos.com/b/security-blog/posts/advisory-resolved-sql-injection-in-cyberoam-os-webadmin-cve-2020-29574)** (CyberoamOS SQL injection): An unauthenticated SQL injection in the WebAdmin interface of the legacy CyberoamOS platform. [APT31 has been identified as exploiting this vulnerability](https://cvefeed.io/vuln/detail/CVE-2020-29574). The affected product is end-of-life with no further security updates -- organizations still running CyberoamOS devices are permanently exposed.

---

## Transparency Assessment

Sophos's disclosure posture is notably better than most peers in this dataset. The company publishes advisories via a [public security advisory page](https://www.sophos.com/en-us/security-advisories) and maintains a [responsible disclosure policy](https://www.sophos.com/en-us/legal/sophos-responsible-disclosure-policy) with a 48-hour acknowledgment commitment. Sophos operates a bug bounty program and is a [FIRST PSIRT member](https://www.first.org/members/teams/sophos_cirt).

The Pacific Rim report represents an industry-leading act of transparency -- publishing a five-year timeline of nation-state exploitation of your own products, including TTPs, attribution, and your own counter-offensive measures, is without precedent among firewall vendors.

However, transparency about past exploitation does not eliminate the vulnerabilities themselves. Three of the six KEV entries affect the same User Portal/Webadmin attack surface (CVE-2020-12271, CVE-2022-1040, CVE-2022-3236), indicating a recurring architectural weakness in WAN-exposed management interfaces. The automatic hotfix deployment capability Sophos demonstrated during the Asnarok campaign is a genuine structural advantage -- but it also implies Sophos recognizes that its customer base cannot be relied upon to patch manually within safe timelines.

---

## Risk Summary

Sophos's 6 edge KEV entries carry a distinctive risk profile shaped by three factors:

1. **Nation-state concentration:** At least four of six KEV entries (CVE-2020-12271, CVE-2022-1040, CVE-2022-3236, CVE-2020-29574) are linked to China-nexus threat actors. This is the highest documented rate of state-sponsored exploitation of any single firewall vendor's edge products in the KEV catalog. Sophos devices are not being exploited opportunistically -- they are being targeted deliberately by well-resourced adversaries.

2. **Attack surface recurrence:** The User Portal and Webadmin interfaces on the WAN zone have produced three separate KEV-listed vulnerabilities across different vulnerability classes (SQL injection, authentication bypass, code injection). The recurring pattern in the same product surface indicates an architectural issue, not isolated implementation bugs.

3. **Legacy tail risk:** Two of six entries (CVE-2020-15069, CVE-2020-29574) affect end-of-life products (XG Firewall v17.x and CyberoamOS) that will never receive further patches. Organizations still running these platforms are permanently exposed, and the February 2025 KEV additions confirm that exploitation of these legacy products is ongoing.

Sophos's transparency -- particularly the Pacific Rim disclosure -- is genuinely commendable and provides defenders with actionable intelligence. The vulnerability record itself, however, shows a pattern of recurring pre-auth flaws in WAN-exposed management surfaces that transparency alone does not resolve.

---

> **Note on raw counts:** Sophos's count of 6 should be read alongside the attribution data. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. Sophos's count is elevated in part because nation-state actors -- particularly China-nexus groups -- have invested sustained effort in finding and exploiting Sophos edge device vulnerabilities, as documented in the Pacific Rim report. This means the count reflects both the vulnerability surface and the intensity of adversary focus, which are distinct risk factors.
