# Sophos

**Scope: Sophos Firewall (SFOS), XG Firewall, SG UTM, and CyberoamOS edge appliances.** A mid-market UTM vendor whose firewall products were the subject of a documented multi-year nation-state campaign by China-nexus threat actors. *(6 edge KEV entries, 2020--2025.)*

---

## KEV CVE Summary Table

All 6 CISA KEV-listed CVEs for Sophos edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Product | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|---------|----------|:--------:|:----------:|
| [CVE-2020-12271](https://nvd.nist.gov/vuln/detail/CVE-2020-12271) | 10.0 | CWE-89 SQL Injection | SFOS | 2021-11-03 | Y | Known |
| [CVE-2020-25223](https://nvd.nist.gov/vuln/detail/CVE-2020-25223) | 9.8 | CWE-78 OS Command Injection | SG UTM (CyberoamOS) | 2022-03-25 | N | Unknown |
| [CVE-2022-1040](https://nvd.nist.gov/vuln/detail/CVE-2022-1040) | 9.8 | Authentication Bypass | Sophos Firewall | 2022-03-31 | Y | Unknown |
| [CVE-2022-3236](https://nvd.nist.gov/vuln/detail/CVE-2022-3236) | 9.8 | CWE-94 Code Injection | Sophos Firewall | 2022-09-23 | Y | Unknown |
| [CVE-2020-15069](https://nvd.nist.gov/vuln/detail/CVE-2020-15069) | 9.8 | CWE-120 Buffer Overflow | XG Firewall | 2025-02-06 | N | Unknown |
| [CVE-2020-29574](https://nvd.nist.gov/vuln/detail/CVE-2020-29574) | 9.8 | CWE-89 SQL Injection | CyberoamOS | 2025-02-06 | N | Unknown |

**Summary statistics:** 6 KEV entries. All 6 rated CRITICAL (CVSS 9.8--10.0). All 6 are pre-authentication -- no credentials required to exploit. 3 confirmed zero-days (exploitation observed before patch availability). 1 flagged by CISA as used in a known ransomware campaign. This is the most consistently severe vendor profile in the dataset: no other vendor has all KEV entries at CVSS 9.8 or above.

---

## Market Position

Sophos is a UK-based security vendor (acquired by Thoma Bravo in 2020) positioned in the SMB and mid-market UTM segment. Gartner named Sophos a Leader in the UTM Magic Quadrant for [seven consecutive years through 2018](https://news.sophos.com/en-us/2018/09/25/sophos-is-named-a-leader-in-the-gartner-utm-magic-quadrant/) and a [Visionary in the 2020 Network Firewall MQ](https://partnernews.sophos.com/en-us/2020/12/resources/gartner-names-sophos-a-visionary-in-the-2020-magic-quadrant-for-network-firewalls/). The product line spans four generations: SG UTM (end-of-sale), XG Firewall (superseded), current Sophos Firewall (SFOS), and CyberoamOS (legacy, from the 2014 Cyberoam acquisition, now end-of-life). KEV entries span all four, and EOL products (CyberoamOS, XG v17.x) cannot receive further patches.

---

## Timeline

### 2020: The Asnarok Campaign (CVE-2020-12271)

[CVE-2020-12271](https://www.tenable.com/blog/cve-2020-12271-zero-day-sql-injection-vulnerability-in-sophos-xg-firewall-exploited-in-the-wild) is a pre-authentication SQL injection in SFOS affecting versions 17.0 through 18.0 before the April 25, 2020 hotfix. CVSS 10.0 -- the only perfect-score vulnerability in the Sophos KEV set. The vulnerability existed in the administration (HTTPS) service and User Portal when exposed on the WAN zone.

The exploitation was not opportunistic. A coordinated campaign -- dubbed "[Asnarok](https://news.sophos.com/en-us/2024/10/31/pacific-rim-timeline/)" by Sophos -- used the SQL injection to deploy a trojan that exfiltrated usernames and hashed passwords from the firewall's local database, specifically targeting credentials used for VPN remote access. The trojan also attempted to download secondary payloads, including the Ragnarok ransomware, onto devices behind the compromised firewall. The campaign was later attributed to China-nexus threat actors as part of the broader "Pacific Rim" investigation.

Sophos deployed an automatic hotfix to all supported firewalls within 48 hours of detection -- a response mechanism not available from most firewall vendors. This automatic hotfix capability would become a recurring structural advantage. EPSS score: 0.431 (98.6th percentile), reflecting the high probability of continued exploitation.

### 2020: Legacy Product Exploitation (CVE-2020-25223, CVE-2020-29574, CVE-2020-15069)

Three 2020-era vulnerabilities affect EOL products that predate the current Sophos Firewall platform.

**[CVE-2020-25223](https://nvd.nist.gov/vuln/detail/CVE-2020-25223)** (CVSS 9.8, OS command injection) affects the WebAdmin interface of SG UTM / CyberoamOS. EPSS score: 0.967 (99.9th percentile) -- the highest exploitation probability of any Sophos CVE. Added to KEV March 25, 2022, linked to the Pacific Rim threat cluster.

**[CVE-2020-29574](https://community.sophos.com/b/security-blog/posts/advisory-resolved-sql-injection-in-cyberoam-os-webadmin-cve-2020-29574)** (CVSS 9.8, SQL injection) targets the same CyberoamOS WebAdmin interface. [APT31 has been identified as exploiting this vulnerability](https://cvefeed.io/vuln/detail/CVE-2020-29574). Not added to KEV until February 6, 2025 -- five years after disclosure, indicating ongoing exploitation.

**[CVE-2020-15069](https://www.sophos.com/en-us/security-advisories/sophos-sa-20200625-xg-user-portal-rce)** (CVSS 9.8, buffer overflow) affected the HTTP/S Bookmarks feature of the User Portal on XG Firewall v17.x, allowing pre-auth RCE. Also added to KEV on February 6, 2025 -- the same date as CVE-2020-29574. The simultaneous KEV addition of two legacy Sophos CVEs five years after disclosure strongly suggests CISA received new exploitation intelligence tying both to ongoing campaigns.

Both CyberoamOS and XG Firewall v17.x are end-of-life. No further patches will be issued. Organizations still running either platform are permanently exposed.

### 2022: China-Nexus Targeted Exploitation (CVE-2022-1040 and CVE-2022-3236)

These two vulnerabilities represent the clearest documented evidence of sustained nation-state targeting of a specific firewall vendor's attack surface. Both hit the same product surface -- the User Portal and Webadmin interfaces -- within six months.

**[CVE-2022-1040](https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce)** (authentication bypass in User Portal and Webadmin, CVSS 9.8): Disclosed by Sophos on March 25, 2022. [Volexity researchers confirmed](https://securityaffairs.com/132377/apt/chinese-driftingcloud-apt-exploited-sophos-firewall-zero-day-before-it-was-fixed.html) that a Chinese APT group tracked as "DriftingCloud" had exploited the zero-day since early March 2022, weeks before the patch, to compromise targets and deploy webshells. DriftingCloud used the compromised firewalls for man-in-the-middle attacks by modifying DNS responses -- turning the security appliance into an offensive platform. Targeting was concentrated in South Asia (Afghanistan, Bhutan, India, Nepal, Pakistan, Sri Lanka). Separately, [Recorded Future attributed exploitation to TA413](https://www.recordedfuture.com/research/chinese-state-sponsored-group-ta413-adopts-new-capabilities-in-pursuit-of-tibetan-targets), a China-nexus group targeting Tibetan government-in-exile organizations, which deployed a custom backdoor ("LOWZERO") through the compromised firewalls. EPSS score: 0.998 (99.96th percentile). Sophos's advisory noted exploitation was focused on "a small number of targeted organizations primarily in the South Asia region."

**[CVE-2022-3236](https://www.sophos.com/en-us/security-advisories/sophos-sa-20220923-sfos-rce)** (code injection in User Portal and Webadmin, CVSS 9.8): Disclosed September 23, 2022 -- added to the KEV catalog the same day, one of the fastest KEV additions in the catalog's history. The exploitation profile mirrored CVE-2022-1040: [targeting a small set of specific organizations, primarily in the South Asia region](https://www.thezdi.com/blog/2022/10/19/cve-2022-3236-sophos-firewall-user-portal-and-web-admin-code-injection), with Sophos directly notifying affected organizations. EPSS score: 0.989 (99.9th percentile). The pattern -- same product surface (User Portal/Webadmin), same geographic targeting, same attacker profile, different vulnerability class -- indicates a persistent adversary returning to the same attack surface after the first vulnerability was patched.

---

## The User Portal/Webadmin Pattern

Three of six KEV entries target the User Portal and/or Webadmin interface when exposed on the WAN zone:

| CVE | CVSS | Class | KEV Added |
|-----|------|-------|-----------|
| [CVE-2020-12271](https://nvd.nist.gov/vuln/detail/CVE-2020-12271) | 10.0 | SQL injection (pre-auth) | 2021-11-03 |
| [CVE-2022-1040](https://nvd.nist.gov/vuln/detail/CVE-2022-1040) | 9.8 | Authentication bypass (pre-auth) | 2022-03-31 |
| [CVE-2022-3236](https://nvd.nist.gov/vuln/detail/CVE-2022-3236) | 9.8 | Code injection (pre-auth) | 2022-09-23 |

Three different vulnerability classes (SQL injection, authentication bypass, code injection) in the same product surface over two years. This is not a single recurring bug -- it indicates an architectural attack surface problem in the WAN-exposed management interface. The defender implication is clear: **disable WAN-facing User Portal and Webadmin access**. Sophos's own guidance recommends this.

---

## The Pacific Rim Report

In October 2024, Sophos published "[Pacific Rim](https://www.sophos.com/en-us/content/pacific-rim)," a detailed account of a **five-year defensive and counter-offensive operation** (2018--2023) against multiple interlinked China-based threat actors targeting Sophos edge devices. The report documented overlapping TTPs with [Volt Typhoon, APT31, and APT41](https://www.sophos.com/en-us/press/press-releases/2024/10/hunter-versus-spy-sophos-pacific-rim-report-details-its-defensive-and), and identified exploit development activity originating from the Sichuan region of China. Targets included nuclear energy suppliers, a national capital's airport, a military hospital, and central government ministries across South and Southeast Asia.

Key details: (1) five attributed China-nexus groups (Volt Typhoon, APT31, APT41, DriftingCloud, TA413) -- the most named state actors targeting any single vendor in this dataset; (2) exploit development traced to the Sichuan region, with evidence of a shared offensive research pipeline across actor clusters; (3) Sophos deployed custom implants on attacker-controlled test devices for real-time intelligence collection -- an unprecedented counter-offensive measure by a firewall vendor; (4) the campaign evolved from broad opportunistic exploitation (Asnarok) to precision targeting of government and critical infrastructure.

The Pacific Rim disclosure is unprecedented in the firewall industry. No other vendor has published a comparable longitudinal account of nation-state targeting of its own products. Whether this reflects uniquely intense targeting of Sophos or uniquely transparent reporting -- or both -- is an open interpretive question.

---

## Threat Actor Attribution

Sophos edge products have the highest density of named China-nexus threat actors of any vendor in this dataset. Attribution data from [THREAT-ACTORS.md](./THREAT-ACTORS.md) and [THREAT-ATTRIBUTION.md](./THREAT-ATTRIBUTION.md):

| Actor | CVEs Exploited | Tooling / TTPs | Source |
|-------|---------------|----------------|--------|
| **DriftingCloud** | CVE-2022-1040 | PupyRAT, Pantegana, Sliver; MitM via DNS modification | [Volexity](https://securityaffairs.com/132377/apt/chinese-driftingcloud-apt-exploited-sophos-firewall-zero-day-before-it-was-fixed.html) |
| **TA413** (LuckyCat) | CVE-2022-1040 | Custom LOWZERO backdoor targeting Tibetan orgs | [Recorded Future](https://www.recordedfuture.com/research/chinese-state-sponsored-group-ta413-adopts-new-capabilities-in-pursuit-of-tibetan-targets) |
| **APT31** (Zirconium) | CVE-2020-29574 | CyberoamOS exploitation | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2020-29574), Sophos Pacific Rim |
| **APT41** (Winnti) | Pacific Rim cluster | Dual espionage + financial operations | [Sophos Pacific Rim](https://www.sophos.com/en-us/content/pacific-rim), FBI indictments |
| **Volt Typhoon** | Pacific Rim cluster | Living-off-the-land, CI pre-positioning | [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a), Sophos Pacific Rim |

Five named China-nexus groups targeting a single vendor's edge products -- the highest density of state-actor attention per KEV entry in the dataset. For comparison, Fortinet (3x as many KEV entries) has four named China-nexus attributions.

---

## Transparency Assessment

Sophos's disclosure posture is the strongest of any vendor in this dataset. The company publishes advisories via a [public security advisory page](https://www.sophos.com/en-us/security-advisories), maintains a [responsible disclosure policy](https://www.sophos.com/en-us/legal/sophos-responsible-disclosure-policy) with a 48-hour acknowledgment commitment, operates a bug bounty program, and is a [FIRST PSIRT member](https://www.first.org/members/teams/sophos_cirt).

**The Pacific Rim report as a benchmark.** Publishing a five-year timeline of nation-state exploitation of your own products -- including TTPs, Sichuan-region attribution, counter-offensive implant deployments, and named actor clusters -- is without precedent among firewall vendors. It provides a reference point for evaluating other vendors' silence: the absence of a "Pacific Rim equivalent" from Fortinet, Cisco, or Palo Alto may reflect less intense targeting or less transparent reporting. Sophos's report suggests the latter is plausible.

**Automatic hotfix deployment** is a structural advantage unique to Sophos in this dataset, demonstrated during Asnarok. **Proactive victim notification** for CVE-2022-1040 and CVE-2022-3236 is another operational differentiator.

However, transparency does not eliminate the vulnerabilities. The User Portal/Webadmin attack surface produced three KEV entries across different vulnerability classes -- an architectural weakness that disclosure alone does not resolve.

---

## Risk Summary

Sophos's 6 edge KEV entries carry a distinctive risk profile shaped by four factors:

1. **Nation-state concentration.** At least four of six KEV entries (CVE-2020-12271, CVE-2022-1040, CVE-2022-3236, CVE-2020-29574) are linked to China-nexus threat actors, with five named groups attributed. This is the highest documented density of state-sponsored exploitation per KEV entry of any vendor in the dataset. Sophos devices are not being exploited opportunistically -- they are being targeted deliberately by well-resourced adversaries with a shared exploit development pipeline.

2. **Severity floor.** Every Sophos KEV entry is CVSS 9.8 or above. Every one is pre-authentication. No other vendor in the dataset has this consistency -- most vendors have a mix of critical and moderate-severity entries. When a Sophos edge vulnerability reaches the KEV catalog, it is by definition a worst-case exploitation scenario.

3. **Attack surface recurrence.** The User Portal and Webadmin interfaces on the WAN zone have produced three separate KEV-listed vulnerabilities across different vulnerability classes (SQL injection, authentication bypass, code injection). The recurring pattern in the same product surface indicates an architectural issue, not isolated implementation bugs.

4. **Legacy tail risk.** Two of six entries (CVE-2020-15069, CVE-2020-29574) affect end-of-life products (XG Firewall v17.x and CyberoamOS) that will never receive further patches. The February 2025 KEV additions -- five years after initial disclosure -- confirm that exploitation of these legacy products is ongoing. Organizations still running these platforms are permanently exposed.

---

## Defender Implications

**1. Disable WAN-facing User Portal and Webadmin.** Three KEV entries target this surface. Sophos recommends restricting management access to the LAN zone or a dedicated management VLAN. If WAN access is required, use a VPN tunnel rather than direct exposure.

**2. Audit for CyberoamOS and XG v17.x.** Both platforms are end-of-life and will not receive further patches. The February 2025 KEV additions confirm active exploitation. Organizations running either platform should replace the hardware -- there is no software mitigation.

**3. Leverage Sophos's automatic hotfix mechanism.** Ensure firewalls are configured to receive and apply automatic hotfixes. This is Sophos's structural advantage over vendors that require manual patching. Verify the hotfix subscription is active and not blocked by network policy.

**4. Consume the Pacific Rim IOCs.** Sophos published detailed indicators of compromise alongside the Pacific Rim report. These IOCs are directly relevant if your organization operates in South or Southeast Asia, or in critical infrastructure sectors (energy, government, military, aviation) targeted by the documented campaign.

---

## Sources

- **Sophos X-Ops:** [Pacific Rim report](https://www.sophos.com/en-us/content/pacific-rim) (Oct 2024); [Timeline](https://news.sophos.com/en-us/2024/10/31/pacific-rim-timeline/); [Security Advisories](https://www.sophos.com/en-us/security-advisories)
- **CISA:** [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) (Volt Typhoon)
- **Volexity:** [DriftingCloud / CVE-2022-1040](https://securityaffairs.com/132377/apt/chinese-driftingcloud-apt-exploited-sophos-firewall-zero-day-before-it-was-fixed.html); **Recorded Future:** [TA413 / CVE-2022-1040](https://www.recordedfuture.com/research/chinese-state-sponsored-group-ta413-adopts-new-capabilities-in-pursuit-of-tibetan-targets); **CVEFeed:** [APT31 / CVE-2020-29574](https://cvefeed.io/vuln/detail/CVE-2020-29574)
- **Tenable:** [CVE-2020-12271 analysis](https://www.tenable.com/blog/cve-2020-12271-zero-day-sql-injection-vulnerability-in-sophos-xg-firewall-exploited-in-the-wild); **ZDI:** [CVE-2022-3236 analysis](https://www.thezdi.com/blog/2022/10/19/cve-2022-3236-sophos-firewall-user-portal-and-web-admin-code-injection)
- **NVD:** CVSS scoring and CWE classification for all 6 CVEs; **FIRST.org EPSS:** via [api.first.org](https://api.first.org/data/v1/epss)

---

> **Note on raw counts:** Sophos's count of 6 should be read alongside the attribution data. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. Sophos's count is elevated in part because nation-state actors -- particularly China-nexus groups -- have invested sustained effort in finding and exploiting Sophos edge device vulnerabilities, as documented in the Pacific Rim report. This means the count reflects both the vulnerability surface and the intensity of adversary focus, which are distinct risk factors. Conversely, the low raw count relative to Fortinet (18) or Ivanti (16) should not be mistaken for lower risk -- all 6 Sophos entries are CVSS 9.8+ Critical pre-auth vulnerabilities, a severity consistency unmatched by any other vendor.
