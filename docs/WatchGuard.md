# WatchGuard Technologies

**Scope: WatchGuard Firebox / XTM (Fireware OS) -- UTM firewall + SSL-VPN / Mobile VPN appliance.** *(4 edge KEV entries -- a mid-range count. Two are from the 2022 Cyclops Blink cluster attributed to Russian GRU; two are 2025 `iked` out-of-bounds writes, one of which was a confirmed zero-day. WatchGuard's SMB-skewed installed base is a structural risk multiplier.)*

---

## KEV CVE Summary Table

All 4 CISA KEV-listed CVEs for WatchGuard edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Published | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|-----------|----------|:--------:|:----------:|
| [CVE-2022-26318](https://nvd.nist.gov/vuln/detail/CVE-2022-26318) | 9.8 | CWE-787 Out-of-bounds Write | 2022-03-04 | 2022-03-25 | N | Unknown |
| [CVE-2022-23176](https://nvd.nist.gov/vuln/detail/CVE-2022-23176) | 8.8 | CWE-269 Improper Privilege Management | 2022-02-24 | 2022-04-11 | N | Unknown |
| [CVE-2025-9242](https://nvd.nist.gov/vuln/detail/CVE-2025-9242) | 9.3 | CWE-787 Out-of-bounds Write | 2025-09-17 | 2025-11-12 | N | Unknown |
| [CVE-2025-14733](https://nvd.nist.gov/vuln/detail/CVE-2025-14733) | 9.8 | CWE-787 Out-of-bounds Write | 2025-12-19 | 2025-12-19 | Y | Unknown |

**Summary statistics:** 4 KEV entries spanning 2022--2025. 3 of 4 rated CRITICAL (CVSS 9.3--9.8); CVE-2022-23176 is HIGH (8.8). 1 confirmed zero-day (CVE-2025-14733, added to KEV on its publication date with active exploitation). 0 entries carry CISA's ransomware-association flag -- WatchGuard's KEV record is, to date, a nation-state and botnet story rather than a ransomware story. CWE-787 (Out-of-bounds Write) accounts for 3 of 4 entries; the fourth is a privilege-management flaw (CWE-269) that formed part of the Cyclops Blink botnet cluster.

---

## Market Position

WatchGuard is a Seattle-based network-security vendor focused on the mid-market and SMB segment, where its Firebox UTM appliances compete with [Zyxel](Zyxel.md), [SonicWall](SonicWall.md), and the lower tiers of [Fortinet](Fortinet.md) and [Sophos](Sophos.md). WatchGuard does not appear in the Gartner Magic Quadrant alongside the enterprise incumbents ([Check Point](CheckPoint.md), Palo Alto Networks, Fortinet), but its installed base of internet-facing Firebox appliances is substantial: [Shadowserver Foundation data from December 2025](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html) counted roughly **117,000 internet-exposed WatchGuard instances** vulnerable to a single CVE, and the [October 2025 disclosure of CVE-2025-9242](https://www.bleepingcomputer.com/news/security/over-115-000-watchguard-firewalls-vulnerable-to-ongoing-rce-attacks/) put the exposed-and-vulnerable population north of 115,000.

That SMB-skewed base is a structural risk multiplier, the same dynamic documented for [Zyxel](Zyxel.md). SMB customers operate with smaller IT teams, less mature patch-management processes, and longer mean-time-to-patch than the regulated enterprises that dominate Check Point's or Palo Alto's installed base. WatchGuard's own remediation tooling history makes the point: after the 2022 Cyclops Blink compromise, WatchGuard had to ship a [4-Step Cyclops Blink Diagnosis and Remediation Plan](https://techsearch.watchguard.com/KB?type=Article&SFDCID=kA16S000000SOJHSA4&lang=en_US) and purpose-built detection tools precisely because its customer base could not be assumed to perform the diagnosis and cleanup unaided. The mid-market positioning that makes Firebox attractive also makes its exposed population slow to patch once exploitation is automated -- exactly the pattern that left 117,000 devices exposed in late 2025.

---

## Timeline

### 2022: The Cyclops Blink Cluster -- CVE-2022-23176 + CVE-2022-26318

WatchGuard's first two KEV entries are inseparable from **Cyclops Blink**, a modular botnet framework attributed to the Russian GRU threat group **Sandworm** (also tracked as Voodoo Bear). On [February 23, 2022, a joint advisory (AA22-054A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-054a) from CISA, the FBI, the NSA, and the UK's National Cyber Security Centre (NCSC) identified Cyclops Blink as Sandworm's replacement for the VPNFilter framework that had been sinkholed in 2018. The advisory stated the malware had been deployed since at least **June 2019** and had been primarily delivered to WatchGuard Firebox devices, with later expansion to ASUS routers.

**[CVE-2022-23176](https://nvd.nist.gov/vuln/detail/CVE-2022-23176)** (CVSS 8.8, CWE-269 Improper Privilege Management, KEV 2022-04-11) is the access vector at the center of the botnet. It allows a remote attacker with unprivileged credentials to obtain a **privileged management session** on Firebox and XTM appliances via exposed management access. Critically -- and consistent with the SMB risk-multiplier thesis -- the flaw is only exploitable when the appliance is configured to allow **unrestricted management access from the internet**, which is not the default. WatchGuard estimated that [approximately 1% of active appliances](https://www.bleepingcomputer.com/news/security/cisa-warns-orgs-of-watchguard-bug-exploited-by-russian-state-hackers/) were affected -- a small fraction in percentage terms, but a meaningful absolute number given the installed base, and every one of them was a device whose operator had exposed management to the open internet. CISA added it to the KEV catalog on April 11, 2022, with a three-week federal remediation deadline (May 2, 2022).

**[CVE-2022-26318](https://nvd.nist.gov/vuln/detail/CVE-2022-26318)** (CVSS 9.8, classified CWE-787 Out-of-bounds Write in NVD/MITRE) is the more severe of the pair: an unauthenticated remote code execution flaw in the management interface (ports 8080/4117) of Firebox and XTM appliances. WatchGuard's own [PSIRT advisory WGSA-2022-00002](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2022-00002) describes the root cause as a null-pointer dereference reachable via exposed management access, while [Assetnote's technical analysis](https://www.assetnote.io/resources/research/diving-deeper-into-watchguard-pre-auth-rce-cve-2022-26318) traced the pre-auth path through the `/agent/login` endpoint into the `wgagent` C binary. WatchGuard published the advisory on February 23, 2022 -- the same day as the joint Cyclops Blink advisory -- and CISA added the CVE to the KEV catalog on March 25, 2022. WatchGuard's advisory states it had evidence of active exploitation in the wild, but neither WatchGuard nor CISA documents a pre-disclosure exploitation window for CVE-2022-26318 specifically, so it is recorded here as **not a confirmed zero-day**.

#### Disruption and Remediation

The Cyclops Blink episode is one of the few in this dataset to end in a law-enforcement disruption. On [April 6, 2022, the US Department of Justice announced a court-authorized FBI operation](https://thehackernews.com/2022/04/fbi-shut-down-russia-linked-cyclops.html) that copied and removed Cyclops Blink malware from the command-and-control firewall devices Sandworm was using as botnet infrastructure, and closed the external management ports the actor relied on -- severing the operator's control before the botnet was fully weaponized. WatchGuard partnered with the FBI on the operation and, [supported by the FBI, CISA, NSA, and NCSC](https://techsearch.watchguard.com/KB?type=Article&SFDCID=kA16S000000SOJHSA4&lang=en_US), released detection tooling and the 4-step diagnosis-and-remediation plan referenced above. EPSS scores: CVE-2022-26318 at 0.78303 (99.52nd percentile), CVE-2022-23176 at 0.12249 (95.66th percentile).

### 2025: The `iked` Out-of-Bounds Writes -- CVE-2025-9242 + CVE-2025-14733

WatchGuard's 2025 KEV entries are two out-of-bounds writes in the **`iked`** process -- the IKE/IKEv2 daemon that terminates WatchGuard's Mobile VPN and branch-office VPN tunnels.

**[CVE-2025-9242](https://nvd.nist.gov/vuln/detail/CVE-2025-9242)** (CVSS 9.3, CWE-787, KEV 2025-11-12) is a pre-authentication remote code execution flaw. [watchTowr Labs](https://labs.watchtowr.com/yikes-watchguard-fireware-os-ikev2-out-of-bounds-write-cve-2025-9242/) reverse-engineered the patch and identified the root cause as a stack-based buffer overflow in the `ike2_ProcessPayload_CERT` function: an unchecked `memcpy` of an attacker-controlled identification payload into a fixed 520-byte stack buffer, reachable during `IKE_SA_AUTH` **before certificate validation completes** -- i.e., with just two unauthenticated IKE packets (`IKE_SA_INIT` followed by `IKE_SA_AUTH`). WatchGuard's [PSIRT advisory WGSA-2025-00015](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00015) was published September 17, 2025 and updated on October 21, 2025 to add indicators of attack and remediation guidance "due to potential active exploits in the wild." The advisory enumerates affected branches from 11.10.2 through 2025.1 and confirms the bug is reachable via mobile-user IKEv2 VPN and branch-office IKEv2 VPN with a dynamic gateway peer. CISA added CVE-2025-9242 to the KEV catalog on November 12, 2025. EPSS score: 0.8637 (99.71st percentile).

**[CVE-2025-14733](https://nvd.nist.gov/vuln/detail/CVE-2025-14733)** (CVSS 9.8, CWE-787, KEV 2025-12-19) is the second `iked` out-of-bounds write, disclosed in December 2025. [The Hacker News reported](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html) that WatchGuard "observed threat actors actively attempting to exploit this vulnerability in the wild," and CISA added it to the KEV catalog on **December 19, 2025 -- the same day as its NVD publication** -- with an unusually short one-week federal deadline (December 26, 2025). That same-day KEV-plus-exploitation pattern is what qualifies CVE-2025-14733 as WatchGuard's one confirmed **zero-day** in this dataset. [Shadowserver](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html) counted roughly 117,490 internet-exposed instances vulnerable to it in the days after disclosure. The public record establishes CVE-2025-14733 as a distinct `iked` out-of-bounds write rather than confirming it as a patch-bypass of CVE-2025-9242; the relationship between the two `iked` flaws -- whether 14733 is an incomplete-fix regression of 9242 or an independent bug in the same daemon -- is **not yet definitively documented in the sources reviewed**, and is flagged here as uncertain. EPSS score: 0.17469 (96.75th percentile).

---

## CWE Weakness Profile

| Category | Count | CVEs |
|----------|------:|------|
| **Out-of-bounds Write** (CWE-787) | 3 | CVE-2022-26318, CVE-2025-9242, CVE-2025-14733 |
| **Improper Privilege Management** (CWE-269) | 1 | CVE-2022-23176 |

**Pattern:** WatchGuard's KEV profile is dominated by memory-corruption -- three of four entries are out-of-bounds writes (CWE-787). This is a meaningfully different signature from [Check Point's](CheckPoint.md) credential-extraction + auth-bypass profile and closer to [Fortinet's](Fortinet.md) memory-corruption history, though concentrated in two distinct subsystems rather than one. The 2022 CVE-2022-26318 OOB write sat in the HTTP management plane; the 2025 pair sit in the `iked` IKEv2 VPN daemon. The recurrence of CWE-787 in the same `iked` process across two CVEs in a single quarter (CVE-2025-9242 in September, CVE-2025-14733 in December) suggests the IKE/IKEv2 payload-parsing code path carries systemic memory-safety debt rather than a one-off bug. The lone outlier, CVE-2022-23176 (CWE-269), is a privilege-management flaw whose significance is contextual: it was the access primitive Sandworm chained into the Cyclops Blink botnet. See [CWE-ANALYSIS.md](CWE-ANALYSIS.md) for cross-vendor comparison.

---

## Threat Actor Attribution

### Nation-State Exploitation

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Sandworm / Voodoo Bear (Russia, GRU)** | CVE-2022-23176 (Cyclops Blink botnet) | [CISA/FBI/NSA/NCSC joint advisory AA22-054A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-054a) |

The Cyclops Blink attribution is among the most firmly established in this dataset: a four-agency joint advisory (CISA, FBI, NSA, NCSC) named Sandworm -- a group with prior, well-documented GRU attribution -- and the attribution was operationalized into a court-authorized FBI takedown. As [METHODOLOGY.md](../METHODOLOGY.md) notes, attribution is probabilistic even when multiple government agencies concur; the strength here is the convergence of a multi-agency advisory, a botnet framework with a documented VPNFilter lineage, and a legal action premised on the same attribution. CVE-2022-23176 is the chained access vector; CVE-2022-26318 (the unauthenticated RCE) is documented as actively exploited in the wild but is not specifically tied by the joint advisory to Sandworm versus opportunistic actors, so its attribution should be treated as less certain than CVE-2022-23176's.

### 2025 Exploitation

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Unattributed (active exploitation)** | CVE-2025-9242, CVE-2025-14733 | [WatchGuard PSIRT](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00015), [The Hacker News](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html) |

The 2025 `iked` exploitation is confirmed active but not publicly attributed to a named actor as of this writing. Reporting on CVE-2025-14733 listed [specific scanning/exploitation source IPs](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html) (e.g., 45.95.19.50, 51.15.17.89) without resolving them to a known cluster. No ransomware association is flagged by CISA for any of WatchGuard's four KEV entries. See [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md) for cross-vendor attribution analysis.

---

## EPSS Context

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2022-26318 | 0.78303 | 99.52nd |
| CVE-2022-23176 | 0.12249 | 95.66th |
| CVE-2025-9242 | 0.86370 | 99.71st |
| CVE-2025-14733 | 0.17469 | 96.75th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

The two unauthenticated RCEs -- CVE-2022-26318 (0.78) and CVE-2025-9242 (0.86) -- carry the highest EPSS scores, consistent with their no-privileges-required, network-accessible attack surface and the availability of public exploit tooling (a [Metasploit module exists for CVE-2022-26318](https://www.rapid7.com/db/modules/exploit/linux/http/watchguard_firebox_unauth_rce_cve_2022_26318/)). CVE-2025-14733's lower EPSS (0.17, 96.75th percentile) reflects its recency: as [the Zyxel CVE-2024-11667 case demonstrates](Zyxel.md), EPSS measures population-wide exploit probability and lags real-world weaponization, so a recent zero-day with confirmed active exploitation can carry a deceptively moderate score while being among the most operationally urgent entries in the set.

---

## The Count: Context, Not Comfort

WatchGuard's **4 KEV entries** place it in the mid-range of this dataset -- above [Check Point](CheckPoint.md) (2), below [Zyxel](Zyxel.md) (6) and [Fortinet](Fortinet.md). As with every vendor here, the count is not a clean proxy for security quality. The repo's thesis holds: **no vendor in this dataset is dramatically cleaner than the others, and raw counts partly reflect installed base and researcher attention** rather than intrinsic code quality. Four confounders apply to WatchGuard specifically:

### 1. Installed Base and Research Attention

WatchGuard attracts less sustained researcher scrutiny than Fortinet or Palo Alto Networks. The 2022 entries surfaced because a nation-state botnet forced government and vendor investigation; the 2025 entries surfaced because [watchTowr](https://labs.watchtowr.com/yikes-watchguard-fireware-os-ikev2-out-of-bounds-write-cve-2025-9242/) chose to reverse-engineer a Fireware patch. A product family analyzed in bursts (botnet incident, then a single researcher's deep-dive) generates a bursty, count-suppressing CVE record relative to its actual vulnerability surface -- the "popularity tax" described in [METHODOLOGY.md](../METHODOLOGY.md).

### 2. SMB Installed Base as a Structural Risk Multiplier

This is the dominant confounder for WatchGuard, mirroring [Zyxel's](Zyxel.md) profile. The ~117,000 exposed-and-vulnerable instances observed in late 2025 are direct evidence that WatchGuard's SMB customers do not patch within the exploitation window. A mid-market base with thin security operations means a low CVE *count* coexists with a high exploited-device *population*. The count understates the risk because the risk is concentrated not in the number of bugs but in the slowness of the patch response.

### 3. Severity and Exploitability Concentration

Three of four entries are CRITICAL (CVSS 9.3--9.8), and two are unauthenticated, no-interaction RCEs -- the most reliably weaponizable primitive class. The single HIGH entry (CVE-2022-23176) became the keystone of a GRU botnet despite its 8.8 score. Severity is not diluted across the four entries; it is concentrated in pre-auth code execution.

### 4. What the Count Does Not Mean

A count of 4 does **not** mean WatchGuard's Fireware codebase has fewer memory-safety defects than higher-count vendors -- the repeated CWE-787 OOB writes in the `iked` daemon within a single quarter argue the opposite for that subsystem. It **does** mean there are four confirmed, cataloged exploitation events to learn from, two of them tied to a documented nation-state campaign, and that the historical record is thinner than Fortinet's or Cisco's for forecasting future exploitation patterns.

---

## Disclosure Assessment

### Positive Indicators

- **Coordinated, multi-agency disclosure in 2022.** WatchGuard published [WGSA-2022-00002](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2022-00002) alongside the [joint government advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-054a) and partnered with the FBI on the takedown -- a substantially better incident posture than the unilateral, framing-controlled communication seen in [Check Point's CVE-2024-24919 episode](CheckPoint.md).
- **Purpose-built remediation tooling.** WatchGuard shipped [detection tools and a 4-step diagnosis-and-remediation plan](https://techsearch.watchguard.com/KB?type=Article&SFDCID=kA16S000000SOJHSA4&lang=en_US) for Cyclops Blink rather than leaving SMB customers to self-assess compromise -- an appropriate response to its own installed base's limitations.
- **PSIRT portal with per-CVE advisories.** WatchGuard maintains a [PSIRT advisory portal](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00015) with affected-version matrices and discrete advisory IDs (WGSA-YYYY-NNNNN), unlike vendors that ship firmware-only fixes without discrete advisories ([Zyxel's CVE-2022-30525 silent patch](Zyxel.md)).

### Concerns

- **Recurring memory-safety debt in `iked`.** Two CWE-787 out-of-bounds writes in the same IKEv2 daemon within a single quarter (CVE-2025-9242, CVE-2025-14733) indicate the IKE payload-parsing path was not comprehensively hardened after the first fix. Whether the second was an incomplete-fix regression is not publicly confirmed, but the recurrence itself is a process concern.
- **Patch-to-exploitation gap left ~117,000 devices exposed.** Even with timely advisories, the late-2025 exposure data shows the disclosure process is insufficient when the installed base cannot absorb patches before exploitation broadens -- the same structural failure documented for [Zyxel's 2023 botnet campaign](Zyxel.md).
- **Internet-exposed management as a precondition.** CVE-2022-23176 and CVE-2022-26318 both required exposed management access. That so many devices had management exposed to the internet -- against WatchGuard's own default -- is a shared customer/vendor configuration-hardening failure.

---

## Defender Implications

**1. Patch `iked`/IKEv2 RCEs as same-day emergencies.** CVE-2025-9242 and CVE-2025-14733 are unauthenticated, pre-auth-reachable RCEs in the VPN daemon, and CVE-2025-14733 was a confirmed zero-day. Any Fireware advisory touching the IKE/IKEv2 path should be treated as an immediate emergency, not a maintenance-window task. The ~117,000 exposed-device figure is the empirical proof that next-window patching is too slow for this product.

**2. Restrict VPN and management exposure to the minimum.** Both 2022 CVEs required internet-exposed management access; both 2025 CVEs are reachable via internet-facing IKEv2 VPN endpoints. Audit every Firebox for exposed management interfaces, restrict management to dedicated VLANs or jump hosts, and where mobile-user or branch-office IKEv2 VPN is not required, disable it. For VPN that must be exposed, follow WatchGuard's [PSIRT indicators-of-attack guidance](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00015).

**3. Treat any pre-2022-patch Firebox as a Cyclops Blink compromise candidate.** Devices that ran vulnerable Fireware with exposed management during the 2019--2022 Cyclops Blink window should be assessed with WatchGuard's [detection tooling and 4-step remediation plan](https://techsearch.watchguard.com/KB?type=Article&SFDCID=kA16S000000SOJHSA4&lang=en_US), not merely patched -- the malware persisted through firmware updates, so a routine upgrade did not guarantee eviction.

**4. Do not read a mid-range count as mid-range risk.** WatchGuard's 4 entries include a GRU botnet keystone and a same-day zero-day, and its SMB base patches slowly enough to leave six-figure exposed-device populations. Organizations running Firebox should hold the same patch-urgency and incident-response posture as those running [Fortinet](Fortinet.md) or [Zyxel](Zyxel.md); the count does not buy comfort.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [Joint Advisory AA22-054A -- New Sandworm Malware Cyclops Blink Replaces VPNFilter](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-054a)
- **WatchGuard PSIRT:** [WGSA-2022-00002 (CVE-2022-26318 unauthenticated RCE)](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2022-00002); [WGSA-2025-00015 (CVE-2025-9242 iked OOB write)](https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00015); [Cyclops Blink FAQs / 4-step remediation](https://techsearch.watchguard.com/KB?type=Article&SFDCID=kA16S000000SOJHSA4&lang=en_US)
- **watchTowr Labs:** [yIKEs -- WatchGuard Fireware OS IKEv2 Out-of-Bounds Write CVE-2025-9242](https://labs.watchtowr.com/yikes-watchguard-fireware-os-ikev2-out-of-bounds-write-cve-2025-9242/)
- **Assetnote:** [Diving Deeper into WatchGuard Pre-Auth RCE -- CVE-2022-26318](https://www.assetnote.io/resources/research/diving-deeper-into-watchguard-pre-auth-rce-cve-2022-26318)
- **BleepingComputer:** [CISA warns orgs of WatchGuard bug exploited by Russian state hackers](https://www.bleepingcomputer.com/news/security/cisa-warns-orgs-of-watchguard-bug-exploited-by-russian-state-hackers/); [Over 115,000 WatchGuard firewalls vulnerable to ongoing RCE attacks](https://www.bleepingcomputer.com/news/security/over-115-000-watchguard-firewalls-vulnerable-to-ongoing-rce-attacks/)
- **The Hacker News:** [WatchGuard Warns of Active Exploitation of Critical Fireware OS VPN Vulnerability (CVE-2025-14733)](https://thehackernews.com/2025/12/watchguard-warns-of-active-exploitation.html); [FBI Shut Down Russia-linked Cyclops Blink Botnet](https://thehackernews.com/2022/04/fbi-shut-down-russia-linked-cyclops.html)
- **Rapid7:** [WatchGuard XTM Firebox Unauthenticated RCE Metasploit module (CVE-2022-26318)](https://www.rapid7.com/db/modules/exploit/linux/http/watchguard_firebox_unauth_rce_cve_2022_26318/)
- **NVD:** CVSS scoring and CWE classification for all 4 CVEs
- **FIRST.org EPSS:** [Exploit Prediction Scoring System data](https://api.first.org/data/v1/epss)

---

> **Note on raw counts:** WatchGuard's count of 4 should be interpreted in context. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention. WatchGuard attracts less scrutiny than Fortinet or Palo Alto, which may suppress the count, while its SMB installed base -- the same structural risk multiplier seen in [Zyxel](Zyxel.md) -- left roughly 117,000 devices exposed and vulnerable in late 2025. The mid-range count does not place WatchGuard in a mid-range risk tier; the concentration of pre-auth RCEs and the slow-patching customer base argue otherwise.
