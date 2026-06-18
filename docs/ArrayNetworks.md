# Array Networks

**Scope: Array Networks AG / vxAG secure-access gateways (ArrayOS AG -- SSL VPN / remote-access gateway).** *(2 edge KEV entries -- tied with [Check Point](./CheckPoint.md) for the lowest count of any vendor in this repo. One is CISA-flagged ransomware-associated and confirmed exploited by a China-nexus espionage actor.)*

---

## KEV CVE Summary Table

All 2 CISA KEV-listed CVEs for Array Networks edge appliances, ordered by KEV date added.

| CVE | CVSS | CWE Class | Published | KEV Date | Zero-Day | Ransomware |
|-----|------|-----------|-----------|----------|:--------:|:----------:|
| [CVE-2023-28461](https://nvd.nist.gov/vuln/detail/CVE-2023-28461) | 9.8 | CWE-306 Missing Authentication | 2023-03-15 | 2024-11-25 | N | Y |
| [CVE-2025-66644](https://nvd.nist.gov/vuln/detail/CVE-2025-66644) | 7.2 | CWE-78 OS Command Injection | 2025-12-05 | 2025-12-08 | N | N |

**Summary statistics:** 2 KEV entries -- tied with [Check Point](./CheckPoint.md) for the smallest vendor count in this dataset. Neither is a confirmed zero-day in the classic sense -- both were patched well before CISA's KEV listing (CVE-2023-28461 was fixed in March 2023, roughly 20 months before its November 2024 KEV addition; CVE-2025-66644 was published only three days before its KEV addition but the exploitation window predates the public CVE). One entry (CVE-2023-28461) carries CISA's ransomware-association flag (50% ransomware rate). Both achieve or enable remote code execution on the SSL-VPN gateway, but through different primitives: missing authentication for a critical function (CWE-306) and OS command injection (CWE-78). The CWE profile -- access-control failure plus command injection -- mirrors the broader edge-VPN exploitation pattern more than [Check Point's](./CheckPoint.md) credential-extraction / auth-bypass pairing.

---

## Market Position

Array Networks is a niche, privately held application-delivery and secure-access vendor, substantially smaller than the firewall incumbents ([Fortinet](./Fortinet.md), [Palo Alto](./PaloAlto.md), [Check Point](./CheckPoint.md)) or the dedicated VPN players ([Ivanti](./Ivanti.md), [Citrix](./Citrix.md)). Its AG / vxAG product line provides SSL-VPN and secure-access gateway functionality -- a direct competitor to Ivanti Connect Secure and Citrix Gateway -- and the ArrayOS AG software underpins both the physical AG appliances and the virtual vxAG instances.

The installed base is correspondingly small. [Censys identified roughly 3,427 internet-routable Array Networks AG/vxAG VPN devices](https://censys.com/advisory/cve-2023-28461) at the time of the CVE-2023-28461 KEV listing -- with approximately one-third located in the United States -- compared with the tens of thousands of exposed gateways enumerated for [Fortinet](./Fortinet.md), [Ivanti](./Ivanti.md), or [Citrix](./Citrix.md) during their respective mass-exploitation events. Array's customer base skews toward enterprises and government agencies in Asia-Pacific markets (Japan, Taiwan, and India recur in the exploitation reporting), which is consistent with the regional targeting of the threat actor attributed to CVE-2023-28461.

A small installed base and a small dedicated-researcher community are the two structural reasons Array's KEV count is low -- a point developed in **The Low Count** section below.

---

## Timeline

### 2023--2024: CVE-2023-28461 -- Long-Tail Disclosure, China-Nexus Espionage Exploitation

**CVE-2023-28461** (CVSS 9.8, missing authentication for a critical function / CWE-306) is the defining Array Networks edge vulnerability in the KEV record. The flaw allows an **unauthenticated remote attacker to browse the filesystem and ultimately execute code** on the AG/vxAG SSL-VPN gateway. Per [Trend Micro and subsequent reporting](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), the vulnerability is triggered by manipulating a **`flags` attribute in an HTTP header** -- a single crafted request reaches a vulnerable code path with no authentication, after which a vulnerable URL can be leveraged for remote code execution.

#### Discovery and Disclosure Timeline

- **March 15, 2023:** The CVE is published. Array Networks ships a fix in **ArrayOS AG 9.4.0.484**; all versions **9.4.0.481 and earlier** (the 9.x line) are affected ([cvedetails](https://www.cvedetails.com/cve/CVE-2023-28461/), [SecurityWeek](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/)).
- **2024:** [Trend Micro documented the LodeInfo campaign of Earth Kasha](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), identifying CVE-2023-28461 as one of the public-facing-product flaws the group used for initial access.
- **November 25, 2024:** [CISA added CVE-2023-28461 to the KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-28461), with a remediation due date of **December 16, 2024** for federal agencies ([The Hacker News](https://thehackernews.com/2024/11/cisa-urges-agencies-to-patch-critical.html)).
- **November 27, 2024:** [Censys published an advisory](https://censys.com/advisory/cve-2023-28461) enumerating ~3,427 internet-exposed AG/vxAG devices.

The roughly **20-month gap** between the patch (March 2023) and the KEV listing (November 2024) is the distinguishing feature of this entry: this is not a same-week zero-day like [Check Point's CVE-2024-24919](./CheckPoint.md). The vulnerability was patched, sat in the wild on unpatched gateways, and only entered the KEV catalog once threat-intelligence reporting confirmed active exploitation -- the long-tail exploitation pattern that [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md) examines across this dataset.

#### Exploitation Profile

[Trend Micro attributed exploitation to **Earth Kasha** (also tracked as **MirrorFace**)](https://thehackernews.com/2024/11/cisa-urges-agencies-to-patch-critical.html), a China-nexus espionage cluster associated with the broader APT10 umbrella. The group used CVE-2023-28461 alongside other public-facing-product flaws for initial access, then deployed backdoors including **LodeInfo**, **NOOPDOOR / NoopDoor**, and **Cobalt Strike** for persistence, targeting advanced-technology organizations and government agencies in **Japan, Taiwan, and India** ([SecurityWeek](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), [The Hacker News](https://thehackernews.com/2024/11/cisa-urges-agencies-to-patch-critical.html)). The operational pattern -- espionage-driven initial access and backdoor deployment rather than encryption-for-extortion -- is characteristic of a state-aligned intrusion set.

#### The Ransomware Flag

CISA's KEV catalog marks CVE-2023-28461 as **`knownRansomwareCampaignUse: "Known"`** ([reflected in CISA KEV reporting](https://thecyberexpress.com/cisa-adds-cve-2023-28461-vulnerability/)). This is worth flagging carefully: the **named, well-documented** exploitation is the Earth Kasha / MirrorFace espionage activity, not a named ransomware operator. CISA's "Known" flag indicates the agency has evidence of ransomware-campaign use, but the public threat-intelligence record for this CVE is dominated by espionage attribution. The two are not mutually exclusive -- access brokers and overlapping tooling routinely blur the line -- but defenders should treat the espionage attribution as the high-confidence claim and the ransomware association as CISA-asserted but less publicly corroborated. EPSS score: 0.67645 (99.22nd percentile).

### 2025: CVE-2025-66644 -- OS Command Injection, Recent KEV Addition

**CVE-2025-66644** (CVSS 7.2, OS command injection / CWE-78) was [published on December 5, 2025](https://www.cvedetails.com/cve/CVE-2025-66644/) and [added to the CISA KEV catalog on December 8, 2025](https://cvefeed.io/vuln/detail/CVE-2025-66644), three days later, with a remediation due date of **December 29, 2025**. The flaw affects **ArrayOS AG before 9.4.5.9** and allows command injection; the CVE record states it was [**exploited in the wild from August through December 2025**](https://x.com/CVEnew/status/1997021630321557510), with public reporting describing webshell deployment on compromised appliances.

The CVSS vector recorded for this entry is `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (base 7.2), with the **PR:H** (high privileges required) metric accounting for the High rather than Critical rating -- a meaningful distinction from CVE-2023-28461's fully unauthenticated CWE-306 primitive. *(Note: some third-party trackers list this CVE at CVSS 9.8; this repo uses the authoritative score recorded in the enriched dataset -- 7.2 with the PR:H vector above. Where trackers disagree, the privileged-access requirement is the load-bearing dispute.)* CISA does **not** flag this entry for ransomware (`knownRansomwareCampaignUse: "Unknown"`). EPSS score: 0.03046 (85.84th percentile) -- low, consistent with a privileged-access prerequisite and a very recent listing.

---

## CWE Weakness Profile

| Category | Count | CVEs |
|----------|------:|------|
| **Missing Authentication** (CWE-306) | 1 | CVE-2023-28461 |
| **OS Command Injection** (CWE-78) | 1 | CVE-2025-66644 |

**Pattern:** With only two data points, a CWE pattern is suggestive rather than definitive. Both CVEs target the gateway's web-facing request handling and both lead to or enable remote code execution, but via different roots: CVE-2023-28461 is an access-control failure (a critical function reachable without authentication), while CVE-2025-66644 is an input-validation failure (unsanitized input reaching an OS command). This access-control-plus-injection pairing aligns more closely with the broader edge-VPN exploitation pattern -- [Ivanti's](./Ivanti.md) auth-bypass-into-injection chains and [Citrix's](./Citrix.md) request-handling flaws -- than with [Check Point's](./CheckPoint.md) credential-extraction / authentication-bypass profile. Neither Array CVE is a memory-corruption bug, distinguishing the pair from [Fortinet's](./Fortinet.md) buffer-overflow chains. See [CWE-ANALYSIS.md](CWE-ANALYSIS.md) for cross-vendor comparison.

---

## Threat Actor Attribution

### Nation-State Exploitation

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Earth Kasha / MirrorFace (China-nexus, APT10 umbrella)** | CVE-2023-28461 | [Trend Micro via SecurityWeek](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), [The Hacker News](https://thehackernews.com/2024/11/cisa-urges-agencies-to-patch-critical.html) |

CVE-2023-28461 is one of the more cleanly attributed entries in this dataset: [Trend Micro tied it to Earth Kasha (MirrorFace)](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), a China-nexus espionage cluster, as part of the LodeInfo campaign. The post-exploitation tooling (LodeInfo, NOOPDOOR, Cobalt Strike) and the regional targeting (Japan, Taiwan, India) are consistent with documented Earth Kasha tradecraft. Attribution for this CVE is therefore stated with comparatively high confidence -- though, as always, "China-nexus espionage cluster" should be read as the well-supported claim, not necessarily a single attributable operator.

For **CVE-2025-66644**, no specific named actor is confirmed in public reporting at the time of writing. The CVE record describes webshell deployment during an August--December 2025 exploitation window, but does not name a group. **This document does not assert an actor for CVE-2025-66644** -- attribution is open.

### Ransomware Operators

| Actor | CVEs Exploited | Source |
|-------|---------------|--------|
| **Unspecified (CISA flag only)** | CVE-2023-28461 | [CISA KEV ransomware flag](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-28461) |

CVE-2023-28461 carries CISA's ransomware-association flag, but -- as noted in the timeline -- no specific ransomware operator is named in the public record, and the high-confidence attribution is espionage (Earth Kasha). Treat the ransomware association as CISA-asserted. CVE-2025-66644 carries no ransomware flag.

See [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md) for cross-vendor attribution analysis.

---

## EPSS Context

| CVE | EPSS | Percentile |
|-----|------|------------|
| CVE-2023-28461 | 0.67645 | 99.22nd |
| CVE-2025-66644 | 0.03046 | 85.84th |

*Source: [FIRST EPSS API](https://api.first.org/data/v1/epss), retrieved 2026-06-18.*

CVE-2023-28461's high EPSS score (99.22nd percentile) reflects its unauthenticated RCE primitive, public PoC maturity, and the sustained scanning that followed both the original 2023 disclosure and the 2024 KEV listing. CVE-2025-66644's low EPSS (85.84th percentile, absolute 0.03) is consistent with its high-privilege prerequisite (PR:H) and its very recent listing -- EPSS typically climbs as exploit tooling matures and scanning broadens, so this score is likely to rise.

---

## The Low Count: Context, Not Comfort

Array Networks ties [Check Point](./CheckPoint.md) for the **lowest edge KEV count (2) of any vendor in this repo**. As with Check Point, that figure invites a "safer vendor" reading that is both incomplete and -- here, given the niche-vendor confounders -- potentially more misleading.

### 1. Installed Base and Research Attention

Array Networks is a small, privately held vendor with an internet-exposed installed base ([~3,427 devices per Censys](https://censys.com/advisory/cve-2023-28461)) that is an order of magnitude smaller than [Fortinet](./Fortinet.md), [Ivanti](./Ivanti.md), or [Citrix](./Citrix.md). Two distinct forces suppress the count: a small fleet generates fewer mass-exploitation events that draw CISA's attention, **and** a small product family attracts far fewer security researchers publishing exploit chains against it -- the "popularity tax" that [METHODOLOGY.md](../METHODOLOGY.md) describes. For a niche vendor, both forces push in the same direction, so the low count says even less about underlying code quality than it does for a high-profile vendor.

### 2. Severity as the Corrective Signal

While the absolute count is 2, CVE-2023-28461 is a **CVSS 9.8 unauthenticated RCE** that was exploited by a named China-nexus espionage actor against government and high-technology targets. A small count of low-severity bugs would be reassuring; a small count where one entry is a maximum-severity, nation-state-exploited gateway compromise is not. The single most consequential Array CVE is as severe as anything in [Ivanti's](./Ivanti.md) or [Citrix's](./Citrix.md) far longer lists.

### 3. Ransomware and Espionage Signal

One of the two entries (50%) carries CISA's ransomware flag, and the better-documented exploitation is state-aligned espionage. The KEV entries Array does have are operationally consequential -- initial access into government and advanced-technology environments -- not theoretical. The sample is too small for statistical confidence, but the qualitative signal is real.

### 4. What a Low Count Does Not Mean

A low count does not mean:
- Array's codebase has fewer vulnerabilities (it means fewer have been found, weaponized, and publicly cataloged -- and a niche vendor draws fewer researchers to find them)
- Array's gateway is architecturally more secure (CVE-2023-28461 was a trivially exploitable, fully unauthenticated RCE)
- Organizations running Array AG/vxAG face less risk (a single CVE enabled China-nexus espionage access into government networks)

A low count **does** mean:
- Fewer confirmed, cataloged exploitation events exist for this product line
- The historical data provides less signal for predicting future exploitation patterns
- Defenders have fewer case studies to inform detection and response playbooks -- and a small vendor may publish thinner advisories and post-compromise guidance than the incumbents

---

## Disclosure Assessment

### Positive Indicators

- **Patch available long before KEV listing (CVE-2023-28461).** Array shipped ArrayOS AG 9.4.0.484 in March 2023, roughly 20 months before the November 2024 KEV addition. Organizations that patched promptly in 2023 were never exposed to the documented 2024 exploitation window -- the gap between fix and KEV reflects unpatched-fleet exploitation, not an unpatched vulnerability.
- **Fixed version clearly identified.** Both CVEs name a specific clean version (9.4.0.484 for CVE-2023-28461; 9.4.5.9 for CVE-2025-66644), giving defenders an unambiguous remediation target.

### Concerns

- **Thin public post-compromise guidance.** As a niche vendor, Array's public advisory footprint is sparse compared with the [Check Point PSIRT portal](./CheckPoint.md) or [Fortinet's PSIRT](./Fortinet.md). Most of the actionable exploitation detail for CVE-2023-28461 came from third parties ([Trend Micro](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/), [Censys](https://censys.com/advisory/cve-2023-28461)), not from Array.
- **Long exploitation tail on a patched bug.** The ~20-month interval between the CVE-2023-28461 fix and confirmed in-the-wild exploitation shows that a patched vulnerability remained a live threat against the unpatched fleet for a very long time -- a particular risk for niche appliances that may receive less attentive patch management than mainstream firewalls.
- **CVSS ambiguity on CVE-2025-66644.** Third-party trackers disagree on the score (7.2 vs 9.8), hinging on whether the command injection requires prior privileges. Defenders should not wait for the dispute to settle: an actively exploited command-injection path in an internet-facing gateway warrants treatment as critical regardless of the nominal base score.

---

## Defender Implications

**1. Patch promptly -- the exploitation tail is long.** CVE-2023-28461 was fixed in March 2023 but exploited well into 2024 against unpatched gateways. Confirm every AG/vxAG appliance is on at least ArrayOS AG 9.4.0.484 (for CVE-2023-28461) and 9.4.5.9 (for CVE-2025-66644). A patch you never applied protects no one; niche appliances are exactly the assets that slip out of patch cadence.

**2. Treat CVE-2023-28461 as a confirmed-compromise scenario for any device exposed and unpatched during 2023--2024.** The vulnerability gave unauthenticated RCE to a China-nexus espionage actor that deployed LodeInfo, NOOPDOOR, and Cobalt Strike. Any gateway that was internet-exposed and unpatched in that window should receive a full compromise assessment: hunt for webshells, unexpected processes, backdoor implants, and lateral movement from the gateway into internal networks -- not just a patch.

**3. Hunt for webshells on appliances exposed during 2025 (CVE-2025-66644).** Public reporting describes webshell deployment via the command-injection path across an August--December 2025 window. Inspect the gateway filesystem and web roots for unauthorized scripts, review command-execution logs, and validate appliance integrity even after patching to 9.4.5.9.

**4. Do not read the low CVE count as low risk.** Array's 2 KEV entries include a CVSS 9.8 unauthenticated RCE exploited by a named nation-state actor and one CISA ransomware-flagged CVE. A niche vendor's small count is driven as much by limited researcher attention and a small fleet as by code quality. Organizations running Array AG/vxAG should maintain the same patch-urgency and incident-response posture as those running [Ivanti](./Ivanti.md) or [Citrix](./Citrix.md) gateways -- the lower historical frequency does not reduce the severity of each individual event.

---

## Sources

- **CISA:** [Known Exploited Vulnerabilities Catalog (CVE-2023-28461 entry)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-28461)
- **Trend Micro / SecurityWeek:** [Chinese Hackers Exploiting Critical Vulnerability in Array Networks Gateways](https://www.securityweek.com/chinese-hackers-exploiting-critical-vulnerability-in-array-networks-gateways/)
- **The Hacker News:** [CISA Urges Agencies to Patch Critical "Array Networks" Flaw Amid Active Attacks](https://thehackernews.com/2024/11/cisa-urges-agencies-to-patch-critical.html)
- **Censys:** [November 27 Advisory: Actively Exploited RCE Vulnerability in Array Networks VPNs (CVE-2023-28461)](https://censys.com/advisory/cve-2023-28461)
- **BleepingComputer:** [Hackers exploit critical bug in Array Networks SSL VPN products](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-bug-in-array-networks-ssl-vpn-products/)
- **The Cyber Express:** [CISA Adds CVE-2023-28461 Vulnerability To KEV Catalog](https://thecyberexpress.com/cisa-adds-cve-2023-28461-vulnerability/)
- **CVE Details:** [CVE-2023-28461](https://www.cvedetails.com/cve/CVE-2023-28461/); [CVE-2025-66644](https://www.cvedetails.com/cve/CVE-2025-66644/)
- **CVEfeed:** [CVE-2025-66644 Array Networks ArrayOS AG OS Command Injection Vulnerability](https://cvefeed.io/vuln/detail/CVE-2025-66644)
- **NVD:** CVSS scoring and CWE classification for both CVEs ([CVE-2023-28461](https://nvd.nist.gov/vuln/detail/CVE-2023-28461), [CVE-2025-66644](https://nvd.nist.gov/vuln/detail/CVE-2025-66644))
- **FIRST.org EPSS:** [Exploit Prediction Scoring System data](https://api.first.org/data/v1/epss)
