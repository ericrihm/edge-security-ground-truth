# What If You Had Chosen Differently? A Scenario Analysis of Edge Vendor Risk

Every edge security deployment starts with a procurement decision. You compare vendors, read analyst reports, check a few CVE counts, maybe get a demo. Then you sign a contract and live with that choice for 5-7 years.

This document takes the 115 CISA KEV-listed edge CVEs in this repository and asks: **what would your life have looked like** under five different decisions? Not in the abstract -- with specific dates, specific CVEs, and specific consequences.

The data is from [`kev_edge_enriched.json`](../scripts/kev_edge_enriched.json), [`TIME-TO-EXPLOIT.md`](./TIME-TO-EXPLOIT.md), [`CWE-ANALYSIS.md`](./CWE-ANALYSIS.md), and [`VENDOR-MATRIX.md`](./VENDOR-MATRIX.md). Every number is reproducible.

---

## Scenario 1: "What if you deployed Fortinet in 2020?"

You chose Fortinet. Reasonable decision -- largest market share (~50% unit share in enterprise firewalls), broad analyst coverage, competitive pricing, strong SD-WAN story. You deployed FortiGate appliances with SSL-VPN enabled for your remote workforce in early 2020.

Here is what happened to you, year by year.

### 2020: The Inheritance

You inherit three CVEs from the 2018-2019 era that are still being actively exploited:

- **CVE-2018-13379** (CVSS 9.1, path traversal in SSL-VPN). Published June 2019 but mass-exploited throughout 2020. Plaintext VPN credentials readable from the filesystem. If you deployed a FortiGate without checking the firmware version, you were exposed on day one. CISA adds it to KEV in November 2021 retroactively, but attackers had lists of compromised credentials circulating on dark web forums by late 2020.
- **CVE-2020-12812** (CVSS 9.8, improper authentication). An authentication bypass that let attackers log in without a valid password under specific conditions. Ransomware-associated.
- **CVE-2019-5591** (CVSS 6.5, missing authentication for critical function). A default configuration flaw where FortiOS accepted LDAP server identity without verification.

**Your experience:** Within months of deployment, you are patching legacy vulnerabilities that predate your purchase. If your team runs a vulnerability scan in mid-2020, three critical findings appear against brand-new hardware running non-current firmware.

### 2021: The Backfill Wave

CISA launches the KEV catalog in November 2021. Four Fortinet CVEs are added:

- The three 2018-2019 CVEs above are formally cataloged.
- **CVE-2021-44168** (FortiOS arbitrary file download). KEV-listed December 10, 2021 -- 25 days *before* NVD publishes the CVE on January 4, 2022. This is the earliest negative-TTE in the entire dataset.

**Your experience:** Your team now has a formal federal mandate to patch. If you are a federal contractor or follow CISA guidance, you are in remediation mode for the holidays.

### 2022: The Year of the Auth Bypass

Three major new CVEs hit, plus two more legacy entries:

- **CVE-2022-40684** (CVSS 9.8, authentication bypass). Published October 18, but CISA added it to KEV on October 11 -- seven days *before* NVD publication. This is an authentication bypass via crafted HTTP requests to the administrative API. Mass-exploited within hours of public PoC. Ransomware-associated.
- **CVE-2022-42475** (CVSS 9.3, heap-based buffer overflow in SSL-VPN). KEV-listed December 13, 2022. NVD does not publish until January 2, 2023 -- 20 days later. This is a pre-auth RCE in the SSL-VPN daemon exploited by UNC3886 (China-nexus). Ransomware-associated.
- Legacy entries: CVE-2018-13382 and CVE-2018-13383 are added to KEV in January 2022. CVE-2018-13374 follows in September.

**Your experience:** Two emergency patch cycles in three months (October and December). CVE-2022-40684 is a "drop everything" event -- unauthenticated admin access to your firewall. CVE-2022-42475 arrives just before the December holidays. Your SOC is working Christmas week.

### 2023: XORtigate and the Silent Patch

- **CVE-2023-27997** (CVSS 9.2, heap buffer overflow -- "XORtigate"). Fortinet ships a fixed firmware build 3-4 days *before* publishing any advisory. Researchers at watchTowr and Lexfo reproduce the vulnerability by diffing the firmware update. If you patched promptly from the firmware release, you were protected. If you waited for the advisory to understand what you were patching, you were exposed for those 3-4 days while an exploit was being reverse-engineered from the diff. Ransomware-associated.
- **CVE-2022-41328** (CVSS 6.5, path traversal). KEV-listed March 2023.

**Your experience:** The silent-patch episode is uniquely corrosive to trust. Your change management process requires understanding what a patch fixes before deploying it. Fortinet shipped the fix without telling you what it fixed. You are now in a position where "wait for the advisory" is a vulnerability, but "deploy uncharacterized firmware updates immediately" violates every change control policy you have.

### 2024: Zero-Day RCE

- **CVE-2024-21762** (CVSS 9.6, out-of-bounds write in SSL-VPN). CISA adds it to KEV the same day as NVD publication (February 9, 2024). Pre-auth RCE in the SSL-VPN. Exploitation was already active when the advisory dropped. Ransomware-associated.
- **CVE-2024-23113** (CVSS 9.8, format string vulnerability in fgfmd daemon). Published February 2024, KEV-listed October 2024.

**Your experience:** February 2024 is another emergency. CVE-2024-21762 is a zero-day -- attackers had it before you had a patch. If you followed Fortinet advisories, you found out and patched on February 9. If your patch cycle is monthly, you were exposed for up to three weeks after the advisory.

### 2025: The Auth Bypass Chain

- **CVE-2024-55591** (CVSS 9.6, auth bypass via alternate path). KEV same-day as NVD publication (January 14, 2025). Arctic Wolf documented exploitation by a ransomware operator who had the exploit approximately two weeks before Fortinet's advisory. Ransomware-associated.
- **CVE-2025-24472** (CVSS 8.1, another auth bypass via alternate path). Published February 2025, KEV March 2025. Same CWE (CWE-288) as CVE-2024-55591. Ransomware-associated.
- **CVE-2019-6693** (CVSS 6.5, hardcoded cryptographic key). A 2019 vulnerability added to KEV in June 2025. Ransomware-associated.
- **CVE-2025-59718** (CVSS 9.1, improper verification of cryptographic signature). KEV December 2025.

**Your experience:** January 2025 is the third January in a row with an emergency Fortinet patch. The CWE-288 pattern (auth bypass via alternate path) is now a recurring motif -- CVE-2024-55591, CVE-2025-24472, and the upcoming CVE-2026-24858 all share it. Your security team starts asking whether FortiOS has a systemic auth architecture problem.

### 2026: FortiBleed and the Pattern Crystallizes

- **CVE-2026-24858** (CVSS 9.4, auth bypass via FortiCloud SSO). KEV same-day (January 27, 2026). Arctic Wolf reported exploitation starting January 15 -- twelve days before Fortinet's advisory. The third CWE-288 in thirteen months.

**Your experience:** Six years in. You have weathered 18 CISA KEV entries, 7 confirmed zero-days, and 12 ransomware-associated vulnerabilities. You have been in emergency patch mode roughly **every 4 months** on average. Three of your CVEs were exploited before any patch existed. One was silently patched. Coalition has publicly documented 14 zero-day advisories for critical Fortinet flaws in under four years.

### The Fortinet Ledger

| Metric | Value |
|--------|------:|
| Total KEV CVEs (2020-2026) | 18 |
| Confirmed zero-days | 7 |
| Ransomware-associated | 12 |
| Auth/access-control failures | 8 (44%) |
| Emergency patch events | ~18 (one per CVE at minimum) |
| Average interval between KEV additions | ~4 months |
| Silent-patch episodes | 1 documented |

---

## Scenario 2: "What if you chose the vendor with the fewest CVEs?"

Your CISO says: "Pick the vendor with the cleanest track record." You pull CISA KEV numbers and see Check Point has **2 entries** against 115 total. Fortinet has 18. The choice seems obvious.

You deploy Check Point Quantum Security Gateways.

### What the number hides

Both of Check Point's CVEs are zero-days. That is a **100% zero-day rate** -- the highest of any vendor in the dataset.

**CVE-2024-24919** (CVSS 8.6, path traversal in SSL VPN / Mobile Access portal). Researchers at mnemonic.io confirmed exploitation by nation-state actors (Iran-nexus campaigns) *before* Check Point published its advisory. Over 10,000 devices were scanned within 48 hours of the PoC becoming public. The attackers were not script kiddies -- they were extracting password hashes and Active Directory credentials from the appliance filesystem. CISA confirmed ransomware association.

**CVE-2026-50751** (CVSS 9.3, improper authentication). Added to KEV on the same day as NVD publication (June 8, 2026). A zero-day. Also ransomware-associated.

### The math that matters

| Vendor | KEV Count | Zero-Day Rate | Ransomware Rate |
|--------|----------:|--------------:|----------------:|
| Fortinet | 18 | 39% | 67% |
| **Check Point** | **2** | **100%** | **100%** |
| Citrix | 13 | 54% | 31% |
| Palo Alto | 12 | 33% | 42% |

Check Point's median TTE is **1 day**. The fastest in the entire dataset. When a Check Point vulnerability is exploited, it is exploited essentially immediately.

A low count can mean:
1. The product has fewer bugs (possible).
2. The product has fewer researchers looking at it (likely -- lower market share means less ROI for bug hunters).
3. The product has fewer *disclosed* bugs (unknown -- silent patching is undocumented for Check Point, but absence of evidence is not evidence of absence).
4. The product's bugs are higher-severity when they do surface (demonstrated -- both are zero-days, both are ransomware-linked, one involved nation-state operators).

**Your experience as a Check Point customer:** You had a quieter 2020-2023. Then in May 2024, nation-state actors extracted credentials from your VPN appliance using a zero-day you could not have patched because no patch existed yet. Your Active Directory credentials were compromised through your perimeter security device. In June 2026, it happened again.

Two incidents in six years versus eighteen for Fortinet. But both of yours were zero-days with no possible patch-based defense. The correct response to CVE-2024-24919 was not "patch faster" -- it was "assume breach, rotate all credentials extracted through the VPN, and hunt for lateral movement."

### The lesson

**Low CVE count is not low risk.** It is low *observed frequency*. The severity, exploitability, and defensibility of each individual CVE matters more than how many there are. Two undefendable zero-days may be worse than eighteen CVEs you could have patched if you were fast enough.

---

## Scenario 3: "What if you had a 30-day patch cycle?"

You have a mature vulnerability management program. You scan weekly, prioritize CISA KEV entries, and commit to deploying patches within 30 calendar days of vendor advisory. This puts you ahead of most organizations -- CISA's own BOD 22-01 allows 14 days for critical KEV entries, but many organizations take 60-90 days in practice.

How many of the 115 exploited edge CVEs would have been weaponized before your 30-day window closed?

### The answer: 49%

**56 of 115 CVEs** (48.7%) were added to CISA KEV within 30 days of NVD publication. This means exploitation was confirmed -- not theoretical, not "proof-of-concept available," but confirmed active exploitation in the wild -- before your 30-day patch cycle could complete.

The breakdown:

| TTE Bucket | CVEs | Cumulative % | Your 30-day patch covers? |
|------------|-----:|-------------:|:-------------------------:|
| Negative (exploited before disclosure) | 6 | 5.2% | No -- no patch exists yet |
| 0 days (same-day) | 35 | 35.7% | No -- patch just released |
| 1-7 days | 6 | 40.9% | No -- still in your review queue |
| 8-30 days | 9 | 48.7% | Maybe -- depends on timing |
| 31-90 days | 11 | 58.3% | Yes |
| 91-365 days | 10 | 67.0% | Yes |
| 365+ days | 38 | 100% | Yes |

### What "30 days" actually means in practice

Your 30-day clock starts when the vendor publishes an advisory. But:

1. **6 CVEs were exploited before any advisory existed.** Your clock has not started. You cannot patch what has not been disclosed. These include CVE-2022-42475 (Fortinet, exploited 20 days before NVD), CVE-2023-46805 and CVE-2024-21887 (Ivanti, exploited 2 days before NVD), and CVE-2025-40602 (SonicWall, 1 day before).

2. **35 CVEs were exploited on the same day as disclosure.** Your clock starts at t=0, but attackers already have working exploits. You need to discover the advisory, assess the impact, test the patch in a lab, schedule a maintenance window, deploy, and verify. Even an aggressive team cannot do this in zero days.

3. **6 CVEs were exploited within 1-7 days.** Your patch is in the approval pipeline. Your change advisory board meets next Tuesday. The attackers are already inside.

### Specific examples of what you would have missed

- **CVE-2024-3400** (Palo Alto, CVSS 10.0): Volexity discovered active exploitation approximately 19 days before any hotfix was available. With a 30-day cycle, you would have been exposed for the entire pre-patch period plus however long it took your team to deploy after the fix shipped.
- **CVE-2022-1388** (F5 BIG-IP, CVSS 9.8): Mass exploitation within 2 days of PoC publication. Your 30-day cycle leaves 28 days of unnecessary exposure.
- **CVE-2023-46805 + CVE-2024-21887** (Ivanti): CISA ED 24-01 ordered federal agencies to *disconnect* their Ivanti VPNs, not just patch them. The patch did not exist for weeks. Your 30-day cycle is irrelevant when the remediation is "turn it off."

### The uncomfortable conclusion

A 30-day patch cycle protects you against roughly **51% of exploited edge CVEs** -- the ones that sit in the long tail before being weaponized. It leaves you exposed to the 49% that are weaponized before you can act. For the most dangerous CVEs (zero-days, nation-state campaigns), a patch cycle of any length is insufficient because the vulnerability is exploited before the patch exists.

---

## Scenario 4: "What if you had a 7-day emergency patch process?"

You invest heavily. You build a rapid-response capability: 24/7 SOC monitoring for CISA KEV additions, pre-staged test environments for every edge vendor, pre-approved emergency change windows, and a commitment to deploy critical patches within 7 calendar days. This is elite-tier patch management -- very few organizations achieve this consistently.

### The answer: 41% still get through

**47 of 115 CVEs** (40.9%) were added to KEV within 7 days of disclosure. Your 7-day process catches 59% of exploited edge CVEs before the confirmed exploitation date, but 41% were already weaponized before your fastest possible response.

| TTE Bucket | CVEs | What happened |
|------------|-----:|---------------|
| Negative TTE | 6 | Exploited before disclosure. No patch existed during exploitation. |
| TTE = 0 | 35 | Exploited same day. Patch available but deployment takes time. |
| TTE 1-7 days | 6 | You might catch these -- if you started the moment the advisory dropped. |
| TTE 8+ days | 68 | Your 7-day process covers these. |

### The improvement is real but bounded

Compared to a 30-day cycle:

| Metric | 30-day cycle | 7-day cycle | Improvement |
|--------|:-----------:|:----------:|:-----------:|
| CVEs exploited before patch deployed | 56 (49%) | 47 (41%) | 9 fewer exposures |
| Zero-days (no patch to deploy) | 38 | 38 | No change |
| Same-day exploitation | 35 | 35 | No change |

The 7-day cycle saves you from **9 additional CVEs** that were exploited between days 8-30. That is meaningful -- it includes CVEs like CVE-2023-4966 (CitrixBleed, TTE=8 days, used by LockBit at Boeing and ICBC) and CVE-2022-1040 (Sophos, TTE=6 days, Pacific Rim campaign).

But it does not help with the 38 zero-days (exploited at or before disclosure) or the 35 same-day exploitations. Those require a different defense entirely: assume-breach posture, network segmentation, anomaly detection, and the ability to hunt for indicators of compromise rather than waiting for a patch.

### What the 7-day elite defenders actually do

The organizations that survive edge zero-days do not rely solely on patching speed. They:

1. **Restrict management-plane exposure.** Most edge zero-days target admin/VPN interfaces exposed to the internet. Restricting access to known IPs or VPN-only admin access eliminates the attack surface for many of these CVEs entirely.
2. **Deploy WAF/IPS virtual patches.** When a vendor advisory drops, a WAF signature can block exploit traffic within hours, buying time for the full patch cycle.
3. **Hunt proactively.** When CISA adds a CVE to KEV, they assume they are already compromised and look for indicators rather than just patching.
4. **Maintain break-glass disconnection authority.** CISA ED 24-01 (Ivanti) ordered disconnection, not patching. The ability to disconnect an edge appliance from the network within hours is a capability most organizations lack.

---

## Scenario 5: "What if you focused on CWE class instead of vendor?"

Every scenario above treats the vendor choice as the key decision. But what if the more predictive variable is not which vendor you chose, but which *weakness classes* you defend against?

### The data: CWE class concentrations

From the [CWE Analysis](./CWE-ANALYSIS.md), three weakness categories account for 72% of all 115 exploited edge CVEs:

| Category | CVEs | Share | Key CWEs |
|----------|-----:|------:|----------|
| Auth / Access Control | 31 | 27% | CWE-287, CWE-288, CWE-306, CWE-863, CWE-284 |
| Injection | 25 | 22% | CWE-78, CWE-89, CWE-94, CWE-77 |
| Memory Safety | 27 | 23% | CWE-120, CWE-121, CWE-122, CWE-787 |

These are not exotic zero-days in novel attack surfaces. They are the same bug classes OWASP warned about in 2003.

### Defense by CWE class

**If you blocked authentication bypasses (CWE-287, CWE-288, CWE-306):**

These three CWEs alone account for 24 of 115 CVEs (20.9%) across 9 of 13 vendors. Every vendor except Citrix, Sophos, Zyxel, and WatchGuard has at least one. Specific examples you would have stopped:

| CVE | Vendor | CVSS | What it did |
|-----|--------|-----:|-------------|
| CVE-2022-40684 | Fortinet | 9.8 | Unauthenticated admin access via crafted HTTP headers |
| CVE-2024-55591 | Fortinet | 9.6 | Auth bypass via Node.js websocket, ransomware entry |
| CVE-2026-24858 | Fortinet | 9.4 | FortiCloud SSO auth bypass, exploited 12 days pre-patch |
| CVE-2025-24472 | Fortinet | 8.1 | Auth bypass via alternate path, ransomware-associated |
| CVE-2024-0012 | Palo Alto | 9.3 | PAN-OS management auth bypass, chained with RCE |
| CVE-2025-0108 | Palo Alto | 8.8 | PAN-OS auth bypass, fast follow-on |
| CVE-2022-1388 | F5 | 9.8 | iControl REST unauthenticated access, mass-exploited in 2 days |
| CVE-2023-46747 | F5 | 9.8 | BIG-IP config utility auth bypass + RCE chain |
| CVE-2024-53704 | SonicWall | 8.2 | SSLVPN authentication bypass |
| CVE-2021-22893 | Ivanti | 10.0 | Pulse Connect Secure auth bypass, China-nexus |
| CVE-2026-50751 | Check Point | 9.3 | Quantum Gateway auth bypass, zero-day |

How would you "block authentication bypasses" without vendor cooperation? You cannot fix the code. But you can:

- **Never expose management interfaces to the internet.** CVE-2022-40684, CVE-2024-0012, CVE-2022-1388, CVE-2023-46747 all target admin APIs. If the admin interface is reachable only from a management VLAN with jump-box access, the attack surface disappears.
- **Enforce MFA on VPN portals.** CVE-2024-55591, CVE-2024-53704, CVE-2021-22893 bypass password-based auth. Hardware token MFA adds a layer the exploit cannot circumvent.
- **Monitor for auth anomalies.** Impossible logins (wrong GeoIP, impossible travel, service-account interactive use) are detectable even when the auth bypass succeeds.

**If you also blocked injection (CWE-78, CWE-89, CWE-94, CWE-77):**

Adding injection defenses covers another 25 CVEs (21.7%). These two categories combined eliminate **49% of the attack surface**. Key injection CVEs you would have stopped:

| CVE | Vendor | CVSS | What it did |
|-----|--------|-----:|-------------|
| CVE-2020-12271 | Sophos | 9.8 | SQL injection, Asnarok campaign, VPN credential theft |
| CVE-2023-3519 | Citrix | 9.8 | Code injection, zero-day, thousands of webshells |
| CVE-2019-11510 | Ivanti | 10.0 | Arbitrary file read leading to credential theft |
| CVE-2023-28771 | Zyxel | 9.8 | OS command injection, Mirai botnet mass exploitation |
| CVE-2021-20038 | SonicWall | 9.8 | Stack-based buffer overflow (injection adjacent) |

Injection defenses at the network level include WAF rules blocking common injection payloads, input length restrictions at the reverse proxy layer, and -- most critically -- ensuring that if an edge device is compromised via injection, the blast radius is contained through network segmentation.

### The cross-vendor pattern

Here is what makes CWE-based defense superior to vendor selection: **auth bypasses and injection appear in every vendor**.

| Vendor | Auth/Access CVEs | Injection CVEs | Combined | % of vendor total |
|--------|:----------------:|:--------------:|:--------:|:-----------------:|
| Fortinet | 8 | 0 | 8 | 44% |
| Juniper | 7 | 0 | 7 | 88% |
| Ivanti | 1 | 6 | 7 | 54% |
| SonicWall | 3 | 5 | 8 | 67% |
| Palo Alto | 4 | 2 | 6 | 50% |
| Sophos | 0 | 4 | 4 | 67% |
| Cisco | 2 | 2 | 4 | 31% |
| Citrix | 2 | 2 | 4 | 31% |
| F5 | 2 | 1 | 3 | 50% |
| Check Point | 1 | 0 | 1 | 50% |
| Zyxel | 0 | 2 | 2 | 33% |
| WatchGuard | 0 | 0 | 0 | 0% |
| Array Networks | 1 | 1 | 2 | 100% |

No matter which vendor you chose in 2020, auth bypass and injection defenses would have reduced your exploited-CVE exposure by 31-88%. **The weakness class is more predictive than the vendor brand.**

### Why this works

Vendor selection is a one-time decision made under uncertainty. You pick a vendor, and then you are locked in for years while their vulnerability profile unfolds in ways you cannot predict.

CWE-class defense is continuous and vendor-agnostic:
- Restricting management-plane access works against *every* auth bypass in *every* vendor.
- WAF/IPS injection signatures work against *every* command injection in *every* vendor.
- Network segmentation limits blast radius regardless of which specific CVE is exploited.
- MFA enforcement adds a layer that no single-vulnerability exploit can bypass.

These controls are under your control. The vendor's code quality is not.

---

## The Takeaway

Five scenarios, one conclusion: **the controllable variable is response speed and architectural defense, not brand.**

| Scenario | What you learned |
|----------|-----------------|
| Fortinet since 2020 | High-volume exposure: 18 KEVs, emergency patches every ~4 months, 7 zero-days, 1 silent patch. The largest vendor is also the most-targeted. |
| Pick lowest CVE count | Check Point's 2 CVEs are both zero-days (100%), both ransomware-linked. Low count hides high per-incident severity. |
| 30-day patch cycle | 49% of CVEs exploited before your patch deploys. A mature patching program still leaves you exposed to nearly half the threat. |
| 7-day emergency patches | 41% still exploited before day 7. Better, but zero-days and same-day exploitation defeat any patch-only strategy. |
| Defend by CWE class | Blocking auth bypass + injection eliminates 49% of the attack surface across *every* vendor. Architectural controls beat vendor selection. |

The edge is the most dangerous component in your network. Every vendor's edge products have been exploited in the wild. The question is not "which vendor is safe?" -- none of them are. The question is: "How fast can you respond, and have you built defenses that work even when the patch does not exist yet?"

**Invest in time-to-respond over brand selection. That is the only variable you control.**

---

*Data sources: CISA KEV catalog (2020-01-01 to 2026-06-18), NVD API 2.0, FIRST EPSS, per-vendor incident reports. All numbers reproducible from [`scripts/kev_edge_enriched.json`](../scripts/kev_edge_enriched.json). Dataset: 115 CVEs, 13 vendors. See [METHODOLOGY.md](../METHODOLOGY.md) for scope rules and limitations.*
