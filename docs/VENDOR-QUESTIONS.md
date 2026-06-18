# 20 Questions to Ask Your Edge Vendor (Based on Data, Not Marketing)

A procurement and renewal checklist for CISOs, security architects, and procurement teams evaluating edge security vendors -- firewalls, SSL-VPNs, and remote-access gateways.

Every question below is grounded in a specific finding from this dataset: 107 CISA KEV-listed CVEs across 11 vendors, 2020--2026. No question is hypothetical. Each one maps to a documented failure mode that cost real organizations real money.

**How to use this document:** Bring these questions to your vendor evaluation, RFP, or contract renewal. The "Data Point" tells you why the question matters. The "Good Answer" tells you what an honest, mature vendor says. The "Red Flag" tells you what evasion sounds like.

---

## A. Vulnerability History (Based on KEV Data)

### A1. How many of your edge-product CVEs appear in CISA's Known Exploited Vulnerabilities catalog, and what is the year-over-year trend?

**Data Point:** Across 11 major edge vendors, KEV counts for edge-only products range from 2 (Check Point) to 18 (Fortinet) over six years. The overall dataset contains 107 exploited edge CVEs. KEV additions are not declining -- 2024 added 19, 2025 added 21 (TIME-TO-EXPLOIT.md, KEV Additions by Year table).

**Good Answer:** The vendor provides the exact number without prompting, breaks it down by product line and year, and explains the trend in context (e.g., "our 2024 count reflects increased researcher attention after our bug bounty expansion"). They distinguish edge-only products from their full portfolio.

**Red Flag:** The vendor does not know what CISA KEV is, conflates edge-product CVEs with total NVD CVEs, or claims "we have very few CVEs" without specifying the scope. Any vendor telling you they have zero KEV entries for an internet-facing product deployed at scale is either lying or irrelevant to the conversation.

---

### A2. What percentage of your KEV-listed edge CVEs were zero-days -- exploited before any patch was available?

**Data Point:** 36 of 107 edge CVEs (34%) in this dataset were exploited at or before public disclosure. 10 of 11 vendors have at least one confirmed zero-day. By vendor: Citrix 55%, Sophos 50%, Ivanti 46%, Fortinet 39%, Palo Alto 33%, Cisco 31%. Only Zyxel has zero confirmed zero-days (TIME-TO-EXPLOIT.md, Zero-Days by Vendor table).

**Good Answer:** The vendor acknowledges zero-day history with specifics: "Two of our seven KEV entries were exploited pre-patch. Here is what we changed in our development process afterward." They describe investments in variant analysis (finding siblings of reported bugs before attackers do).

**Red Flag:** "Our products have never been the subject of a zero-day." If the vendor is in this dataset, that is almost certainly false. Alternatively: "Zero-days are not our fault because there was no patch to apply" -- true but irrelevant to your risk; the question is what the vendor does to reduce zero-day likelihood and exposure duration.

---

### A3. How many of your exploited CVEs have been associated with ransomware campaigns?

**Data Point:** 46 of 107 edge CVEs (43%) are flagged by CISA as used in known ransomware campaigns. Fortinet leads with 12 ransomware-associated CVEs (67% of their KEV total). SonicWall has 6 (50%), driven by Akira and Fog ransomware targeting SonicOS CVE-2024-40766 (Arctic Wolf documented 30+ intrusions). CitrixBleed (CVE-2023-4966) was exploited by LockBit affiliates to breach Boeing, ICBC, DP World, and Allen & Overy (VENDOR-MATRIX.md, Ransomware Density table; TIME-TO-EXPLOIT.md, Ransomware Association section).

**Good Answer:** The vendor knows which of their CVEs appeared in ransomware campaigns, names them, and explains the downstream response (customer notification, IOC publication, coordination with law enforcement). They provide data on how quickly they issued patches for ransomware-targeted CVEs.

**Red Flag:** "Ransomware is a customer patching problem, not a vendor problem." While patching is ultimately the customer's responsibility, vendors whose products repeatedly serve as ransomware entry points should demonstrate they are investing in reducing the pre-auth attack surface that makes mass exploitation possible.

---

### A4. What is the severity distribution of your exploited CVEs? How many are pre-authentication?

**Data Point:** The dataset is dominated by high-severity, pre-auth bugs. All 6 Sophos KEV entries are CVSS 9.8 Critical and pre-authentication. 5 of 6 Zyxel KEV entries are CVSS 9.8 Critical. The top CWEs -- CWE-306 (Missing Auth for Critical Function, 7 CVEs across 4 vendors) and CWE-287 (Improper Authentication, 6 CVEs across 5 vendors) -- are by definition pre-auth or auth-bypass vulnerabilities (CWE-ANALYSIS.md, Top 10 CWEs table).

**Good Answer:** The vendor breaks down their KEV history by pre-auth vs. post-auth. They quantify how much of their internet-facing attack surface is reachable without authentication and describe how that surface has changed (shrunk) over time.

**Red Flag:** The vendor emphasizes average CVSS scores or focuses on low-severity CVEs to dilute the picture. Any vendor with a CISA KEV entry has, by definition, a CVE that was exploited in the wild -- the severity speaks for itself.

---

### A5. Has any nation-state actor been publicly attributed to exploiting your products?

**Data Point:** 22 distinct threat actors have been attributed to exploiting edge CVEs in this dataset. China-nexus actors dominate: UNC3886 (Fortinet + Juniper), UNC5221/UNC5337 (Ivanti), UTA0218 (Palo Alto), DriftingCloud/TA413 and the Pacific Rim cluster (Sophos). The ArcaneDoor actor (UAT4356/STORM-1849) targeted Cisco ASA/FTD. Iran-nexus actors exploited Check Point CVE-2024-24919. Only F5 has zero public actor attributions -- which does not mean absence of sophisticated exploitation, only absence of public naming (THREAT-ATTRIBUTION.md, Attribution Matrix).

**Good Answer:** The vendor acknowledges public attributions by name, describes their collaboration with government agencies (CISA, NSA, Five Eyes), and explains what architectural changes resulted from the campaigns. Sophos publishing the Pacific Rim five-year timeline is the transparency benchmark in this dataset.

**Red Flag:** "We cannot discuss threat intelligence" with no further detail. Public attributions are already public -- the vendor is not revealing classified information by acknowledging Mandiant or Volexity reports. Refusal to engage means the vendor has not internalized the lessons.

---

## B. Disclosure and Response Quality (Based on Vendor Behavior)

### B6. Have you ever silently patched a critical vulnerability -- shipped a fix without a CVE, advisory, or coordinated disclosure?

**Data Point:** Two vendors in this dataset have documented silent-patching episodes. Fortinet shipped a firmware update containing the fix for CVE-2023-27997 ("XORtigate," CVSS 9.8 pre-auth RCE in FortiOS SSL-VPN) 3--4 days before publishing any advisory; researchers at watchTowr discovered the fix by diffing the firmware. Zyxel silently patched CVE-2022-30525 (CVSS 9.8 unauthenticated OS command injection) on April 28, 2022 without a CVE, advisory, or researcher coordination -- Rapid7 discovered the patch two weeks later by diffing firmware (README.md, Fortinet and Zyxel sections; VENDOR-MATRIX.md, Silent Patch column).

**Good Answer:** "No, and here is our disclosure policy with SLAs." Or, if the vendor has a history: "Yes, in [year]. Here is what we changed -- we now commit to publishing advisories within N hours of any security fix shipping." The answer includes a verifiable policy URL.

**Red Flag:** Silence, evasion, or "we follow responsible disclosure practices" without specifics. Silent patching is not a minor process failure -- it leaves every customer who does not immediately update firmware running a known-vulnerable version with no awareness of the risk. A vendor who has done it once and not publicly committed to stopping will do it again.

---

### B7. What is your mean time from internal discovery (or researcher report) to public advisory?

**Data Point:** The fastest vendor response in this dataset is Check Point: CVE-2024-24919 received a same-day advisory, though initial scope framing lagged external researcher confirmation of mass exploitation. The worst cases involve weeks of delay: Citrix CVE-2019-19781 sat with mitigation-only guidance (no patch) for weeks while exploitation expanded to tens of thousands of devices. Ivanti CVE-2023-46805 + CVE-2024-21887 had no patch for weeks, ultimately triggering CISA Emergency Directive 24-01 ordering federal agencies to disconnect (README.md, Ivanti section).

**Good Answer:** The vendor provides a measurable SLA (e.g., "advisory within 48 hours of confirmed exploitability") and publishes historical data on advisory latency. They distinguish between "advisory published" and "patch available" -- these are different events with different timelines.

**Red Flag:** "We prioritize thoroughness over speed." Translation: they will sit on critical vulnerability details while customers are actively being compromised. Any edge vendor unable to commit to a 72-hour advisory SLA for critical pre-auth vulns is not operating at the speed of modern exploitation.

---

### B8. When you discover a vulnerability is being exploited in the wild, do you publish IOCs (indicators of compromise) alongside the patch?

**Data Point:** Cisco's response to the ArcaneDoor campaign (CVE-2024-20353 + CVE-2024-20359) included multi-agency coordinated disclosure with IOCs and detection signatures released alongside patches -- the strongest transparency response in the dataset. Sophos published an entire five-year campaign timeline (Pacific Rim) with detailed IOCs across multiple CVEs. By contrast, Fortinet's initial advisory for CVE-2024-21762 provided limited exploitation context despite CISA adding it to KEV the very next day (README.md, Cisco and Sophos sections).

**Good Answer:** "Yes. Every advisory for an actively-exploited CVE includes IOCs, YARA rules or Snort/Suricata signatures, and forensic guidance for checking whether the device was compromised before patching." The vendor cites specific recent examples.

**Red Flag:** "We provide IOCs to customers under NDA" or "IOCs are available through our threat intelligence subscription." If attackers already have the exploit, restricting IOCs to paying customers is a revenue decision, not a security decision. The adversary does not care about your NDA.

---

### B9. Do you run a public bug bounty program for your edge products, and what are the payout ranges?

**Data Point:** Multiple CVEs in this dataset were discovered by external researchers, not the vendor. CVE-2024-3400 (Palo Alto, CVSS 10.0) was discovered by Volexity already under active exploitation -- not by Palo Alto's internal teams. CVE-2022-30525 (Zyxel) was found by Rapid7 only after the vendor silently patched it. CVE-2023-27997 (Fortinet) was found by Lexfo/watchTowr. External researcher discovery of actively-exploited bugs is a signal that internal security testing missed critical attack surfaces (README.md, per-vendor sections).

**Good Answer:** The vendor names their bug bounty platform (HackerOne, Bugcrowd, etc.), provides payout ranges for edge-product RCEs (expect $10K--$100K+ for pre-auth RCE in a firewall), and shares metrics: number of valid submissions, average time to triage, percentage of critical findings versus internal discovery.

**Red Flag:** "We have a responsible disclosure policy" (a reporting address is not a bounty). Or: the bounty exists but the maximum payout for a pre-auth RCE in a firewall is under $5,000. At that price, the economics favor selling to a vulnerability broker, not reporting to the vendor.

---

### B10. How do you handle vulnerability disclosures for end-of-life products?

**Data Point:** VulnCheck's 2026 report found that 42.5% of exploited network-edge vulnerabilities in 2025 hit end-of-life devices. Sophos has 2 KEV entries (XG v17.x, CyberoamOS) affecting EOL products that will never be patched. Zyxel's SMB customer base -- smaller IT teams, slower upgrade cycles -- makes EOL exposure a structural risk multiplier. Juniper's ScreenOS CVE-2015-7755 (hardcoded backdoor) was in a platform long past its prime but still deployed (README.md, Sophos and Zyxel sections; VulnCheck citation in README.md).

**Good Answer:** The vendor specifies a clear EOL security policy: "We publish security advisories for EOL products for N years after EOL. We provide migration tooling and discounted upgrade paths. We notify customers of actively-exploited CVEs in EOL products even if no patch will be issued, so they can make informed risk decisions."

**Red Flag:** "EOL products are no longer supported. Please upgrade." Full stop, no further communication. This means if a zero-day hits an EOL product that is still deployed (and they are -- at scale), the vendor will not even tell customers they are exposed.

---

## C. Architecture and SDL (Based on CWE Patterns)

### C11. What percentage of your exploited edge CVEs are authentication bypasses or missing-authentication bugs?

**Data Point:** Authentication and access-control failures account for 30 of 107 exploited edge CVEs (28%) -- the single largest weakness category. The trend is worsening: auth bugs went from 12% of exploited CVEs (pre-2019) to 35% (2024+). Fortinet has 8 auth/access-control CVEs (44% of their KEV total). Juniper has 7 (88%). Palo Alto has 4 (33%). CWE-306 (Missing Authentication for Critical Function) alone accounts for 7 CVEs across 4 vendors -- meaning the management API was simply unprotected (CWE-ANALYSIS.md, Per-Vendor CWE Distribution table; CWE Evolution Over Time section).

**Good Answer:** The vendor provides the specific number and describes the architectural root cause. For example: "Three of our exploited CVEs were authentication bypasses. Root cause: our management plane had legacy API endpoints that predated our auth framework. We have completed a full auth-surface audit and every endpoint now requires authentication with no exceptions. Here are the test results."

**Red Flag:** "We take authentication seriously" without numbers. Or: "Those were edge cases in rarely-used features." CWE-288 (Auth Bypass via Alternate Path, 5 CVEs across 3 vendors) proves that "alternate paths" are not edge cases -- they are the exact paths attackers find. If the vendor cannot enumerate their unauthenticated attack surface, they have not measured it.

---

### C12. What programming languages are your edge appliance's SSL-VPN engine and management plane written in?

**Data Point:** Memory-safety bugs (buffer overflows, out-of-bounds writes) account for 22 of 107 exploited edge CVEs (21%), and the share is surging -- from 14% in 2020--2021 to 30% in 2024+. Cisco ASA, Citrix NetScaler, and Fortinet FortiOS each have 4+ memory-safety KEV entries in their C/C++ SSL-VPN and packet-parsing code. CISA's Secure-by-Design initiative specifically calls for adoption of memory-safe languages for these components (CWE-ANALYSIS.md, Memory-Safe Languages section; CWE Evolution Over Time table).

**Good Answer:** The vendor states the language and describes their migration plan: "Our SSL-VPN engine is written in C. We are rewriting the TLS parser in Rust, with completion targeted for [date]. Our management API is already in Go/Python/Java." They provide a roadmap with deliverables, not aspirations.

**Red Flag:** "Our code undergoes rigorous testing" (does not answer the question). Or: "Language choice does not determine security" (contradicted by the data -- memory-safety bugs are the fastest-growing category of exploited edge CVEs). A vendor with 4+ memory-safety KEV entries who has no memory-safe rewrite plan is telling you to expect more of the same.

---

### C13. How do you prevent OS command injection in your management interfaces?

**Data Point:** OS command injection (CWE-78) appears across 5 of 11 vendors: Ivanti, Palo Alto, SonicWall, Sophos, and Zyxel. This is functionally universal -- it happens when management interfaces shell out to system commands with attacker-controlled input instead of using safe APIs. Sophos has 4 injection CVEs (67% of their KEV total), all in the XG Firewall. SonicWall has 5 injection CVEs (42%), including 3 SQL injections in the SMA appliance line suggesting shared vulnerable database-interaction patterns (CWE-ANALYSIS.md, Universal CWEs section; Vendor-Specific Observations).

**Good Answer:** "We do not use shell calls for any operation reachable from the management plane. All system operations use language-native APIs. We enforce this through static analysis rules in our CI pipeline that block `system()`, `exec()`, and equivalent calls in any code path reachable from an HTTP handler. Here is our SAST configuration."

**Red Flag:** "We sanitize all user input." Input sanitization is the fallback when the architecture allows dangerous operations in the first place. The correct answer is architectural elimination of the command-injection vector, not filtering. Five vendors shipping OS command injection bugs in 2020--2025 proves that sanitization fails at scale.

---

### C14. What is your process for finding and eliminating vulnerability variants after a CVE is reported?

**Data Point:** Multiple vendors show recurring CVEs in the same component. Fortinet's `sslvpnd` has produced 4 separate KEV entries (CVE-2020-12812, CVE-2022-42475, CVE-2023-27997, CVE-2024-21762). Sophos has 3 CVEs (CVE-2020-12271, CVE-2022-1040, CVE-2022-3236) hitting the same User Portal/Webadmin surface -- a recurring architectural weakness. The CWE-ANALYSIS.md "Recurring Weakness Indicators" table identifies 10 vendor-category pairs with 3+ exploited CVEs in the same weakness class. These are not independent mistakes -- they are systemic SDL gaps (CWE-ANALYSIS.md, Recurring Weakness Indicators table).

**Good Answer:** "When we receive a CVE report, we conduct variant analysis: we search the entire codebase for the same pattern, not just the specific instance. For CVE-[X], our variant scan found N additional instances that we fixed in the same release. We measure variant-analysis coverage and publish it in our annual SDL report."

**Red Flag:** "We fix the specific vulnerability reported and verify the fix." This means they patch the one hole the researcher found and leave the identical bug three functions over. Four separate pre-auth RCEs in the same Fortinet SSL-VPN daemon over four years is what happens when variant analysis is absent.

---

### C15. Has your edge product undergone independent architecture review by a third party, and are the results available under NDA?

**Data Point:** The CWE data reveals that certain vendors have deeply embedded architectural weaknesses: Fortinet's 8 auth-subsystem CVEs, Juniper's PHP-based J-Web management plane (exposed by CWE-473, PHP External Variable Modification -- 2 CVEs unique to Juniper), and the C/C++ foundation of every vendor's packet-processing and TLS engine. These are not bugs that fuzz testing finds -- they are design-level issues that require architecture review to identify. The Juniper ScreenOS backdoor (CVE-2015-7755, hardcoded credentials discovered years after deployment) demonstrates the stakes of unreviewed architecture (CWE-ANALYSIS.md, Vendor-Specific CWEs section; README.md, Juniper section).

**Good Answer:** "Yes. [Named third party] reviewed our management-plane auth architecture in [year]. The report is available under mutual NDA. We also submit to CISA's Secure-by-Design pledge and publish annual SDL metrics."

**Red Flag:** "Our internal security team conducts architecture reviews." Internal reviews found zero of the 36 zero-days in this dataset. Every zero-day was discovered by external researchers (Mandiant, Volexity, Rapid7, watchTowr, Lexfo) or by the attacker themselves. Internal review is necessary but obviously insufficient.

---

## D. Operational Risk (Based on TTE and Ransomware Data)

### D16. What is the median time-to-exploit for your product's CVEs, and how has it changed?

**Data Point:** The dataset-wide median TTE is 40 days, but this masks a dramatic acceleration. For CVEs published in 2024, median TTE across all vendors is 0 days -- exploitation is simultaneous with disclosure. For 2025, it is 3 days. Per-vendor medians range from 1 day (Check Point) to 550 days (Sophos), but these are distorted by legacy CVEs backdated when KEV launched in 2021. The operationally relevant metric: for CVEs published in 2024+, median TTE converges to 0--3 days across all vendors (TIME-TO-EXPLOIT.md, TTE Distribution; Median TTE by NVD Publication Year table).

**Good Answer:** The vendor provides per-year TTE data for their products, acknowledges the acceleration, and describes how their release engineering has adapted: "Our average time from internal fix to customer-available patch has decreased from N days to M days over the past 3 years. We support hotfix deployment without full firmware upgrade for critical fixes."

**Red Flag:** "We patch promptly." Without data, this is meaningless. Also: "TTE depends on the threat actors, not on us." While true that TTE reflects attacker behavior, the vendor controls how fast the patch is available and how easy it is to deploy. Fortinet requiring full firmware upgrades (with reboots) for every security fix is a vendor-controlled bottleneck.

---

### D17. How many of your CVEs have been weaponized by ransomware groups, and what did you do about it?

**Data Point:** 46 of 107 edge CVEs (43%) are CISA-flagged as ransomware-associated. SonicWall CVE-2024-40766 was mass-exploited by Akira and Fog ransomware -- Arctic Wolf documented 30+ intrusions. CitrixBleed (CVE-2023-4966) was used by LockBit affiliates in attacks on Boeing, ICBC, DP World, and Allen & Overy. Fortinet has 12 ransomware-associated CVEs, accounting for 26% of all ransomware-linked edge CVEs in the dataset (TIME-TO-EXPLOIT.md, Ransomware Association table; VENDOR-MATRIX.md).

**Good Answer:** The vendor provides the count, names the ransomware groups, and describes proactive measures: customer notification campaigns, IOC feeds, partnership with CISA/FBI for takedown operations, and engineering changes to reduce the pre-auth attack surface that ransomware operators target for initial access.

**Red Flag:** "Ransomware is a customer responsibility." Technically true, ethically bankrupt. When your product is the initial-access vector in 30+ documented intrusions by the same ransomware group (SonicWall/Akira), the vendor bears responsibility for the architectural conditions that enabled it.

---

### D18. Has your company's own infrastructure ever been compromised in an incident related to your edge products?

**Data Point:** SonicWall is the only vendor in this dataset with a documented breach of its own infrastructure related to edge products. The September 2025 MySonicWall cloud-backup breach exposed firewall configuration backups (encrypted credentials, VPN configurations, network topology) for cloud-backup customers -- initially stated as "<5%," later revised to all cloud-backup users -- attributed to a state-sponsored actor. This breach was directly linked to the Marquis Software ransomware attack affecting 74 U.S. banks (README.md, SonicWall section; VENDOR-MATRIX.md, Vendor Breach column).

**Good Answer:** "No, and here is our SOC2 Type II report covering our cloud management infrastructure. We separate customer configuration data from our corporate network. Our cloud services undergo annual penetration testing by [named firm]." Or, if the answer is yes: full transparency about scope, timeline, remediation, and architectural changes made.

**Red Flag:** "We cannot discuss security incidents." If the incident is already public (as SonicWall's is), refusing to discuss it signals the vendor has not learned from it. Also: "Our cloud services are not part of the edge product." If the cloud service manages firewall configurations, it is part of your attack surface -- the SonicWall breach proved this definitively.

---

### D19. Do you support emergency patching without a full firmware upgrade and reboot?

**Data Point:** When median TTE is 0--3 days for recent CVEs, any deployment friction is a security gap. Fortinet requires a full firmware upgrade (with device reboot) for every security fix. The F5 CVE-2022-1388 went from public PoC to mass exploitation in 2 days. The PAN-OS CVE-2024-0012 + CVE-2024-9474 chain reached exploitation within approximately 48 hours of a public PoC. A 4-hour maintenance window in a 48-hour exploitation timeline consumes 8% of your response budget on logistics alone (TIME-TO-EXPLOIT.md, Documented exploitation timelines; DEFENDER-PLAYBOOK.md, Patch Cadence section).

**Good Answer:** "Yes. For critical CVEs, we support hotfix packages that can be applied without rebooting the appliance. We also support virtual patching through our IPS engine as a same-day compensating control while the full patch is tested. We have delivered N hotfixes in the past 24 months."

**Red Flag:** "We recommend following our standard upgrade procedure." Translation: reboot the firewall during a zero-day campaign. Also: "Virtual patching through [separate product] provides interim protection" -- only useful if the customer already owns and has deployed that separate product.

---

### D20. What is your contractual commitment to security advisory SLAs, and what happens if you miss them?

**Data Point:** The gap between vendor advisory and customer action is the single most exploitable window in edge security. Citrix CVE-2019-19781 had mitigation-only guidance for weeks while exploitation expanded to tens of thousands of devices -- Citrix had no patch available. Ivanti CVE-2023-46805 + CVE-2024-21887 had no patch for weeks, severe enough to trigger CISA Emergency Directive 24-01 ordering federal agencies to disconnect their VPNs entirely -- an unprecedented step. Mandiant's 2024 average TTE went negative (exploited before the patch existed), and 44% of 2024 zero-days targeted security/edge appliances (README.md, Ivanti and Citrix sections; TIME-TO-EXPLOIT.md, Comparison to Mandiant TTE Benchmarks).

**Good Answer:** The vendor provides contractual SLAs in the support agreement: "Critical pre-auth CVEs: advisory within 48 hours, patch within 7 days, or documented compensating control within 24 hours if patch is delayed. We provide credits/remedies if we miss these SLAs. Our SLA compliance rate for the past 12 months is N%."

**Red Flag:** "Our SLAs cover uptime, not vulnerability response." This means the vendor has no contractual obligation to tell you about or fix security vulnerabilities in any specific timeframe. When the next pre-auth RCE drops and the vendor takes three weeks to ship a patch (as Citrix and Ivanti have done), you have no recourse. If the vendor will not put security response SLAs in writing, they are telling you everything you need to know about their priorities.

---

## Using This Document

### In an RFP Process

Include these questions verbatim as required response items. Weight the vendor's willingness to provide specific numbers (KEV count, zero-day count, TTE data) as heavily as the numbers themselves. A vendor who can produce this data quickly has internalized it; a vendor who cannot has not.

### In a Renewal Negotiation

Compare the vendor's answers against the data in this repository. If the vendor claims "2 KEV entries" and this dataset shows 12, the discrepancy is either a scope disagreement (which the vendor should explain) or a credibility problem. Use the data as a factual baseline, not an accusation.

### In an Architecture Review

Questions C11--C15 are designed for security architects evaluating the long-term defensibility of an edge platform. A vendor with 8 authentication-bypass CVEs (Fortinet) or 6 injection CVEs (Ivanti) has a systemic SDL problem in that area. This is not a one-time risk -- it predicts future CVEs in the same category.

### Across Vendors

No vendor in this dataset is dramatically safer than the others. Eleven vendors, 2--18 exploited edge CVEs each, all under active exploitation. The purpose of these questions is not to find a "safe" vendor -- it is to find a vendor whose response posture, transparency, and engineering trajectory give you the best chance of surviving the next zero-day.

---

## Source Data

All data points reference analyses in this repository, reproducible from the live CISA KEV catalog:

| Source | Document |
|--------|----------|
| KEV counts | [README.md](../README.md), [`kev_edge_counts.json`](../scripts/kev_edge_counts.json) |
| Vendor comparison | [VENDOR-MATRIX.md](VENDOR-MATRIX.md) |
| CWE patterns | [CWE-ANALYSIS.md](CWE-ANALYSIS.md) |
| Time-to-exploit | [TIME-TO-EXPLOIT.md](TIME-TO-EXPLOIT.md) |
| Threat attribution | [THREAT-ATTRIBUTION.md](THREAT-ATTRIBUTION.md) |
| Defender playbook | [DEFENDER-PLAYBOOK.md](DEFENDER-PLAYBOOK.md) |

---

*Dataset: 107 CISA KEV-listed CVEs, 11 edge vendors, 2020--2026. Last updated: 2026-06-18.*
