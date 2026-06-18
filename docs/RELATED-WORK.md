# Related Work

This section positions the Edge Security Ground Truth repository relative to existing academic research, industry measurement frameworks, and comparable datasets. It is structured as a literature review suitable for a security conference paper, with citations in \[Author Year\] or \[Organization Year\] format.

---

## 1. Vulnerability Measurement Frameworks

### 1.1 CVSS and Its Limitations

The Common Vulnerability Scoring System (CVSS) has been the dominant vulnerability severity metric since its introduction by NIST and FIRST. However, its limitations are well-documented. [Frei et al. 2006] performed a large-scale analysis of over 80,000 security advisories and found that CVSS base scores, being static and context-free, poorly predict actual exploitation timing or likelihood. [Spring et al. 2021] formalized these criticisms in the Stakeholder-Specific Vulnerability Categorization (SSVC) framework, arguing that CVSS conflates severity with risk and that a single numeric score cannot serve the divergent needs of vendors, coordinators, and deployers.

Empirical studies reinforce these concerns. [Allodi and Massacci 2014] demonstrated that CVSS scores are poor discriminators of which vulnerabilities will actually be exploited, finding that "High" and "Critical" CVSS scores are assigned to the vast majority of CVEs while only ~2% are ever exploited in the wild. [Spring et al. 2023] (CVSS scoring inconsistency study, IEEE S&P) surveyed 196 CVSS users and found significant inter-rater disagreement on identical vulnerabilities, confirming that the system's apparent precision is illusory. [Dong et al. 2019] found that 35--82% of vendor advisories lack a CVSS score entirely, a finding corroborated by [Anwar et al. 2020] ("Cleaning the NVD," arXiv:2006.15074), who documented pervasive inconsistencies in NVD data including missing scores, incorrect vendor/product mappings, and inaccurate publication dates.

CVSS 4.0, released in 2023, attempted to address some criticisms by adding supplemental metrics and refining the base score formula, but early analyses suggest it shifts more vulnerabilities into the "Critical" bucket rather than improving discrimination [FIRST 2023]. This repository deliberately avoids CVSS as a primary metric, consistent with the consensus that severity scores alone cannot prioritize remediation.

### 1.2 EPSS: Exploit Prediction Scoring System

The Exploit Prediction Scoring System (EPSS) represents a fundamentally different approach: rather than scoring severity, it estimates the *probability* that a CVE will be exploited in the wild within 30 days. The foundational work is [Jacobs et al. 2021] ("Improving Vulnerability Remediation Through Better Exploit Prediction," ACM Digital Threats: Research and Practice), which described "the first open, data-driven framework for assessing vulnerability threat" using gradient-boosted decision trees trained on CVE characteristics, threat intelligence feeds, and temporal features. The original model achieved ROC AUC of 0.838.

EPSS v3, deployed in March 2023, expanded the feature set and improved performance by 82% over v2 in identifying likely-exploited vulnerabilities [FIRST 2023]. [Jacobs et al. 2023] (WEIS) further enhanced the model with community-driven exploit intelligence signals. However, EPSS has structural limitations relevant to this repository: it is CVE-only (silently-patched or un-CVE'd vulnerabilities are invisible), it can lag exploitation of novel edge-device attack surfaces that lack historical training data, and its 30-day prediction window may be too narrow for vulnerabilities that are stockpiled by nation-state actors before mass exploitation.

This repository uses EPSS as a supporting enrichment signal (via `enrich_epss.py`) rather than a gating filter, precisely because of these limitations.

### 1.3 CISA KEV: Known Exploited Vulnerabilities Catalog

The CISA Known Exploited Vulnerabilities (KEV) catalog, launched in November 2021 under Binding Operational Directive 22-01, is the authoritative U.S. government list of CVEs confirmed exploited in the wild [CISA 2021]. Unlike CVSS (which scores hypothetical severity) or EPSS (which predicts future exploitation probability), KEV is a *retrospective* confirmation: a CVE appears only after CISA has evidence of active exploitation.

[Beardsley 2025] (KEVology, runZero) -- authored by the former CISA Section Chief responsible for the KEV -- provided the most comprehensive public analysis of the catalog's operational characteristics, finding that no single enrichment signal (CVSS, EPSS, SSVC, exploit tooling, ATT&CK mappings) is sufficient alone, and that time-based relationships between CVE publication, exploit availability, and KEV addition are highly variable. The companion KEV Collider tool open-sourced the enrichment dataset.

KEV's principal limitation is coverage. [VulnCheck 2026] found that only 23.7% of vulnerabilities with observed exploitation evidence appear in CISA KEV, meaning the catalog systematically understates the exploited-vulnerability population. This undercounting is particularly acute for edge devices where exploitation may be observed by commercial threat intelligence firms before CISA confirms it. Despite this, KEV remains the highest-confidence public exploitation signal, which is why this repository uses it as the gating filter: a CVE must be KEV-listed to enter our count.

### 1.4 SSVC: Stakeholder-Specific Vulnerability Categorization

[Spring et al. 2021] (Carnegie Mellon SEI / CISA) proposed SSVC as a decision-tree alternative to numeric scoring, producing qualitative priority labels (Track, Track\*, Attend, Act) tailored to specific stakeholder roles. CISA adopted SSVC for its own prioritization workflow and recommends it for federal agencies [CISA 2022]. SSVC's key insight -- that different stakeholders (vendors, coordinators, deployers) need different decision inputs -- is directly relevant to this repository's refusal to produce a single vendor "score." A deployer choosing between Fortinet and Palo Alto needs different facts than a coordinator triaging disclosures; collapsing them into one number serves neither.

---

## 2. Edge Device Security Research

### 2.1 Industry Threat Reports

The shift of attacker focus toward network edge devices is one of the most documented trends in contemporary threat intelligence.

**Mandiant / GTIG M-Trends.** [Mandiant 2025] (M-Trends 2025) reported that exploits were the most common initial infection vector for the fifth consecutive year (33% of all intrusions), and that the four most frequently exploited vulnerabilities in 2024 were all in edge devices (VPNs, firewalls, routers). The average time-to-exploit shrank to five days, down from 32 days in prior years. Critically, 44% of zero-days in 2024 targeted enterprise security and networking platforms.

**Google GTIG Zero-Day Reviews.** [GTIG 2025] ("Hello 0-Days, My Old Friend: A 2024 Zero-Day Exploitation Analysis") tracked 75 zero-days exploited in 2024, with 20 targeting security and network appliances specifically. Enterprise technologies accounted for 44% of all zero-days, up from 37% in 2023. The 2025 follow-up [GTIG 2026] ("Look What You Made Us Patch") found the enterprise proportion reached an all-time high of 48% (43 of 90 zero-days). PRC-attributed groups remained the most prolific state-sponsored zero-day users, with nearly 30% of espionage zero-days attributed to Chinese threat actors.

**Verizon DBIR.** [Verizon 2025] (2025 Data Breach Investigations Report) documented an eightfold increase in edge-device vulnerability exploitation, rising from 3% to 22% of all vulnerability-exploitation breaches in a single year. The median time between disclosure and mass exploitation for critical edge-device vulnerabilities was *zero days*. Only 54% of vulnerable edge devices were fully remediated during the observation period, with a median time-to-remediate of 32 days.

**VulnCheck.** [VulnCheck 2026] ("2026 State of Exploitation: Exploiting the Network Edge") examined 181 exploited network edge device vulnerabilities from 2025, finding that 42.5% affected end-of-life devices and that 65% of botnet-exploited vulnerabilities targeted EOL products. Consumer routers and globally distributed networking products accounted for 56% of exploited edge vulnerabilities. Separately, [VulnCheck 2026b] (State of Exploitation 2026) found that 28.96% of newly exploited vulnerabilities in 2025 were exploited on or before the day their CVE was published, up from 23.6% in 2024.

**Coalition Cyber Insurance.** [Coalition 2024] provided actuarial evidence of edge-device risk: policyholders with internet-exposed Cisco ASA devices were 5.1x more likely to file a cyber insurance claim, and FortiOS SSL VPN users were 2.8x more likely. This is among the few datasets that quantify edge-device risk in dollar terms rather than CVE counts.

**Trend Micro.** [Trend Micro 2026] ("Edge Under Siege") synthesized publicly available vulnerability trend data with leaked operational data to explain the economic drivers of edge exploitation, estimating that edge-device exploits cost $30,000--$100,000 on the exploit market -- one-third to one-tenth the cost of browser or mobile exploits -- while enabling broader network access. The report documented coordination among state-sponsored actors (UNC5221, Salt Typhoon, Volt Typhoon) who share tooling and divide targets.

### 2.2 Government Guidance

The Five Eyes intelligence alliance (CISA, NCSC-UK, ASD ACSC, CCCS, NCSC-NZ) published joint edge-device security guidance in February 2025, comprising four documents: "Security Considerations for Edge Devices" (CCCS), "Digital Forensics Monitoring Specifications" (NCSC-UK), and executive and practitioner mitigation strategies (ASD ACSC) [Five Eyes 2025]. The guidance explicitly acknowledges that edge devices cannot run EDR agents, offer limited logging by default, and require downtime to patch -- structural properties that this repository's data reflects in the recurring pattern of pre-patch exploitation across all thirteen vendors.

### 2.3 Academic Research on Edge/Perimeter Security

Academic treatment of edge-device security as a distinct research domain remains sparse relative to its operational importance. [Frei et al. 2006] ("Large-Scale Vulnerability Analysis," SIGCOMM Workshop on Large-Scale Attack Defense) analyzed 80,000+ advisories and found that exploit availability outpaces patch availability -- a finding that has only intensified for edge devices, where Mandiant's 2024 average time-to-exploit went negative. [Lyu et al. 2024] (arXiv:2512.15803, "An Empirical Analysis of Zero-Day Vulnerabilities Disclosed by the Zero Day Initiative") examined severity distributions and vendor response patterns for zero-days, though without specific edge-device scoping.

The closest academic work to this repository's scope is [Iannone et al. 2024] ("Early and Realistic Exploitability Prediction of Just-Disclosed Software Vulnerabilities," ACM TOSEM), which evaluated 72 prediction models using only information available at CVE disclosure time. Their finding that initial CVE descriptions and linked discussions are weak predictors of exploitability underscores why retrospective exploitation data (KEV) is more reliable than predictive scores for the threat-model decisions this repository supports.

---

## 3. Exploitation Prediction and Timing

### 3.1 Exploit Lifecycle Models

The vulnerability lifecycle -- from discovery through disclosure, patch release, exploit development, and mass exploitation -- has been modeled by several research groups. [Frei et al. 2006] established the empirical baseline: at disclosure, exploit availability jumps from below 20% to over 70%, and 95% of exploits are available within a month. [Arora et al. 2008] ("Optimal Policy for Software Vulnerability Disclosure," Management Science) formalized the disclosure timing problem game-theoretically, modeling the interaction between a social planner setting disclosure policy and a vendor deciding patch speed and quality.

[Suciu et al. 2022] ("Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits," USENIX Security '22) proposed Expected Exploitability (EE), a temporal metric that reflects the evolving likelihood of functional exploit development over time. Their key finding -- that technical features extracted at disclosure are poor predictors, and that post-disclosure artifacts (write-ups, PoCs) are far more informative -- is consistent with this repository's decision to rely on confirmed exploitation (KEV) rather than predictive scores.

### 3.2 Time-to-Exploit Acceleration

The most consequential recent finding is the collapse of the defender's patch window. [Mandiant 2025] reported the 2024 average time-to-exploit was five days from disclosure; for the top four exploited vulnerabilities (all edge devices), three were zero-days exploited before any patch existed. This repository's per-vendor analysis corroborates the finding: across the thirteen vendors, multiple CVEs (Fortinet CVE-2022-42475, Ivanti CVE-2023-46805/CVE-2024-21887, Palo Alto CVE-2024-3400, Citrix CVE-2023-3519) were exploited days to weeks before patches were available.

[VulnCheck 2026b] quantified this at scale: 28.96% of KEVs in 2025 were exploited on or before CVE publication day, up from 23.6% in 2024 -- an accelerating trend that renders calendar-based patch cycles structurally inadequate for edge devices.

The arXiv paper cited by this repository ([arXiv:2405.01289]) provides academic corroboration of Mandiant's time-to-exploit findings, analyzing exploitation timing distributions and confirming that edge/security appliances experience significantly faster exploitation than other technology categories.

### 3.3 Predictive Models

Beyond EPSS, several academic efforts have attempted to predict exploitation. [Bullough et al. 2017] ("Predicting Exploitation of Disclosed Software Vulnerabilities Using Open-Source Data," arXiv:1707.08015) used Exploit-DB as ground truth for training classifiers. [Jacobs et al. 2023] (WEIS) extended EPSS with community-driven signals. [Iannone et al. 2024] evaluated 72 models using only disclosure-time features and found that even the best achieved limited reliability, concluding that "early prediction remains an open challenge." These findings collectively justify this repository's design choice: rather than predicting which CVEs *will* be exploited, we count which ones *were*, using KEV as the authoritative signal.

---

## 4. Vendor Disclosure Economics

### 4.1 The Economics of Disclosure

The economics of vulnerability disclosure have been studied formally since [Arora et al. 2008], who showed that disclosure policy (the protected period before public release) indirectly affects patch speed and quality through vendor incentives. [ENISA 2018] (RAND Europe, "Economics of Vulnerability Disclosure") identified four actor groups (users, vendors, finders, coordinators) with divergent incentives, explaining why economically rational vendor behavior can produce outcomes harmful to defenders -- such as delayed patches or bundled fixes that obscure individual vulnerabilities.

[Bouwman et al. 2023] ("No One Drinks from the Firehose," IEEE S&P) studied how organizations filter and prioritize vulnerability information, finding that the volume of disclosures exceeds organizational processing capacity -- a structural problem that silent patching and advisory ambiguity exacerbate.

### 4.2 Silent Patching and Advisory Manipulation

This repository documents two confirmed instances of silent patching among the thirteen vendors:

- **Fortinet** (CVE-2023-27997, "XORtigate"): firmware was released 3--4 days before the advisory; researchers discovered the fix by diffing firmware binaries ([watchTowr 2023], [Tenable 2023]).
- **Zyxel** (CVE-2022-30525): firmware was released without a CVE or advisory; the vulnerability was discovered by Rapid7 only after diffing the update ([Rapid7 2022]).

Silent patching creates an information asymmetry that disadvantages defenders who rely on advisories for patch prioritization. Attackers, who monitor firmware diffs and commit logs, can detect the fix and reverse-engineer the vulnerability before defenders are informed. [Frei et al. 2008] ("0-Day Patch: Exposing Vendors' (In)security Performance," Black Hat Europe) documented this dynamic empirically, showing that the "speed of insecurity exceeds the speed of security."

The opposite extreme -- radical transparency -- is exemplified by Sophos' "Pacific Rim" disclosure [Sophos 2024], a five-year timeline of China-nexus campaigns against Sophos firewalls that drew attention to the vendor's own historical defects. [Sophos 2026] ("The High Cost of Low Trust") reported that only 5% of organizations fully trust their cybersecurity vendors, and identified bug bounty programs, transparent advisories, and incident communication as the primary trust drivers. This repository's per-vendor "supporting signals" (silent-patch history, vendor-side breaches, transparency posture) are designed to make these disclosure-economics differences visible without collapsing them into a single score.

### 4.3 The Popularity Tax (Installed-Base Confounding)

A persistent challenge in vulnerability comparison is that vendors with larger installed bases attract more researcher attention, more attacker investment, and consequently more CVE filings -- a phenomenon this repository terms the "popularity tax." This is not merely a statistical nuisance; it is a first-order confounder. Fortinet's ~50% unit market share in the firewall segment [Gartner 2024] means it receives disproportionate scrutiny relative to, say, Check Point, whose lower KEV count (2 vs. 18) partly reflects lower researcher attention rather than demonstrably superior code.

Per-install normalization would correct this, but as [Rescorla 2005] ("Is Finding Security Holes a Good Idea?," IEEE S&P) argued, even with perfect installation counts, the relationship between installed base and vulnerability discovery is nonlinear and confounded by product complexity, deployment context, and disclosure culture. Vendor-reported install-base figures conflate unit count, revenue share, and managed-service seats, making reliable normalization infeasible. This repository therefore publishes no normalized score and explicitly identifies installed-base confounding as its most important limitation -- a stance consistent with [Ozment and Schechter 2006] ("Milk or Wine: Does Software Security Improve with Age?," USENIX Security), who found that even longitudinal vulnerability trends within a single product are difficult to interpret without controlling for codebase size and audit intensity.

---

## 5. Comparable Datasets and Tools

### 5.1 CISA KEV Catalog (Raw Data)

The primary data source is the CISA KEV catalog itself [CISA 2021], maintained as a public JSON feed. The `cisagov/kev-data` GitHub repository mirrors the feed. Several projects consume this data:

- **KEVology / KEV Collider** [runZero 2025]: enriches KEV entries with CVSS, EPSS, SSVC, exploit tooling, and ATT&CK mappings; provides an interactive explorer. KEVology is the closest existing analysis to this repository in ambition, but it covers the full KEV catalog without edge-device scoping or per-vendor deep-dive analysis.
- **Kaggle KEV datasets** [various]: multiple researchers have published enriched KEV datasets on Kaggle, combining KEV data with CVSS and EPSS metrics for machine learning research.

### 5.2 VulnCheck KEV

[VulnCheck 2023] launched a parallel Known Exploited Vulnerabilities catalog that tracks approximately 80% more exploited CVEs than CISA KEV, with an average 27-day lead time. VulnCheck KEV is commercially maintained and includes exploit proof-of-concept links. This repository uses CISA KEV rather than VulnCheck KEV as its gating filter because CISA KEV is freely available, government-maintained, and represents a higher confirmation bar (reducing false positives at the cost of undercounting).

### 5.3 AttackerKB

Rapid7's AttackerKB platform provides community-driven assessments of vulnerability exploitability and attacker value. Unlike KEV (binary: exploited or not) or EPSS (probability score), AttackerKB captures qualitative analyst judgment about ease of exploitation and strategic value. It is a useful complementary signal but lacks the reproducibility and scope consistency this repository requires.

### 5.4 Exploit-DB

The Exploit Database (Exploit-DB), maintained by OffSec, is the largest public archive of proof-of-concept exploit code. It is widely used in academic research as ground truth for exploit availability ([Bullough et al. 2017], [Jacobs et al. 2021]). The presence of an Exploit-DB entry for a CVE is a weaker signal than KEV listing (a PoC existing does not mean exploitation occurred in the wild), but it is a useful enrichment dimension that this repository's future EPSS integration may incorporate.

### 5.5 Google Project Zero 0-Day Tracking

Google Project Zero maintains a public spreadsheet of all known zero-day vulnerabilities exploited in the wild, updated in the annual GTIG zero-day reviews [GTIG 2025, GTIG 2026]. This dataset overlaps with CISA KEV but includes entries that CISA has not yet confirmed, and provides richer attribution data. It does not, however, offer vendor-scoped analysis or the reproducible count methodology this repository provides.

---

## 6. How This Repository Differs

This repository occupies a specific gap in the existing landscape:

| Existing Resource | What It Provides | What It Lacks |
|---|---|---|
| CISA KEV | Authoritative exploitation confirmation | No vendor scoping, no product-line filtering, no per-vendor analysis |
| EPSS | Predictive exploitation probability | CVE-only, can lag novel edge attacks, no retrospective confirmation |
| CVSS | Severity assessment | Poor exploitation discrimination, static, inconsistent scoring |
| SSVC | Stakeholder-tailored decision trees | Framework, not data; requires per-organization implementation |
| KEVology / KEV Collider | Rich KEV enrichment and exploration | Full-catalog scope, no edge-device filtering or vendor deep-dives |
| VulnCheck KEV | Broader exploitation coverage, faster | Commercial, higher false-positive tolerance, no vendor-scoped analysis |
| Mandiant M-Trends / GTIG | Threat landscape statistics | Aggregate reporting, not per-vendor reproducible datasets |
| AttackerKB | Qualitative exploitability assessment | Community-driven, not reproducible, no systematic vendor comparison |
| Exploit-DB | PoC exploit availability | Exploit existence != in-the-wild exploitation |

**This repository contributes:**

1. **Uniform edge-device scoping.** A single, documented include/exclude rule (firewall / SSL-VPN / remote-access gateway) applied identically to all thirteen vendors, with the rule itself published as executable code (`build_kev_counts.py`). No existing public dataset applies consistent product-line scoping across vendors.

2. **Reproducible counts from public data.** Every number in the repository is computable from the public CISA KEV feed plus the documented scope rule. The script, the feed URL, and the rule are all published; anyone can re-run and verify or modify the scope.

3. **Per-vendor qualitative signals without aggregation.** Rather than collapsing time-to-exploit, zero-day status, silent-patch history, and vendor-side breaches into a composite score, this repository presents them as individually-cited facts. This preserves the incommensurability that composite scores destroy: a pre-auth RCE zero-day and a vendor cloud breach are different kinds of risk, and which matters more depends on the deployer's threat model.

4. **Explicit treatment of installed-base confounding.** This repository identifies the "popularity tax" as its most important limitation and declines to fabricate a normalization that existing data cannot support -- a stance derived from the academic consensus ([Rescorla 2005], [Ozment and Schechter 2006]) that installed-base normalization is not reliably computable.

5. **Disclosure-economics visibility.** By documenting silent-patching events, vendor-side breaches, and transparency posture per vendor, this repository surfaces the disclosure-economics dynamics that [Arora et al. 2008] and [ENISA 2018] identified as critical but that raw CVE counts and exploitation catalogs obscure.

---

## References

### Academic Papers

- [Allodi and Massacci 2014] L. Allodi and F. Massacci. "Comparing Vulnerability Severity and Exploits Using Case-Control Studies." ACM Transactions on Information and System Security, 17(1), 2014.
- [Anwar et al. 2020] A. Anwar, A. Khormali, D. Nyang, and A. Mohaisen. "Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses." arXiv:2006.15074, 2020.
- [Arora et al. 2008] A. Arora, R. Telang, and H. Xu. "Optimal Policy for Software Vulnerability Disclosure." Management Science, 54(4):642--656, 2008.
- [Bouwman et al. 2023] X. Bouwman, S. de Smale, R. van Dijk, and M. van Eeten. "No One Drinks from the Firehose: How Organizations Filter and Prioritize Vulnerability Information." IEEE Symposium on Security and Privacy (SP), 2023.
- [Bullough et al. 2017] B. Bullough, A. Yanchenko, C. Smith, and J. Zipkin. "Predicting Exploitation of Disclosed Software Vulnerabilities Using Open-Source Data." arXiv:1707.08015, 2017.
- [Dong et al. 2019] Y. Dong, W. Guo, Y. Chen, et al. "Towards the Detection of Inconsistencies in Public Security Vulnerability Reports." USENIX Security Symposium, 2019.
- [Frei et al. 2006] S. Frei, M. May, U. Fiedler, and B. Plattner. "Large-Scale Vulnerability Analysis." Proceedings of the 2006 SIGCOMM Workshop on Large-Scale Attack Defense (LSAD), 2006.
- [Frei et al. 2008] S. Frei, D. Schatzmann, B. Plattner, and B. Trammell. "0-Day Patch: Exposing Vendors' (In)security Performance." Black Hat Europe, 2008.
- [Iannone et al. 2024] E. Iannone, G. Sellitto, E. Iaccarino, F. Ferrucci, A. De Lucia, and F. Palomba. "Early and Realistic Exploitability Prediction of Just-Disclosed Software Vulnerabilities: How Reliable Can It Be?" ACM Transactions on Software Engineering and Methodology (TOSEM), 2024.
- [Jacobs et al. 2021] J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, and I. Adjerid. "Exploit Prediction Scoring System (EPSS)." ACM Digital Threats: Research and Practice, 2(3), 2021.
- [Jacobs et al. 2023] J. Jacobs et al. "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights." Workshop on the Economics of Information Security (WEIS), 2023.
- [Ozment and Schechter 2006] A. Ozment and S. Schechter. "Milk or Wine: Does Software Security Improve with Age?" USENIX Security Symposium, 2006.
- [Rescorla 2005] E. Rescorla. "Is Finding Security Holes a Good Idea?" IEEE Security & Privacy, 3(1):14--19, 2005.
- [Spring et al. 2021] J. Spring, E. Hatleback, A. Householder, A. Manion, and D. Shick. "Prioritizing Vulnerability Response: A Stakeholder-Specific Vulnerability Categorization." Carnegie Mellon SEI Technical Report CMU/SEI-2021-SR-015, 2021.
- [Spring et al. 2023] J. Spring et al. "Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study on Evaluating Widespread Security Vulnerabilities." IEEE Symposium on Security and Privacy (SP), 2024. arXiv:2308.15259.
- [Suciu et al. 2022] O. Suciu, C. Nelson, Z. Lyu, T. Bao, and T. Dumitras. "Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits." USENIX Security Symposium, 2022.

### Industry Reports and Datasets

- [Beardsley 2025] T. Beardsley. "KEVology: An Analysis of CISA KEV Exploits, Scores, and Timelines." runZero Research, 2025. https://www.runzero.com/resources/kevology/
- [CISA 2021] Cybersecurity and Infrastructure Security Agency. "Known Exploited Vulnerabilities Catalog." Binding Operational Directive 22-01, November 2021. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- [CISA 2022] CISA. "Stakeholder-Specific Vulnerability Categorization (SSVC)." 2022. https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- [Coalition 2024] Coalition. "2024 Cyber Claims Report: The State of Active Insurance." 2024. https://www.coalitioninc.com/announcements/coalition-claims-report-2024
- [ENISA 2018] RAND Europe / ENISA. "Economics of Vulnerability Disclosure." European Union Agency for Cybersecurity, 2018. https://www.enisa.europa.eu/publications/economics-of-vulnerability-disclosure
- [FIRST 2023] Forum of Incident Response and Security Teams. "Exploit Prediction Scoring System (EPSS) v3." 2023. https://www.first.org/epss/
- [Five Eyes 2025] CISA, NCSC-UK, ASD ACSC, CCCS, NCSC-NZ. "Guidance and Strategies to Protect Network Edge Devices." February 2025. https://www.cisa.gov/resources-tools/resources/guidance-and-strategies-protect-network-edge-devices
- [GTIG 2025] Google Threat Intelligence Group. "Hello 0-Days, My Old Friend: A 2024 Zero-Day Exploitation Analysis." April 2025. https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends
- [GTIG 2026] Google Threat Intelligence Group. "Look What You Made Us Patch: 2025 Zero-Days in Review." 2026. https://cloud.google.com/blog/topics/threat-intelligence/2025-zero-day-review
- [Mandiant 2025] Mandiant / Google Cloud. "M-Trends 2025." April 2025. https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025
- [Rapid7 2022] Rapid7. "CVE-2022-30525 (Fixed): Zyxel Firewall Unauthenticated Remote Command Injection." May 2022. https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/
- [Sophos 2024] Sophos. "Pacific Rim: Inside the Counter-Offensive." October 2024. https://www.sophos.com/en-us/content/pacific-rim
- [Sophos 2026] Sophos. "The High Cost of Low Trust: Our Commitment to Radical Transparency." 2026. https://www.sophos.com/en-us/blog/the-high-cost-of-low-trust-our-commitment-to-radical-transparency
- [Trend Micro 2026] Trend Micro. "Edge Under Siege: How State-Sponsored Actors Exploit Your Perimeter." April 2026. https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/edge-under-siege-how-state-sponsored-actors-exploit-your-perimeter
- [Verizon 2025] Verizon. "2025 Data Breach Investigations Report." April 2025. https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf
- [VulnCheck 2023] VulnCheck. "VulnCheck Known Exploited Vulnerabilities (KEV) Catalog." 2023. https://www.vulncheck.com/kev
- [VulnCheck 2026] VulnCheck. "2026 State of Exploitation: Exploiting the Network Edge." 2026. https://www.vulncheck.com/blog/network-edge-device-report-2026
- [VulnCheck 2026b] VulnCheck. "VulnCheck State of Exploitation 2026." 2026. https://www.vulncheck.com/blog/state-of-exploitation-2026
- [watchTowr 2023] watchTowr Labs. "XORtigate, or CVE-2023-27997." June 2023. https://labs.watchtowr.com/xortigate-or-cve-2023-27997/
