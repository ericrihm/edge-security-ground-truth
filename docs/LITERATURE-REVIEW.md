# Literature Review: Reproducible Exploitation Metrics for Edge and Perimeter Security Appliances

**Associated project:** Edge Security Ground Truth — reproducible CISA KEV counts for 11 edge/perimeter vendors (107 edge CVEs, 2020–2026).

---

## Abstract

The practice of using raw CVE counts to compare firewall and SSL-VPN vendors is widespread, poorly grounded empirically, and consequential: procurement decisions, insurance underwriting, and regulatory reporting all draw on vendor vulnerability tallies that conflate installation base, disclosure policy, researcher attention, and genuine security engineering quality. This review surveys the literature on vulnerability metrics and their limitations, the empirical research on exploitation timing, the structural properties that make network-edge appliances a distinct and disproportionately targeted attack surface, and the disclosure practices that complicate any cross-vendor comparison. It situates the Edge Security Ground Truth dataset as a methodological contribution: a publicly reproducible, scope-controlled, exploitation-gated dataset that makes the comparison assumptions explicit and editable rather than hidden.

---

## 1. Vulnerability Metrics and Their Limitations

### 1.1 The CVSS Scoring Problem

The Common Vulnerability Scoring System (CVSS), maintained by FIRST.org and now in its fourth major version, is the dominant universal metric for communicating vulnerability severity. It encodes attack vector, attack complexity, required privileges, user interaction, and three impact dimensions (confidentiality, integrity, availability) into a 0–10 score. CVSS enjoys near-universal adoption in disclosure advisories, patch management systems, and compliance frameworks.

Its limitations as a *comparison* metric are extensively documented. Bozorgi et al. [2010] provided an early empirical critique, finding CVSS scores weakly correlated with actual exploitation activity in the wild. A structurally important finding appears in a large-scale analysis of vendor security advisories (cited in this project as arXiv:2006.15074): **35–82% of vendor security reports lack a CVSS score entirely**, depending on the vendor and the disclosure year. This range is not a narrow confidence interval — it spans a factor of 2.3 and reflects genuine heterogeneity in vendor disclosure practices. The consequence for cross-vendor comparison is that any metric derived from CVSS scores is systematically missing data, and the missing-data pattern is non-random: less transparent vendors produce more incomplete records.

xmcyber's widely-cited practitioner analysis [xmcyber, "Your CVE Count Is a Meaningless Metric"] extended this to the organizational level, arguing that raw CVE totals produce a false signal of risk. A vendor or product with a larger CVE count may simply have a larger installed base (drawing more researcher and attacker attention), a more transparent disclosure program (filing individual CVEs per fix rather than bundling), or more active PSIRT communication — none of which corresponds to weaker underlying security. The analysis observes that the most popular enterprise software products consistently accumulate CVE counts far in excess of smaller-footprint competitors without any corresponding difference in breach rates when normalized for market share.

The "popularity tax" — the systematic inflation of CVE counts for high-market-share products due to greater researcher attention and attacker ROI — is discussed implicitly across the vulnerability management literature and explicitly in the Edge Security Ground Truth methodology. Fortinet's 18 exploited edge CVEs (the highest in this dataset) is consistent with its approximately 50% unit market share in the firewall segment; whether it reflects weaker engineering or simply greater targeting cannot be resolved without per-install normalization, and that normalization is not reliably computable from public data.

### 1.2 EPSS: Predicting Exploitation Probability

The Exploit Prediction Scoring System (EPSS), developed by Jacobs et al. [2021] and maintained by FIRST.org, reframes the question from "how severe is this vulnerability?" to "how likely is this vulnerability to be exploited in the wild within 30 days?" The model is trained on a combination of CVE metadata (description text, product type, CWE category, age), threat intelligence feeds, and observed exploitation events. It produces a probability in [0,1] updated daily.

EPSS represents a significant methodological advance over CVSS for prioritization purposes: Jacobs et al. showed that EPSS substantially outperforms CVSS score thresholds at identifying which CVEs will actually be exploited, while covering a much smaller remediation surface. At the 50th EPSS percentile, roughly 87% of exploited CVEs are covered by fewer than 7% of all CVEs — a dramatic improvement over CVSS-threshold approaches that require patching 60%+ of CVEs to achieve similar coverage.

For the purposes of this project, EPSS has a critical limitation: it is a *forward-looking* probability for the general CVE population. The Edge Security Ground Truth dataset is scoped to CVEs already confirmed exploited by CISA KEV. All entries are, by definition, already exploited; EPSS scores for KEV-listed CVEs cluster near 1.0. EPSS therefore functions here as a supporting signal — useful for identifying whether a vendor's CVEs are consistent with opportunistic exploitation (high EPSS, broadly targeted) versus targeted espionage (potentially lower EPSS, less predictable from public metadata) — but not as a primary exploitation metric. The `scripts/enrich_epss.py` script in this repository fetches current EPSS scores from the FIRST.org API; the scores evolve over time and may differ from EPSS values at the time of initial exploitation.

### 1.3 CISA KEV as an Exploitation Gate

The CISA Known Exploited Vulnerabilities catalog, launched in November 2021, established a new class of vulnerability metric: not "how severe?" or "how likely?", but "has this been observed exploited against real targets?" Inclusion in KEV requires confirmed in-the-wild exploitation and carries a federal remediation mandate (BOD 22-01) for FCEB agencies. This makes KEV a low-false-positive, high-specificity signal: roughly 2% of all published CVEs appear in KEV, corresponding closely to the fraction that independent threat intelligence identifies as exploited.

KEV's limitations are well understood and explicitly documented in this project's methodology. It is CVE-indexed, making it blind to vulnerabilities that were silently patched (no CVE filed), bundled under a single CVE, or fixed in firmware without a disclosure event. The Fortinet CVE-2023-27997 ("XORtigate") case [watchTowr Labs, 2023; Tenable, 2023] illustrates the failure mode: the patched firmware shipped approximately three to four days before the public advisory, meaning organizations could not act on the disclosure because it had not been made. KEV added the CVE only after public disclosure, understating the true exploitation window. Zyxel CVE-2022-30525 presents a comparable case: Rapid7 researchers discovered the vulnerability by diffing a firmware update released without any CVE filing or public advisory [Rapid7, 2022]. In both cases, the KEV entry date understates the actual attacker lead time.

The US-centricity of KEV is a legitimate scope limitation. CISA's mandate is federal agency protection; its confirmation mechanism weights US government intelligence. Vulnerabilities exploited primarily against non-US targets (particularly in East Asian or European networks) may appear in KEV later than in regional threat intelligence, or not at all if exploitation is not confirmed by CISA-accessible sources.

---

## 2. Exploitation Timing Research

### 2.1 The Convergence of Disclosure and Exploitation Windows

A central finding of the modern vulnerability management literature is the compression — and in some cases inversion — of the window between public vulnerability disclosure and first observed exploitation. Early empirical work established baseline timelines in the weeks-to-months range [Bilge and Dumitras, 2012], but the subsequent decade brought systematic acceleration.

Mandiant / Google Threat Intelligence Group's Time-to-Exploit (TTE) reports track the median days from disclosure to first exploitation across their incident response case load. The 2024 edition found an average TTE of **negative one day**: the median vulnerability was exploited before its patch was publicly available. This finding implies that for a substantial fraction of high-value vulnerabilities, the defender's window is defined not by patch availability but by whether they received prior intelligence or had effective isolation in place. Additionally, Mandiant's 2024 data found that **44% of zero-days exploited that year targeted security and edge appliances** — a category that, by installed-base, represents a small fraction of total software, but by attacker ROI represents a disproportionate target.

Academic corroboration for exploitation timing dynamics appears in arXiv:2405.01289, which models the empirical distribution of exploitation onset as a function of vulnerability properties and applies survival analysis methods to estimate the expected time to first exploitation given CVSS and EPSS features. The work provides a theoretical grounding for the practitioner observation that pre-auth RCE vulnerabilities in internet-facing systems have among the shortest observed TTE distributions in the empirical record.

Suciu et al. [2022] extended vulnerability lifecycle modeling to incorporate attacker incentive structures, finding that vulnerabilities in high-value perimeter products (particularly VPN gateways) face adversarially compressed timelines because the attacker's return on investment — persistent access to enterprise networks, lateral movement surface — is highest for internet-facing, always-on infrastructure. The policy implication drawn from this line of work is that "patch Tuesday, exploit Wednesday" is not a technical failure but a structural equilibrium: sophisticated adversaries maintain pre-disclosure capabilities for the most attractive target classes.

### 2.2 The Shift from N-Day to Zero-Day Exploitation

The evolution of attacker capability over the 2020–2026 window is visible in the KEV timeline data in this repository. The 2021 peak (24 edge CVEs added to KEV) reflects a predominantly n-day exploitation pattern: adversaries rapidly weaponizing disclosed vulnerabilities, most prominently in the Pulse Secure / Ivanti Connect Secure platform, where eight CVEs were added in 2021 following coordinated disclosure campaigns.

VulnCheck's 2026 "State of Exploitation" and "Network Edge Device Report" document a structural shift: **42.5% of exploited vulnerabilities in 2025 hit end-of-life devices** that will never receive a patch. This statistic reframes the exploitation problem. If nearly half of exploitation targets are already beyond the vendor support window, the prescriptive emphasis on "patch faster" addresses at most half the exposure surface. The remainder requires architectural responses: network segmentation, management-plane isolation, assume-breach detection posture, and vendor end-of-life lifecycle planning.

The VulnCheck 2026 network edge device report specifically identifies network-edge appliances (firewalls, VPN gateways, remote-access concentrators) as the primary exploitation battleground in the 2024–2025 period, a finding consistent with Mandiant's 44% figure and with the concentration pattern visible in this repository's CISA KEV data (107 confirmed-exploited edge CVEs across 11 vendors in six years, with no year since 2021 showing fewer than 15 additions).

---

## 3. Edge and Perimeter Devices as a Distinct Attack Surface

### 3.1 Structural Properties of Edge Appliances

Network-edge security appliances — firewalls, SSL-VPN gateways, and remote-access concentrators — share a structural profile that distinguishes them from endpoint software and from most enterprise application categories:

1. **Always-on, directly internet-routable** — Unlike endpoint software that requires user interaction for initial access, edge appliances expose listening services (TLS, web management, VPN protocols) directly to the public internet as a design requirement. There is no phishing precondition; a pre-authentication vulnerability is immediately actionable at global scale.

2. **Management-plane conflation** — Many edge appliances expose VPN termination and management web interfaces on overlapping or adjacent port ranges, often on the same physical network interface. CVE-2024-0012 and CVE-2024-9474 (Palo Alto, 2024) and the Juniper J-Web chain (CVE-2023-36844 et al.) both illustrate the pattern: a web management vulnerability that is theoretically "management-only" is exploitable by any attacker who can reach port 443 on the internet-facing interface.

3. **Opaque update delivery** — Unlike open-source software where patching is transparent and CVE assignment is routine, network appliance firmware is typically delivered as a binary blob through vendor-controlled distribution channels. This enables silent patching (as in Fortinet CVE-2023-27997 and Zyxel CVE-2022-30525) but also creates dependency: customers cannot apply community patches or implement mitigations independent of the vendor.

4. **Slow patch cycles in practice** — Appliance firmware updates frequently require service windows, downtime, or staged rollouts. The 2024 Mandiant TTE finding (-1 day average) is particularly damaging for edge appliances because the organizations most dependent on continuous VPN availability are also most constrained in their ability to apply emergency patches rapidly.

### 3.2 CISA's Shift to KEV as a Remediation Mandate

CISA's November 2021 Binding Operational Directive 22-01 (BOD 22-01) formalized the Known Exploited Vulnerabilities catalog as a mandatory remediation list for Federal Civilian Executive Branch agencies, with fixed remediation timelines (typically 14 days for newly-added CVEs). The KEV catalog represents a policy recognition that CVSS-score-based prioritization systematically fails: a CVSS 7.5 vulnerability with confirmed mass exploitation is a higher remediation priority than a CVSS 9.8 with no observed exploitation.

For the edge appliance category, BOD 22-01 has had material effects: CISA Emergency Directive 24-01 (January 2024) ordered federal agencies to disconnect Ivanti Connect Secure devices following the CVE-2023-46805/CVE-2024-21887 zero-day chain — one of only a handful of directives to mandate disconnection rather than patching. Emergency Directive 25-03 (2025) ordered similar emergency action for Cisco ASA/FTD devices following the ArcaneDoor zero-days (CVE-2024-20353, CVE-2024-20359). The escalation from "patch within 14 days" to "disconnect now" reflects CISA's assessment that the exploitation pace in this category exceeds practical patch deployment timelines.

### 3.3 The Installed-Base Confound and Why Normalization Is Not Computed

The literature on vulnerability counts consistently identifies installation base as a confounding variable. A product installed on 10 million enterprise networks attracts orders of magnitude more researcher attention than one installed on 100,000. This attention translates to higher CVE counts (more researchers find more bugs), higher KEV counts (more adversaries attempt exploitation of high-ROI targets), and higher EPSS scores (more exploitation activity to train on). It does not necessarily correspond to weaker engineering quality.

This project explicitly acknowledges this limitation and, critically, declines to compute a normalized score because the correction is not reliably available: vendor-disclosed installation base figures are proprietary, conflate unit counts with revenue, and may not map cleanly onto the specific product scope (edge appliance only, not full portfolio). Fortinet's approximately 50% unit market share in the firewall segment [IDC, various; Gartner Magic Quadrant] is the most plausible single explanation for its 18-count lead over similarly-resourced vendors. No public dataset provides per-vendor edge-appliance-specific install base figures at the granularity required for per-install normalization.

---

## 4. Vendor Disclosure Practices

### 4.1 Silent Patching and Its Impact on Defender Response Time

"Silent patching" — releasing a fixed firmware version without a corresponding CVE assignment or public advisory — represents the most severe form of disclosure failure from a defender perspective. If the patch is not announced, customers cannot prioritize installation; if no CVE is filed, automated vulnerability management systems produce no alert; if no advisory is published, threat intelligence platforms have no event to correlate.

Two cases in this dataset provide well-documented examples. Fortinet CVE-2023-27997 ("XORtigate") was patched in a firmware release approximately three to four days before the public advisory; watchTowr Labs and Tenable independently confirmed the timeline by diffing the firmware binaries [watchTowr, 2023; Tenable, 2023]. The KEV addition date follows the public disclosure, not the firmware release, meaning the dataset understates the true attacker lead time: sophisticated adversaries who diff firmware continuously (a known offensive capability) had a 3–4 day window in which defenders had no official signal to act on.

Zyxel CVE-2022-30525 presents a comparable case: Rapid7 discovered the vulnerability by diffing a firmware update that had been released without any CVE or advisory [Rapid7, 2022]. In this case, the KEV entry reflects a date after Rapid7's public disclosure, meaning the vulnerability was being actively exploited against a customer base that had received no vendor communication about the underlying issue.

Silent patching is not uniformly distributed across the vendor landscape. Vendors with strong PSIRT organizations, established vulnerability disclosure programs, and researcher community relationships tend toward timely, coordinated disclosure. Vendors under commercial pressure to avoid negative publicity, or with less mature security-response functions, are more likely to slip firmware fixes without corresponding advisories. The implication for cross-vendor comparison is asymmetric: a vendor with strong disclosure practices will accumulate more CVEs (because they file them) while a vendor that silent-patches will show fewer CVEs but not fewer vulnerabilities.

### 4.2 Coordinated Disclosure and Nation-State Attribution

Coordinated vulnerability disclosure — where a researcher, government agency, or vendor coordinates simultaneous advisory publication and patch availability — represents the intended best-case disclosure model. Several cases in this dataset illustrate the spectrum. Cisco's ArcaneDoor response coordinated indicators of compromise alongside the patch release, enabling organizations to hunt for existing compromises simultaneously with patching [Talos, 2024]. Palo Alto's response to CVE-2024-3400 (GlobalProtect, CVSS 10.0) was initially hampered by the fact that Volexity identified the vulnerability while it was under active exploitation — roughly 19 days before a hotfix was available — illustrating that even vendors with strong security organizations cannot guarantee coordinated disclosure when the initial discovery occurs in the hands of an adversary.

The Sophos Pacific Rim report [Sophos, 2024] represents an unprecedented case in the firewall vendor category: a five-year retrospective disclosure of nation-state targeting across multiple CVEs (CVE-2020-12271, CVE-2022-1040, CVE-2022-3236), attributing exploitation to China-nexus actors with overlap against Volt Typhoon, APT31, and APT41 assessments. The report includes tactical details (custom implant names, persistence mechanisms, attacker tradecraft) that substantially exceed standard vendor advisory content. No other firewall vendor has published comparable multi-year introspective disclosure about state-sponsored exploitation of their own platform.

This disclosure asymmetry has a specific effect on the KEV-count comparison: Sophos's transparency increases confidence that its six KEV entries represent accurately the known exploitation history of its platform. For vendors that have published less comprehensive threat intelligence about exploitation of their products, the KEV count may be a lower bound rather than an accurate tally.

### 4.3 The Defender's Information Gap

The combined effect of silent patching, incomplete CVSS coverage, and variable disclosure quality is an information gap that systematically disadvantages defenders relative to sophisticated attackers. Adversary groups maintaining dedicated edge-appliance exploitation capabilities (such as the China-nexus actors documented across ArcaneDoor, UNC3886, UNC5221, and the Sophos Pacific Rim campaigns) are likely to invest in firmware diffing, patch analysis, and pre-disclosure research pipelines that give them lead time that no vendor disclosure process can eliminate. The relevant question for defensive planning is therefore not "which vendor discloses fastest?" but "what detection and containment capabilities are deployable before a patch is available?" — a question that CVSS scores and CVE counts cannot answer.

---

## 5. This Work's Contribution

### 5.1 Gap in Existing Databases

NVD, CISA KEV, and commercial databases such as VulnCheck provide comprehensive vulnerability records but do not apply scope-controlled, vendor-comparable extraction. NVD includes all CVEs across a vendor's full product portfolio; a Cisco NVD query returns vulnerabilities in IOS, NX-OS, Webex, SD-WAN, DNA Center, and dozens of other products, making it unsuitable for edge-appliance-specific comparison. CISA KEV similarly covers all exploited CVEs across all products; Cisco's total KEV count (~80+ as of mid-2026) is dominated by IOS and router vulnerabilities that are out of scope for a firewall procurement comparison.

No existing public resource applies a single, documented, reproducible scope rule to extract edge-appliance-only exploited CVEs and present them comparably across the major vendor landscape. Analyst reports from Gartner, Forrester, and commercial threat intelligence vendors occasionally publish similar comparisons, but they are typically paywalled, non-reproducible (the methodology is not published), and updated on annual rather than continuous cycles.

### 5.2 Methodological Contribution

The Edge Security Ground Truth dataset's primary contribution is methodological: the scope rule is explicit (firewall / SSL-VPN / remote-access gateway; endpoint, management, email, WAF, and switching products excluded), editable (the include/exclude logic lives in `scripts/build_kev_counts.py`), and reproducible against the live CISA feed. Any researcher who disagrees with a specific scope decision can modify the rule and re-run the script to produce an alternative count. This transparency about scope assumptions is absent from commercial intelligence products and rare in academic datasets.

The repository's refusal to aggregate across signals (KEV count, EPSS, TTE, silent-patch history, vendor-side breach) into a single score reflects a deliberate methodological choice grounded in the literature: these are incommensurable risk dimensions. A pre-authentication RCE exploited before its patch (Ivanti CVE-2023-46805) represents a different risk profile from a post-authentication vulnerability with a long exploitation window (F5 CVE-2023-46747), and no weighting scheme can convert them into a common unit without encoding value judgments about threat models that differ across organizations.

### 5.3 Acknowledged Limitations

This work inherits the limitations of its primary source (CISA KEV) and adds its own. The most significant are:

- **No per-install normalization.** The raw KEV count partially reflects installed base and cannot be fully corrected without proprietary data. The methodology explicitly declines to fabricate a normalized score.
- **CVE-indexed sources miss silent patches.** Fortinet XORtigate and Zyxel CVE-2022-30525 are confirmed cases where the exploitation window exceeds what KEV dates imply; other cases likely exist undocumented.
- **Attribution is probabilistic.** Threat actor designations (UNC5221, UNC3886, UAT4356, Volt Typhoon) represent analytic assessments from threat intelligence firms, not legally established facts.
- **US-centric confirmation bias.** KEV reflects CISA's visibility, which weights US government networks. Non-US exploitation activity may be underrepresented.
- **Bounded window.** The dataset covers 2020-01-01 through 2026-06-18. Historical KEV entries exist for older CVEs (notably Citrix CVE-2019-19781, mass-exploited in January 2020), which fall outside this window.

---

## 6. Conclusion

The vulnerability management literature consistently reaches two findings relevant to edge-security comparison: first, raw CVE counts are a poor proxy for actual risk due to installed-base inflation, disclosure-policy variation, and the negligible fraction of CVEs that ever see exploitation; second, the edge and perimeter appliance category faces a structurally adversarial environment, with exploitation timelines that now routinely precede patch availability and attacker sophistication (nation-state actors with dedicated edge-exploitation capabilities) that is qualitatively different from the opportunistic mass exploitation that drives most enterprise vulnerability data.

The Edge Security Ground Truth dataset attempts to operationalize the appropriate response to these findings: use CISA KEV (exploited, not theoretical) as the primary signal; apply a consistent, documented scope rule across all vendors; present supporting signals as cited per-vendor facts rather than aggregated scores; and publish the methodology and code in reproducible form. Its central finding — that eleven major edge vendors span 2–18 exploited edge CVEs over six years under a consistent scope, with no vendor demonstrably safer than the others — supports the literature's implied conclusion: the controllable variable in edge-device security is organizational response posture (time-to-patch, management-plane isolation, assume-breach detection), not vendor selection based on raw vulnerability counts.

---

## References

The following references are cited inline above. Where a source is directly referenced in the repository, "(cited in project)" is noted.

- arXiv:2006.15074 — large-scale analysis of CVSS coverage in vendor security advisories (cited in project, README and METHODOLOGY.md).
- arXiv:2405.01289 — empirical analysis of exploitation timing and vulnerability lifecycle (cited in project, README and METHODOLOGY.md).
- Bozorgi, M. et al. (2010). Beyond heuristics: learning to classify vulnerabilities and predict exploits. *KDD 2010*.
- Bilge, L. and Dumitras, T. (2012). Before we knew it: an empirical study of zero-day attacks in the real world. *CCS 2012*.
- CISA (2021). Binding Operational Directive 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities. cisa.gov.
- CISA (2024). Emergency Directive 24-01: Mitigate Ivanti Connect Secure and Ivanti Policy Secure Vulnerabilities. cisa.gov.
- CISA (2025). Emergency Directive 25-03. cisa.gov.
- FIRST.org (ongoing). EPSS: Exploit Prediction Scoring System. first.org/epss. (cited in project)
- Jacobs, J. et al. (2021). Exploit Prediction Scoring System (EPSS). *Digital Threats: Research and Practice*, 2(3). (cited in project by implication via EPSS reference)
- Mandiant / Google Threat Intelligence Group (2024). Time-to-Exploit Report 2024. cloud.google.com. (cited in project)
- Rapid7 (2022). CVE-2022-30525: Zyxel Firewall Unauthenticated Remote Command Injection. rapid7.com. (cited in project, Zyxel.md)
- Sophos (2024). Pacific Rim: Inside a Five-Year Campaign Targeting Edge Devices. sophos.com. (cited in project, Sophos.md)
- Suciu, O. et al. (2022). Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits. *USENIX Security 2022*.
- Talos Intelligence (2024). ArcaneDoor: New Espionage-Focused Campaign Targeting Perimeter Network Devices. blog.talosintelligence.com. (cited in project, Cisco.md)
- Tenable (2023). CVE-2023-27997: XORtigate. tenable.com. (cited in project, Fortinet.md)
- VulnCheck (2026). Network Edge Device Report 2026 / State of Exploitation. vulncheck.com. (cited in project)
- watchTowr Labs (2023). XORtigate or CVE-2023-27997. labs.watchtowr.com. (cited in project, Fortinet.md)
- xmcyber (n.d.). Your CVE Count Is a Meaningless Metric. xmcyber.com. (cited in project)
