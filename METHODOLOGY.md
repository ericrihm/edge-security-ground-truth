# Methodology

This document describes the data sources, scope definitions, counting procedures, enrichment pipeline, statistical methods, and known limitations of the Edge Security Ground Truth dataset. It is written to the standard of an academic methodology section: a reader with access to the cited sources and the repository's scripts should be able to reproduce every number, evaluate every judgment call, and identify every confound.

**This is data, not a ranking.** The methodology produces a reproducible count under a transparent scope rule. It does not rank vendor security quality, and it cannot do so. The distinction matters and is revisited throughout.

---

## Research Questions

This project is structured to answer three empirical questions using the methods described in the sections below.

**RQ1.** Are CISA KEV counts across edge-appliance vendors consistent with a uniform distribution, or do some vendors accumulate significantly more exploited vulnerabilities?
*Answered by: chi-squared goodness-of-fit test (§7.3).*

**RQ2.** Do vendor-specific CWE patterns reveal recurring SDL weaknesses, or are weakness classes distributed uniformly across vendors?
*Answered by: per-vendor CWE matrix (§7.2).*

**RQ3.** Is time-to-exploit for edge appliances faster than the industry-wide baseline, and does it vary significantly by vendor?
*Answered by: TTE analysis benchmarked against Mandiant/GTIG figures (§7.1).*

### Hypotheses

| RQ | Null hypothesis (H₀) |
|----|----------------------|
| RQ1 | Vendor KEV counts do not differ from a uniform distribution across the thirteen vendors (i.e., expected count = total / 13 for each vendor). |
| RQ2 | CWE assignments are distributed uniformly across vendors; no vendor shows a statistically anomalous concentration of a particular weakness class. |
| RQ3 | Median TTE for edge appliances in this dataset does not differ from the Mandiant industry-wide median TTE; vendor-level TTE distributions are drawn from the same underlying population. |

All three null hypotheses are tested at α = 0.05. Given n = 13 vendors and the confounds described in §4, results are treated as descriptive findings rather than definitive causal conclusions.

---

## 1. Data Sources

### 1.1 CISA Known Exploited Vulnerabilities (KEV) Catalog

**What it is.** The CISA KEV catalog is a machine-readable feed maintained by the United States Cybersecurity and Infrastructure Security Agency (CISA) listing Common Vulnerabilities and Exposures (CVE) identifiers that CISA has confirmed to be actively exploited in the wild. It was launched in November 2021 alongside Binding Operational Directive (BOD) 22-01, which mandates that Federal Civilian Executive Branch (FCEB) agencies remediate KEV-listed vulnerabilities within prescribed timelines. As of mid-2026 it contains approximately 1,200 entries.

**What "confirmed exploited" means.** KEV inclusion requires that CISA have sufficient evidence -- typically from US government incident response, intelligence community reporting, or credible public threat intelligence -- that the vulnerability has been used against real targets. This is a high-specificity signal: roughly 2% of all published CVEs appear in KEV, a figure consistent with independent estimates of the exploited fraction (Jacobs et al. 2021, VulnCheck 2026).

**What it measures.** For each CVE, the KEV catalog provides: CVE identifier, vendor name (`vendorProject`), product name (`product`), a short description (`shortDescription`), the date CISA added the entry (`dateAdded`), the required action deadline, and whether the vulnerability is known to be associated with ransomware campaigns (`knownRansomwareCampaignUse`).

**What it does not measure.** KEV does not measure vulnerability severity, exploitation volume, the number of compromised organizations, the sophistication of exploitation, or the quality of the vendor's response. A CVE exploited once by a nation-state actor and a CVE mass-exploited by botnet operators receive the same catalog entry.

**Known biases and limitations.**

1. **CVE-indexing.** KEV is indexed by CVE identifier. Vulnerabilities that are silently patched without a CVE filing, bundled under a single CVE covering multiple bugs, or fixed in firmware without a public advisory are invisible to KEV. This systematically understates exposure for vendors with weak disclosure practices.

2. **US-centricity.** CISA's intelligence-gathering mandate is oriented toward US federal agency protection. Vulnerabilities exploited primarily against non-US targets -- particularly in East Asian, Middle Eastern, or European networks -- may appear in KEV later than in regional threat intelligence feeds, or may not appear at all if exploitation is not confirmed through CISA-accessible sources.

3. **Selection bias.** Not all exploited vulnerabilities make the catalog. CISA exercises editorial judgment: a vulnerability must have a CVE, an actionable remediation, and sufficient evidence. The pipeline from exploitation in the wild to catalog inclusion is opaque and likely varies in latency.

4. **Retrospective backfill.** KEV was launched in November 2021 with an initial batch of entries covering vulnerabilities exploited in prior years. The `dateAdded` field for these backfilled entries reflects when CISA added them to the catalog, not necessarily when exploitation was first observed. This means the 2021-2022 year counts include historical backfill and should not be interpreted as reflecting exploitation activity solely within those calendar years.

5. **Catalog version drift.** CISA publishes a `catalogVersion` field in the JSON feed. The feed is additive (new entries are appended; existing entries are rarely modified or removed). However, minor corrections to product names, descriptions, or remediation deadlines do occur. This project records the catalog version at generation time in its output metadata.

**Feed URL and format.** The live feed is available at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. It is a JSON document with a top-level `vulnerabilities` array.

**Role in this project.** KEV is the **gating filter**: a CVE is counted if and only if it appears in the KEV catalog. We do not count total CVEs, CVSS-thresholded CVEs, or EPSS-predicted CVEs. This design choice was deliberate -- it answers "how many bugs were confirmed exploited?" rather than "how many bugs were disclosed?" The former is a meaningful threat signal; the latter is confounded by disclosure practice differences to the point of being misleading.

### 1.2 FIRST EPSS (Exploit Prediction Scoring System)

**What it is.** EPSS is a machine-learning model maintained by FIRST.org that estimates the probability that a CVE will be exploited in the wild within the next 30 days. It is trained on CVE metadata (description text, product type, CWE category, age), threat intelligence feeds, and observed exploitation events (Jacobs et al. 2021). EPSS produces a probability in [0,1] and a percentile rank, updated daily.

**What it measures.** Forward-looking exploitation probability for the general CVE population. At the 50th EPSS percentile, roughly 87% of exploited CVEs are covered by fewer than 7% of all CVEs (Jacobs et al. 2021), making it substantially more efficient than CVSS-threshold approaches for patch prioritization.

**What it does not measure.** EPSS does not measure severity, impact, or the identity of the exploiting actor. It is optimized for *prediction* of exploitation onset, not for characterization of ongoing exploitation.

**Known biases and limitations.**

1. **Redundancy with KEV in this dataset.** Every CVE in our dataset is already confirmed exploited (it is KEV-listed). EPSS scores for KEV-listed CVEs cluster near 1.0. EPSS therefore functions here as a *supporting signal* -- useful for distinguishing opportunistic exploitation (high EPSS, broadly targeted) from targeted espionage (potentially lower EPSS, less predictable from public metadata) -- but not as a primary metric.

2. **Temporal instability.** EPSS scores change daily. The scores in this dataset reflect the date of enrichment (recorded in output metadata), not the EPSS score at the time of initial exploitation. For historical analysis, time-series EPSS data would be required from FIRST.org's historical API.

3. **CVE-only.** Like KEV, EPSS is indexed by CVE identifier and cannot score vulnerabilities without one.

**API.** `https://api.first.org/data/v1/epss`. Batch queries of up to 100 CVE identifiers per request. No authentication required. The project applies a 1-second inter-batch delay as a courtesy rate limit.

**Role in this project.** EPSS is an enrichment signal. It is fetched for every CVE in the KEV-scoped dataset and recorded in the enriched output (`kev_edge_enriched.json`). It is used in the cross-vendor pattern analysis (`analyze_patterns.py`) and the statistical framework (`analyze_statistics.py`) as a secondary variable for Spearman rank correlation.

### 1.3 NVD / CVE (National Vulnerability Database)

**What it is.** The NVD, maintained by NIST, provides standardized vulnerability descriptions, CVSS scores, CWE classifications, and publication dates for CVE identifiers. It is the authoritative US government repository for CVE metadata.

**What it measures.** Per-CVE: CVSS v3.1 base score and vector string, CVSS severity rating (CRITICAL / HIGH / MEDIUM / LOW), CWE weakness classification, and NVD publication date.

**What it does not measure.** NVD does not track exploitation status (that is KEV's role), patch availability timelines, or real-world impact.

**Known biases and limitations.**

1. **Incomplete CVSS coverage.** Between 35% and 82% of vendor security advisories lack a CVSS score in NVD, depending on the vendor and disclosure year (arXiv:2006.15074, xmcyber). The missing-data pattern is non-random: less transparent vendors produce more incomplete records. For the edge-KEV dataset specifically, CVSS coverage is higher (these are high-profile exploited CVEs that attract NVD analyst attention), but it is not 100%.

2. **CWE classification subjectivity.** CWE assignments in NVD are made by NVD analysts, not by the vendor or the discovering researcher, and may differ from the CNA-assigned CWE. Some CVEs receive `NVD-CWE-noinfo` (insufficient information to classify) or `NVD-CWE-Other`, which are analytically unhelpful. The project records both the primary and any secondary CWE assignments.

3. **Publication date vs. disclosure date.** The NVD `published` date reflects when the CVE record was created in NVD, which may lag the vendor advisory, the initial CVE reservation, or the actual public disclosure by days to weeks. For time-to-exploit (TTE) computation, the NVD date is used as a proxy for public disclosure, but the true disclosure date may differ.

4. **API reliability.** The NVD API 2.0 (`services.nvd.nist.gov`) has experienced persistent availability issues (HTTP 503 errors, IPv6 failures) during the 2025-2026 period. The enrichment script (`enrich_nvd.py`) mitigates this by using the MITRE CVE Services API (`cveawg.mitre.org`) as the primary data source and falling back to the NVD API only when MITRE returns no data. Both APIs provide CVSS and CWE data, though from different authoritative perspectives (CNA vs. NVD analyst).

**APIs.** Primary: `https://cveawg.mitre.org/api/cve/{CVE-ID}` (MITRE CVE Services, no rate limit issues). Fallback: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}` (NVD API 2.0, rate-limited at ~6 requests/minute without an API key). The project applies a 2-second inter-request delay.

**Role in this project.** NVD/MITRE data is an enrichment layer providing CVSS scores, CWE classifications, and publication dates. These are used in the CWE analysis (`analyze_cwe.py`), time-to-exploit analysis (`analyze_tte.py`), statistical framework (`analyze_statistics.py`), and cross-vendor pattern analysis (`analyze_patterns.py`).

### 1.4 Mandiant / GTIG Time-to-Exploit Reports

**What they are.** Annual reports from Mandiant (now Google Threat Intelligence Group, GTIG) that measure the median number of days between public vulnerability disclosure and first observed exploitation across their incident response caseload.

**What they measure.** The 2024 report found an average TTE of **negative one day** (exploited before patch), and that **44% of 2024 zero-days targeted security/edge appliances**. These figures characterize the attacker tempo for high-value targets.

**What they do not measure.** Mandiant's TTE data is drawn from their client base, which skews toward large enterprises and government agencies. The median TTE for vulnerabilities exploited against SMB targets or in regions outside Mandiant's operational footprint may differ.

**Known biases.** Incident response selection bias (Mandiant responds to serious incidents; low-severity exploitation may not be observed), temporal coverage (annual reports with year-to-year methodology changes), and confidential attribution (threat actor designations like UNC5221, UNC3886, UAT4356 are assessments, not judicial-standard proof).

**Role in this project.** Mandiant TTE data provides contextual framing for the time-to-exploit analysis. It is cited in the README and in per-vendor narrative sections to characterize zero-day exploitation events. It is not ingested programmatically.

### 1.5 VulnCheck Reports

**What they are.** VulnCheck publishes periodic exploitation landscape reports, including the 2026 "State of Exploitation" and "Network Edge Device Report."

**Key findings used.** 42.5% of 2025 exploited vulnerabilities hit end-of-life (EOL) devices; the network edge is identified as the primary exploitation battleground for 2024-2025.

**Known biases.** VulnCheck's data is drawn from their proprietary exploit intelligence platform. Coverage may differ from CISA KEV, Mandiant, or other threat intelligence providers.

**Role in this project.** VulnCheck data provides supporting context for the scope justification (why edge appliances specifically). It is cited in the README and literature review, not ingested programmatically.

### 1.6 Academic Literature

Several academic works inform the methodology:

- **arXiv:2006.15074** -- Documents CVSS coverage gaps (35-82% missing across vendors) and the statistical invalidity of raw CVE counting.
- **arXiv:2405.01289** -- Models empirical distribution of exploitation onset as a function of vulnerability properties; corroborates the practitioner finding that pre-auth RCE in internet-facing systems has the shortest TTE.
- **Jacobs et al. 2021** -- EPSS design paper; demonstrates EPSS outperforms CVSS thresholds for exploitation prediction.
- **Bozorgi et al. 2010** -- Early empirical critique of CVSS as a predictor of exploitation.
- **Bilge and Dumitras 2012** -- Baseline empirical work on zero-day and n-day exploitation timelines.
- **Suciu et al. 2022** -- Vulnerability lifecycle modeling incorporating attacker incentive structures; finds VPN gateways face adversarially compressed exploitation timelines.

These works are discussed in detail in [docs/RELATED-WORK.md](./docs/RELATED-WORK.md).

---

## 2. Scope Definition

### 2.1 Formal Definition

**Edge appliance** is defined as: an internet-facing network security appliance whose primary function is one or more of (a) stateful firewall, (b) SSL-VPN termination, or (c) remote-access gateway. This corresponds to the product categories that are, by design, directly reachable from the public internet without prior authentication -- the property that makes pre-authentication vulnerabilities immediately exploitable at global scale.

### 2.2 Justification for This Scope

**Why not broader (all enterprise security products)?** Endpoint protection agents (e.g., FortiClient, MobileIron), management consoles (e.g., FortiManager, Cisco FMC, Ivanti EPM), email security gateways (e.g., FortiMail), WAFs (e.g., FortiWeb), and load balancers operate in fundamentally different threat models. They are not typically directly internet-reachable without prior network access; they require different exploitation preconditions (often post-authentication or internal-network-adjacent); and they serve different architectural roles. Including them would conflate distinct attack surfaces under a single vendor label. For example, Cisco's portfolio-wide KEV total exceeds 80 entries, spanning IOS, switches, routers, and SD-WAN -- attributing all of these to "Cisco firewalls" would be factually incorrect and analytically useless.

**Why not narrower (firewall only)?** SSL-VPN gateways and remote-access appliances share the same structural properties as firewalls in terms of internet exposure, pre-authentication attack surface, and exploitation dynamics. In many product lines they run on the same operating system (e.g., FortiOS serves both firewall and SSL-VPN functions; PAN-OS serves both firewall and GlobalProtect VPN). Excluding VPN gateways would omit the majority of the highest-impact exploitation events in the 2020-2026 window (the Ivanti/Pulse Secure VPN chains, the Fortinet SSL-VPN series, CitrixBleed).

**Why these thirteen vendors?** The thirteen vendors in scope (Array Networks, Check Point, Cisco, Citrix, F5 Networks, Fortinet, Ivanti, Juniper Networks, Palo Alto Networks, SonicWall, Sophos, WatchGuard, Zyxel) represent the major commercial edge appliance vendors that appear in the CISA KEV catalog within the scope window. No vendor with qualifying KEV entries is excluded — WatchGuard (Firebox/Fireware, 4 entries) and Array Networks (ArrayOS AG/vxAG, 2 entries) were added in the 2026-06 expansion after an audit found qualifying entries that earlier versions had missed. The dataset is extensible: adding a vendor requires adding a scope rule to `SCOPE` in `build_kev_counts.py` and re-running.

### 2.3 Inclusion and Exclusion Logic

The scope rule is implemented as a per-vendor pair of regular expressions applied to the KEV `product` field (and, for "Multiple Products" entries, the concatenation of `product` and `shortDescription`):

- **Include regex**: matches product names corresponding to the vendor's edge appliance line.
- **Exclude regex**: matches product names that should be excluded even if the include regex matches.

The exact regexes are defined in the `SCOPE` dictionary in [`scripts/build_kev_counts.py`](./scripts/build_kev_counts.py) (lines 26-49). For transparency, the following table summarizes the rules:

| Vendor | Include pattern | Exclude pattern | Rationale |
|--------|----------------|-----------------|-----------|
| Fortinet | `FortiOS\|FortiProxy` | `FortiClient\|FortiManager\|FortiWeb\|FortiMail\|FortiVoice\|FortiNDR` | FortiOS is the firewall+VPN OS; FortiProxy is a related web gateway. Endpoint agents, management consoles, WAF, email, voice, and NDR are excluded. |
| Ivanti | `Connect Secure\|Pulse Connect Secure\|Policy Secure` | `MobileIron\|Endpoint Manager\|EPMM\|EPM\|Sentry\|Cloud Services Appliance\|Virtual Traffic Manager` | Connect Secure/Pulse Secure is the SSL-VPN. MDM, endpoint management, and application delivery products are excluded. |
| Cisco | `Adaptive Security Appliance\|ASA\|Firepower Threat Defense\|FTD\|Secure Firewall` | `Management Center\|FMC` | ASA and FTD are the firewall/VPN platforms. FMC (management console) is excluded. IOS, switches, routers, SD-WAN, Webex, and other Cisco products are excluded by vendor name matching (they appear under different `vendorProject` names or different product strings). |
| Palo Alto Networks | `PAN-OS` | `Expedition` | PAN-OS is the firewall/VPN OS. Expedition (migration tool) is excluded. |
| SonicWall | `SonicOS\|SMA\|SSLVPN\|SSL[- ]?VPN\|Secure Remote Access\|SRA` | `Email Security` | SonicOS (firewall) and SMA/SRA (remote access) are both in scope. Email security is excluded. |
| Check Point | `Quantum\|CloudGuard\|Security Gateway\|Gaia` | `Endpoint\|Harmony\|SmartConsole\|ZoneAlarm` | Quantum Security Gateway / Gaia is the firewall platform. Endpoint, Harmony (consumer), management console, and ZoneAlarm are excluded. |
| Citrix | `NetScaler ADC\|NetScaler Gateway\|Citrix ADC\|Citrix Gateway\|Application Delivery Controller\|^NetScaler$` | `Workspace\|XenApp\|XenDesktop\|ShareFile\|Endpoint Management` | NetScaler ADC/Gateway is the SSL-VPN/load balancer with gateway function. The anchored `^NetScaler$` term captures KEV entries CISA labels with the bare product string "NetScaler" (e.g. CVE-2025-7775, CVE-2026-3055). Virtualization and SaaS products are excluded. |
| F5 | `BIG-IP` | `BIG-IQ\|NGINX` | BIG-IP serves APM (SSL-VPN), LTM (load balancing), and firewall functions. BIG-IQ (management) and NGINX are excluded. |
| Zyxel | `Multiple Firewalls\|USG\|ATP\|ZyWALL\|VPN\|FLEX` | `NAS\|Network-Attached Storage\|Router\|CPE\|DSL\|Access Point` | USG/ATP/FLEX/VPN/ZyWALL are the firewall product lines. NAS, routers, CPE devices, and access points are excluded. |
| Juniper | `Junos OS\|ScreenOS` | *(none)* | Junos OS (J-Web) and ScreenOS are the firewall/VPN operating systems. No exclusion needed because Juniper's non-firewall KEV entries appear under different product names. |
| Sophos | `Firewall\|XG Firewall\|SG UTM\|SFOS\|CyberoamOS` | `Web Appliance\|Intercept X\|Central\|Endpoint\|Email` | Sophos Firewall (SFOS), XG Firewall, SG UTM, and CyberoamOS (legacy) are in scope. Endpoint, email, web appliance, and management (Central) are excluded. |
| WatchGuard | `Firebox\|XTM\|Fireware` | `AuthPoint` | Firebox / XTM appliances running Fireware OS are the UTM firewall + Mobile VPN line. AuthPoint (cloud MFA) is excluded. |
| Array Networks | `ArrayOS\|vxAG` | *(none)* | AG / vxAG appliances running ArrayOS are the SSL-VPN / secure-access gateway line. |

### 2.4 Special Cases

**"Multiple Products" entries.** Some KEV entries use `product = "Multiple Products"` for vulnerabilities affecting multiple product lines (e.g., Fortinet CVE-2022-40684 affects FortiOS, FortiProxy, and FortiSwitchManager). For these entries, the script concatenates the `product` and `shortDescription` fields before applying the include regex. This ensures that an entry affecting FortiOS is counted even when the product field says "Multiple Products."

**Cross-product attribution.** SonicWall's count spans two distinct product families (SonicOS firewalls and SMA remote-access appliances) because both fall within the edge-appliance scope definition. This is stated explicitly in the README and in the table footnotes. A reader who wishes to separate them can modify the scope regex and re-run.

**Product name evolution.** Vendor and product names in the KEV catalog are not perfectly consistent over time. "Pulse Connect Secure" became "Ivanti Connect Secure" after the 2021 acquisition. The include regex captures both. "Citrix ADC" became "NetScaler ADC" after the 2023 rebrand. Both forms are matched.

---

## 3. Counting Methodology

### 3.1 Algorithm

The counting algorithm, implemented in [`scripts/build_kev_counts.py`](./scripts/build_kev_counts.py), proceeds as follows:

1. **Fetch the KEV catalog.** Either from a local file (for reproducible snapshots) or from the live CISA feed at the URL above.

2. **For each vendor in `SCOPE`:**
   a. Compile the include and exclude regular expressions (case-insensitive).
   b. Iterate over every entry in the KEV `vulnerabilities` array.
   c. **Vendor match:** Check whether `vendorProject` (case-insensitive) matches the vendor key.
   d. **Product match:** Determine the "haystack" string. If the `product` field contains the word "multiple" (case-insensitive), concatenate `product + " " + shortDescription`; otherwise use `product` alone. Apply the include regex to the haystack. If no match, skip.
   e. **Exclusion check:** If an exclude regex is defined and matches the `product` field, skip.
   f. **Window check:** If the entry's `dateAdded` falls outside the scope window (`2020-01-01` to the configured end date), skip.
   g. **Record the entry:** Capture the CVE ID, product name, `dateAdded`, and short description.

3. **Sort entries** within each vendor by `dateAdded` (ascending).

4. **Output results** in the requested format (table, JSON, or CSV). The JSON output includes full metadata: catalog version, scope window, generation timestamp, per-vendor scope rules, and per-vendor counts.

### 3.2 Scope Window

The default window is `2020-01-01` through `2026-12-31`. The start date was chosen to capture the pre-KEV exploitation period (KEV was launched November 2021 but backfilled earlier entries) while excluding very old vulnerabilities that predate modern exploitation dynamics. The end date is set to year-end 2026 to capture ongoing additions without requiring script modification during the study period.

The window is keyed to the KEV `dateAdded` field -- the date CISA added the entry to the catalog -- not the CVE publication date, not the vendor advisory date, and not the date of first observed exploitation. This is a design choice with consequences: `dateAdded` is the most authoritative timestamp CISA provides for when exploitation was confirmed, but it systematically lags the actual exploitation onset (sometimes by weeks or months for zero-days, and substantially for backfilled entries).

The `--as-of` flag allows a user to reproduce historical snapshots by capping `dateAdded` at a specified date. This is the primary reproducibility mechanism: given a local copy of the KEV feed and a fixed `--as-of` date, the output is deterministic.

### 3.3 Vendor Name Matching

Vendor matching uses case-insensitive, whitespace-trimmed string comparison against the KEV `vendorProject` field (the live feed ships some values with stray trailing whitespace — e.g. `"Array Networks "` — so the comparison `.strip()`s both sides). This field is controlled by CISA and is generally consistent within a vendor, but it can vary: e.g., "Palo Alto Networks" (with "Networks") vs. a hypothetical "Palo Alto" (without). The current regexes assume CISA's established naming conventions. If CISA introduces a variant, the script must be updated.

### 3.4 Edge Cases and Resolution

| Edge case | Resolution | Example |
|-----------|------------|---------|
| KEV entry with `product = "Multiple Products"` | Concatenate `product + " " + shortDescription` for regex matching | Fortinet CVE-2022-40684 |
| Same CVE appears under two vendor names (theoretical) | Not observed in the current dataset; if encountered, the CVE would be counted once per vendor | N/A |
| Product name does not match any include regex | Entry is silently excluded; the full exclusion list is visible by running the script with `--format csv` and diffing against the unfiltered KEV feed | Fortinet FortiManager entries |
| Vendor has KEV entries but all are out of scope | Vendor appears in output with count = 0 | Not currently observed |
| CVE assigned to a parent company after acquisition | Include regex captures both legacy and current product names | Pulse Secure / Ivanti |
| `dateAdded` is before the scope window start | Entry excluded | Pre-2020 entries |

---

## 4. Known Confounds

The following confounds affect the interpretation of the primary metric (exploited edge-CVE count). They are listed not because they can be corrected in this dataset -- most cannot -- but because any honest methodology must enumerate the ways the numbers could mislead.

### 4.1 Installed Base / Popularity Tax

**Formal statement.** The expected number of CVE discoveries (and hence KEV entries) for a vendor is a function of both (a) the vendor's underlying code quality and (b) the size and attractiveness of the vendor's installed base. Larger installed bases attract more security researcher attention (increasing discovery rate) and more attacker interest (increasing exploitation rate), independent of code quality. This is a classical confound: the treatment (code quality) and the confounder (installed base) both influence the outcome (CVE/KEV count) in the same direction.

**Magnitude.** Fortinet's approximately 50% unit market share in the firewall segment (estimated from industry analyst reports) is consistent with its highest KEV count (18). The extent to which this count reflects market share vs. engineering quality cannot be determined without per-install normalization. Such normalization is not reliably computable: install-base figures are proprietary, estimated differently by different analysts, and conflate unit counts, revenue share, and managed-service deployments.

**Consequence.** We publish no normalized score and fabricate none. Every presentation of the count table includes the caveat that counts partly reflect installed base. This is the single most important limitation of the methodology.

### 4.2 Disclosure Practice Differences

**Silent patching suppresses counts.** When a vendor releases a firmware update containing a security fix without issuing a CVE or public advisory, the vulnerability is invisible to KEV (which requires a CVE) and to this dataset. Documented examples include:

- **Fortinet CVE-2023-27997 ("XORtigate"):** Patched firmware shipped approximately 3-4 days before the public advisory (watchTowr Labs 2023, Tenable 2023).
- **Zyxel CVE-2022-30525:** Firmware released without CVE or advisory; discovered by Rapid7 only after diffing the update (Rapid7 2022).

Vendors that silently patch more frequently will have systematically lower KEV counts, all else equal. This is the opposite of what a naive consumer might expect: a vendor with fewer CVEs may have weaker disclosure practices, not stronger code.

**Bundled vs. granular CVE filing.** Some vendors (and some open-source projects) file one CVE per individual fix; others bundle multiple fixes under a single CVE or advisory. The former inflates the CVE count; the latter deflates it. This asymmetry is not correctable from public data.

### 4.3 Researcher Attention Bias

**More researchers investigating a product leads to more CVEs found.** Products with larger market share, more accessible firmware (easier to reverse engineer), or higher bug-bounty payouts attract disproportionate researcher attention. Products that are harder to obtain, harder to reverse, or have smaller markets receive less scrutiny -- not because they are more secure, but because the incentive structure directs research effort elsewhere.

**Consequence.** A low CVE count may reflect low scrutiny rather than high security. Check Point's count of 2 partly reflects fewer disclosed pre-auth RCE vulnerabilities in its gateway product line, but also lower researcher attention relative to Fortinet and Palo Alto. The methodology cannot distinguish between these explanations.

### 4.4 CISA KEV Selection Bias

**Not all exploited vulnerabilities make the catalog.** KEV inclusion requires: (a) a CVE identifier exists, (b) CISA has sufficient evidence of exploitation, and (c) an actionable remediation is available. Vulnerabilities exploited against non-US targets, exploited via classified capabilities that intelligence agencies do not wish to disclose, or exploited in ways that do not reach CISA's confirmation pipeline may be under-represented.

The KEV catalog also reflects CISA's operational priorities. Vulnerabilities affecting FCEB agencies may be prioritized for catalog inclusion over those affecting only private-sector targets. This creates a potential bias toward vendors with larger federal deployments.

### 4.5 Temporal Effects

**Catalog growth and maturation.** KEV was launched in November 2021 with a batch of backfilled entries. The catalog has grown each year, both because new exploitation occurs and because CISA's collection and confirmation pipeline has matured. More recent years may show higher counts partly due to improved detection and cataloging, not solely due to increased exploitation activity.

**Scope window framing.** The 2020-2026 window captures a specific period in vulnerability exploitation dynamics. The 2020-2021 period saw a surge in VPN exploitation (driven by COVID-19 remote work adoption); the 2023-2024 period saw a shift toward zero-day exploitation of edge appliances. A different window would produce different counts and potentially different vendor orderings.

### 4.6 Product Scope Boundary Effects

**Scope is a judgment call.** Reasonable people can disagree about whether F5 BIG-IP's load-balancer function belongs in an "edge appliance" dataset, whether Junos OS router entries (vs. SRX firewall entries) should be included, or whether Citrix NetScaler ADC is primarily a VPN gateway or primarily a load balancer. The scope rule is made transparent specifically so that readers can modify it and re-run. But any fixed scope rule creates boundary effects: moving one entry in or out of scope can change a vendor's count by one, which for vendors with counts in single digits is a material percentage change.

---

## 5. What This Methodology Can and Cannot Answer

### 5.1 What It CAN Answer

1. **Comparison of confirmed-exploited counts under a uniform scope rule.** Given a fixed definition of "edge appliance" and a fixed temporal window, how many CISA-confirmed-exploited CVEs does each vendor have? This is a reproducible, verifiable fact.

2. **Identification of exploitation patterns.** Which CWE categories recur? Which vendors have zero-day entries? What is the distribution of time-to-exploit? What fraction is ransomware-associated?

3. **Framing of relative exposure.** The spread of the data (2-18 across thirteen vendors) is itself a finding: no vendor is dramatically cleaner than the others, and no vendor is immune.

### 5.2 What It CANNOT Answer

1. **Ranking of vendor security quality.** The count conflates code quality, installed base, disclosure practices, and researcher attention. It cannot disentangle them. A higher count does not prove worse security engineering.

2. **Prediction of future vulnerabilities.** Past exploitation does not predict future exploitation in a statistically meaningful way at the vendor level. The sample sizes are too small (n=2 to n=18) and the confounders are too large.

3. **Normalization for installed base.** Per-install exploitation rates would be the appropriate comparison metric, but install-base denominators are not publicly available at sufficient precision.

4. **Assessment of vendor response quality.** The count says how many bugs were exploited, not how fast the vendor responded, how well the advisory communicated the risk, or how effectively the vendor supported its customers during the incident.

5. **Comprehensive exploitation measurement.** KEV represents a lower bound on exploitation. Silently patched vulnerabilities, vulnerabilities without CVE identifiers, and vulnerabilities exploited outside CISA's visibility are not counted.

---

## 6. Enrichment Methodology

### 6.1 Pipeline Overview

The data pipeline has three stages:

1. **Count** (`build_kev_counts.py`): Fetch CISA KEV, apply scope rules, produce `kev_edge_counts.json` (vendor -> [CVE-ID list]).
2. **Enrich -- EPSS** (`enrich_epss.py`): Batch-fetch EPSS scores from FIRST.org API, produce `kev_edge_enriched.json` with EPSS fields.
3. **Enrich -- NVD** (`enrich_nvd.py`): Fetch CVSS, CWE, and publication dates from MITRE CVE Services API (primary) and NVD API 2.0 (fallback), merge into `kev_edge_enriched.json`.

Each stage is idempotent: re-running produces the same output given the same upstream data. The enrichment scripts preserve existing data when adding new fields (EPSS enrichment does not overwrite NVD data, and vice versa).

### 6.2 EPSS Enrichment

**Script:** `scripts/enrich_epss.py`

**Procedure:**
1. Load `kev_edge_counts.json` and collect all unique CVE identifiers.
2. Batch-fetch EPSS scores in groups of up to 100 CVEs per request from `https://api.first.org/data/v1/epss`.
3. Apply a 1-second inter-batch delay as a courtesy rate limit.
4. For each CVE, record `epss` (float, 0-1) and `percentile` (float, 0-1). If the CVE is not in the EPSS database, record `null` for both fields.
5. Write enriched output with per-vendor structure and metadata (source URL, timestamp, total CVEs, EPSS found/missing counts).

**API version:** EPSS API v1. No authentication required.

**Freshness:** EPSS scores are point-in-time snapshots. The enrichment timestamp is recorded in the output `_metadata` block. For longitudinal analysis, the enrichment must be re-run.

### 6.3 NVD / MITRE Enrichment

**Script:** `scripts/enrich_nvd.py`

**Procedure:**
1. Load `kev_edge_counts.json` for the CVE list and any existing `kev_edge_enriched.json` for previously fetched data.
2. For each CVE requiring enrichment:
   a. **Primary source -- MITRE CVE Services API** (`https://cveawg.mitre.org/api/cve/{CVE-ID}`): Parse CNA-provided CVSS scores (v3.1 preferred, v3.0 fallback), CWE classifications from `problemTypes`, and publication date from `cveMetadata.datePublished`. If MITRE returns data, use it.
   b. **Fallback -- NVD API 2.0** (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}`): Parse NVD-analyst-provided CVSS scores (Primary type preferred), CWE from `weaknesses`, and publication date from `published`. Used only when MITRE returns no data.
3. Apply a 2-second inter-request delay. For NVD API errors (HTTP 403, 429, 503), retry with exponential backoff (6s, 12s).
4. Record for each CVE: `cvss` (float), `cvss_severity` (string), `cvss_vector` (string), `cwe` (string, primary CWE-ID), `cwe_name` (string, human-readable), `cwe_secondary` (list, if multiple CWEs), `published` (date string), and `_source` (string, "mitre" or "nvd").
5. Save progress after every CVE (crash-safe incremental writes).
6. Merge with existing EPSS data, preserving all previously enriched fields.

**IPv4 enforcement.** The NVD API returns HTTP 503 over IPv6 as of June 2026. The script patches `socket.getaddrinfo` to force IPv4 resolution.

**Resume capability.** The `--skip-existing` flag allows interrupted enrichment runs to resume without re-fetching previously enriched CVEs.

**CWE name resolution.** The script contains a built-in lookup table of approximately 80 well-known CWE identifiers and their names. This avoids a separate API call to the CWE database and covers the vast majority of CWE assignments in the edge-KEV dataset.

### 6.4 Enriched Output Format

The enriched output (`kev_edge_enriched.json`) is a JSON object with:
- Top-level keys = vendor names (string)
- Each vendor value = object mapping CVE-ID to enriched fields
- `_metadata` key = object with source URLs, timestamp, counts, and provenance

Example entry:
```json
{
  "SonicWall": {
    "CVE-2021-20016": {
      "epss": 0.40038,
      "percentile": 0.9845,
      "published": "2021-02-03",
      "cvss": 9.8,
      "cvss_severity": "CRITICAL",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89",
      "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
      "_source": "mitre"
    }
  }
}
```

---

## 7. Analysis Methods

### 7.1 Time-to-Exploit (TTE) Analysis

**Script:** `scripts/analyze_tte.py`

**Definition.** TTE is computed as: `TTE = KEV_dateAdded - NVD_publishedDate` (in calendar days). This measures how quickly CISA confirmed active exploitation after public disclosure, not the time from patch availability to exploitation or the time from exploitation onset to CISA confirmation.

**Interpretation.** Negative TTE values mean the CVE was added to KEV before its NVD publication date -- a strong signal of true zero-day exploitation (exploited before public disclosure). Zero or small positive values indicate exploitation near the time of disclosure. Large positive values may indicate either slow exploitation or delayed KEV addition (e.g., backfilled entries).

**Known zero-days.** The analysis maintains a curated list of confirmed zero-day exploitation events, derived from incident reports (Mandiant, Volexity, CISA advisories), not solely from TTE arithmetic. A CVE may have positive TTE but still be a confirmed zero-day if exploitation preceded the NVD publication date by a pathway not captured in the date fields.

**Histogram buckets.** TTE values are binned into: negative (<0 days), 0-7 days, 8-30 days, 31-90 days, 91-365 days, and 365+ days.

### 7.2 CWE Pattern Analysis

**Script:** `scripts/analyze_cwe.py`

**Procedure.** CWE identifiers from the enriched dataset are aggregated globally and per-vendor. The analysis produces: global CWE distribution (top weakness classes), per-vendor CWE matrix (which vendors have which weakness types), and identification of recurring weakness patterns (e.g., repeated authentication bypasses in a single vendor's product line).

**Limitation.** CWE assignments are not uniformly granular. Some CVEs receive broad categories (CWE-284 "Improper Access Control") while functionally equivalent vulnerabilities in other vendors receive specific subcategories (CWE-287 "Improper Authentication"). This inconsistency is a property of the NVD/MITRE data, not correctable by this project.

### 7.3 Statistical Framework

**Script:** `scripts/analyze_statistics.py`

All statistical computations are implemented from first principles using Python's `math` and `statistics` modules (no numpy, scipy, or pandas dependencies). Methods include:

- **Chi-squared goodness-of-fit** tests whether vendor counts differ from a uniform distribution. P-value uses the Wilson-Hilferty normal approximation. The null hypothesis is that all vendors have equal expected counts.
- **Herfindahl-Hirschman Index (HHI)** measures concentration: 1/n = perfectly equal, 1.0 = monopoly.
- **Gini coefficient** measures inequality: 0 = perfect equality, 1 = maximum concentration.
- **Coefficient of variation** (CV = sigma/mu) measures dispersion relative to the mean.
- **Spearman rank correlation** tests monotonic relationships (e.g., CVE count vs. mean EPSS score). Significance via t-distribution approximation.
- **Poisson regression** models the expected count under various assumptions.
- **Confidence intervals** via bootstrap or normal approximation where applicable.

**Small-sample caveat.** All tests are conducted with n=13 vendors. This is below the sample size at which most asymptotic statistical tests achieve reliable coverage. Results should be interpreted as descriptive summaries, not as definitive hypothesis tests. The chi-squared test result (p approximately 0.0008 in the current dataset) suggests counts differ from uniform, but the uncontrolled confounders (installed base, researcher attention) make causal interpretation hazardous.

---

## 8. Reproducibility

### 8.1 How to Reproduce Every Number

1. **Clone the repository** at a specific commit hash. All scope rules, analysis scripts, and output files are version-controlled.

2. **Obtain the CISA KEV feed.** Either use the live feed (results will reflect the catalog at fetch time) or download and archive a copy (for exact reproducibility).

3. **Run the counting script:**
   ```bash
   python3 scripts/build_kev_counts.py              # live feed
   python3 scripts/build_kev_counts.py kev.json      # local copy
   python3 scripts/build_kev_counts.py --as-of 2026-06-18  # reproduce a specific snapshot
   ```
   Output: `scripts/kev_edge_counts.json` with counts, CVE lists, and metadata including catalog version.

4. **Run enrichment:**
   ```bash
   python3 scripts/enrich_epss.py    # EPSS scores (point-in-time)
   python3 scripts/enrich_nvd.py     # CVSS, CWE, publication dates
   ```
   Output: `scripts/kev_edge_enriched.json`.

5. **Run analyses:**
   ```bash
   python3 scripts/analyze_cwe.py --format markdown
   python3 scripts/analyze_tte.py --format markdown
   python3 scripts/analyze_statistics.py --format markdown
   python3 scripts/analyze_patterns.py --format markdown
   ```

### 8.2 Reproducibility Guarantees and Limitations

**What is reproducible.** Given the same CISA KEV feed version and the same commit of this repository, `build_kev_counts.py` will produce identical counts. The scope rules are deterministic.

**What varies.** EPSS scores change daily. NVD/MITRE data may be updated (CVSS scores occasionally change, CWE assignments are revised). The CISA KEV feed grows over time. Running enrichment on different dates will produce different EPSS values.

**Version pinning.** The output JSON files record: catalog version (from CISA), generation timestamp (UTC), scope rules applied, and data source URLs. These metadata fields allow a reader to assess the freshness and provenance of any specific output file.

### 8.3 Dependencies

All scripts use **Python standard library only** (json, re, csv, urllib, math, statistics, collections, datetime, socket, time, argparse, os, sys, io, tempfile). No pip-installable packages are required. This eliminates dependency version as a reproducibility variable. Python 3.7+ is required.

---

## 9. Limitations

This section consolidates all known limitations, including those discussed above, into a single reference.

### 9.1 Fundamental Limitations (Not Correctable)

1. **Installed-base confound.** The count conflates code quality and market share. Per-install normalization would correct it, but install-base denominators are proprietary and unreliable. This is the most important limitation.

2. **Disclosure practice asymmetry.** Vendors that silently patch have systematically lower counts. Vendors that file granular CVEs have systematically higher counts. The direction of this bias (inflating transparent vendors, deflating opaque ones) is the opposite of what a naive consumer would infer.

3. **KEV selection pipeline opacity.** CISA's confirmation process for KEV inclusion is not publicly documented in detail. The latency from exploitation onset to catalog inclusion varies and is not measurable from public data.

4. **CVE-indexing blindness.** The entire methodology is blind to vulnerabilities without CVE identifiers. This includes silently patched bugs, bundled fixes, and firmware-only fixes without public advisories.

### 9.2 Methodological Limitations (Could Be Addressed with Additional Data)

5. **No per-install normalization.** If reliable install-base data were available, counts could be normalized. They are not, so we do not normalize.

6. **No exploitation volume data.** KEV records binary presence/absence of exploitation. Two CVEs -- one exploited against one target by a nation-state, another mass-exploited against thousands of targets by botnets -- receive equal weight. Exploitation volume data is not publicly available at CVE granularity.

7. **No patch-to-exploit timeline.** TTE is computed from NVD publication date, not from patch availability or vendor advisory date. The true defender-relevant timeline (patch available to exploitation observed) requires per-CVE advisory date collection, which is not automated in this pipeline.

8. **EPSS temporal mismatch.** EPSS scores are fetched at enrichment time, not at exploitation time. Historical EPSS scores would require FIRST.org's time-series API.

9. **Single-source confirmation.** KEV is the sole exploitation-confirmation source. Cross-referencing with VulnCheck KEV, Mandiant incident data, or Recorded Future exploitation intelligence would increase confidence but is outside the current scope.

### 9.3 Scope Limitations (By Design)

10. **Edge-only scope.** The methodology intentionally excludes endpoint, management, email, WAF, and infrastructure products. A vendor's total security posture includes these; the edge-only scope captures one (important) dimension.

11. **Thirteen vendors.** The dataset covers the major commercial edge vendors in the CISA KEV catalog, including WatchGuard (Firebox/Fireware) and Array Networks (ArrayOS) added in the 2026-06 expansion. Vendors still excluded (e.g., Barracuda's email-security gateway, pfSense/Netgate) have few or no *qualifying edge* KEV entries in the scope window, not because they are more secure.

12. **Bounded temporal window.** The 2020-2026 window captures a specific period. Pre-2020 exploitation (e.g., early Pulse Secure campaigns) is excluded. Post-window exploitation will require re-running the pipeline.

### 9.4 Statistical Limitations

13. **Small sample size.** With n=13 vendors, most statistical tests have limited power. The chi-squared test, HHI, and Gini coefficient are descriptive summaries, not definitive tests.

14. **No causal inference.** The observational design supports description and correlation only. No causal claims (e.g., "vendor X has worse code than vendor Y") are supported by this methodology.

15. **Multiple testing.** The analysis scripts compute multiple test statistics without formal multiple-comparison correction. Individual p-values should be interpreted cautiously.

---

## 10. Stance: Data, Not a Ranking

This methodology produces a count. It does not produce a ranking, a score, a verdict, or a recommendation. The count table is sorted by count descending for deterministic presentation -- a sort, not a judgment. The methodology is designed to make every assumption explicit, every judgment call transparent, and every number reproducible. Readers who disagree with a scope decision can change it and re-run. That editability is the point.

---

## Sources and Corrections

**Primary data sources:** CISA KEV catalog and Emergency Directives, FIRST.org EPSS API, NVD API 2.0, MITRE CVE Services API, Mandiant/GTIG Time-to-Exploit reports, VulnCheck 2026 State of Exploitation.

**Secondary sources (per-vendor narrative):** Vendor PSIRTs, Volexity, Mandiant, Rapid7, Tenable, watchTowr Labs, Talos Intelligence, Arctic Wolf, CISA advisories and Emergency Directives. Every factual claim in the README and per-vendor documentation carries an inline citation to a primary or named research source.

**Academic references:**
- Bozorgi, M. et al. (2010). "Beyond heuristics: learning to classify vulnerabilities and predict exploits."
- Bilge, L. and Dumitras, T. (2012). "Before we knew it: an empirical study of zero-day attacks in the real world."
- Jacobs, J. et al. (2021). "Exploit Prediction Scoring System (EPSS)." *Digital Threats: Research and Practice.*
- Suciu, O. et al. (2022). "Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits."
- arXiv:2006.15074 -- CVSS coverage gaps in vendor security advisories.
- arXiv:2405.01289 -- Exploitation timing models and survival analysis.

**Corrections welcome.** Open an issue with a primary source. Unconfirmed figures are flagged or excluded, never asserted -- the same standard we hold ourselves to.
