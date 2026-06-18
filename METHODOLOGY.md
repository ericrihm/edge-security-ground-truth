# Methodology

This repository presents **reproducible, cited exploitation data** for perimeter & edge security vendors and lets readers draw their own conclusions. **It does not rank vendors.**

> **Data, not a ranking.** An earlier version of this repo assigned a subjective 1–6 "risk rank" that mixed incomparable signals into a single editorial verdict. We removed it. What remains is one reproducible count and a set of individually‑sourced facts. Your threat model decides which matter.

---

## 1. Why raw CVE counts are not a valid comparison metric

Four documented failures:

1. **Incomplete attack‑surface coverage** — a count ignores *where* the bugs are.
2. **No contextual risk** — only ~2% of CVEs are ever exploited in the wild ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [EPSS](https://www.first.org/epss/)).
3. **Vendor disclosure‑policy differences** — open‑source files a CVE per fix and inflates counts; closed‑source bundles or ships silently, so a *higher* count can reward opacity.
4. **Large data‑quality variance** — 35–82% of vendor reports lack a CVSS score ([arXiv:2006.15074](https://arxiv.org/abs/2006.15074), [xmcyber](https://xmcyber.com/blog/your-cve-count-is-a-meaningless-metric/)).

A second confounder — installed base / researcher attention (a "popularity tax") — compounds all four, and the fair correction (per‑install normalization) is not reliably computable, so we do not fake it.

---

## 2. Frameworks this is grounded in

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — authoritative exploited‑in‑the‑wild set; our gating filter (measure exploited, not total).
- **[EPSS](https://www.first.org/epss/)** (FIRST.org) — ML probability of exploitation within 30 days; a supporting indicator (CVE‑only, can lag).
- **[Mandiant / GTIG Time‑to‑Exploit](https://cloud.google.com/blog/topics/threat-intelligence)** — days from disclosure to first observed exploitation; 2024 average **−1 day**, and 44% of 2024 zero‑days hit security/edge appliances. Academic corroboration: [arXiv:2405.01289](https://arxiv.org/abs/2405.01289).
- **[VulnCheck 2026 State of Exploitation](https://www.vulncheck.com/blog/network-edge-device-report-2026)** — the edge is the primary exploitation battleground (why we scope to edge).

---

## 3. What we measure

**Primary metric — exploited edge‑CVE count (reproducible).** The number of CISA‑KEV‑listed CVEs affecting each vendor's edge appliance (firewall / SSL‑VPN / remote‑access gateway), by KEV `dateAdded` within **2020‑01‑01 → 2026‑06‑16**. It is computed by [`scripts/build_kev_counts.py`](./scripts/build_kev_counts.py) directly from the CISA feed under one documented include/exclude scope rule applied uniformly to every vendor. The script + the public feed make every count **reproducible**, and the scope rule is editable and re‑runnable.

**Supporting signals — presented as cited per‑vendor facts, not aggregate scores.** Time‑to‑exploit / zero‑day status, pre‑auth RCE history, documented silent‑patching, and vendor‑side breaches each require per‑CVE and per‑incident interpretation. Rolling them into uniform count columns would imply a precision the underlying judgments don't support and invite exactly the apples‑to‑oranges comparison this repo exists to avoid. So we present them as **individually‑sourced statements** (in the [README](./README.md) and per‑vendor docs), each cited to first‑party or named research — never combined into a single number.

---

## 4. The scope rule (a judgment call, made transparent)

**Edge appliance = an internet‑facing firewall, SSL‑VPN, or remote‑access gateway.** Excluded: endpoint / MDM (e.g. MobileIron, EPMM, FortiClient), management appliances (FortiManager, Expedition, Ivanti EPM/CSA), email security, WAF (FortiWeb), load balancers, and switch/router/IOS products. The exact per‑vendor include/exclude regex lives in [`scripts/build_kev_counts.py`](./scripts/build_kev_counts.py). **If you scope differently, edit the rule and re‑run** — the numbers move accordingly, and that transparency is the point. The window is keyed to KEV `dateAdded` (the date CISA confirmed exploitation).

Consequences worth stating plainly: SonicWall's count spans firewall **and** SMA remote‑access (two product families); Cisco is **ASA/FTD only** (its portfolio‑wide KEV total, ~80+, is *not* attributed to its firewalls); Palo Alto excludes the Expedition migration tool.

---

## 5. Limitations

1. **Per‑install‑base normalization is not reliably computable** — install‑base figures are proprietary/estimated and conflate unit vs. revenue share. We publish no normalized score and fabricate none. *The most important limitation: the raw count still partly reflects popularity.*
2. **KEV and EPSS are CVE‑only** — silently‑fixed, bundled, or un‑CVE'd bugs are invisible, understating exposure for weak‑disclosure vendors.
3. **Attribution is probabilistic** (UNC5221, UNC3886, UAT4356, UTA0218 = assessments, not proof).
4. **Bounded window** (2020‑01‑01 → 2026‑06‑16); exposure/incident figures vary by source and date and are attributed, never averaged.

---

## 6. Stance: this is data, not a ranking

We assign no overall rank, weight nothing into one number, and name no "worst." A pre‑auth RCE zero‑day and a vendor‑side cloud breach are different *kinds* of risk; which matters more depends on your deployment. The KEV table is **sorted by count for deterministic presentation — a sort, not a verdict.** Re‑sort, re‑scope, and weigh the cited facts yourself.

---

## Sources & corrections

Primary sources: CISA KEV catalog & Emergency Directives, FIRST.org EPSS, Mandiant/GTIG TTE, VulnCheck 2026, NVD, vendor PSIRTs, and named research (Volexity, Mandiant, Rapid7, Tenable, watchTowr, Talos, Arctic Wolf). Every factual claim in the README and per‑vendor docs carries an inline citation.

**Corrections welcome.** Open an issue with a primary source. Unconfirmed figures are flagged or excluded, never asserted — the same standard we hold ourselves to.
