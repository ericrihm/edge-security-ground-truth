# Documentation Index

A navigational guide to all research, analysis, and reference material in this repository.

---

## Start Here

| Document | Description |
|----------|-------------|
| [README](../README.md) | Project overview, methodology summary, and KEV counts by vendor |
| [Executive Summary](EXECUTIVE-SUMMARY.md) | State of Edge Security 2026 — key findings for decision-makers |
| [The Numbers](THE-NUMBERS.md) | High-signal statistics: counts, rates, and ranked comparisons at a glance |

---

## Research

| Document | Description |
|----------|-------------|
| [Methodology](../METHODOLOGY.md) | Data sources, scope decisions, KEV attribution rules, and reproducibility notes |
| [Statistics](STATISTICS.md) | Statistical analysis of CISA KEV edge-appliance exploitation trends |
| [Market-Share Sensitivity](MARKET-SHARE-SENSITIVITY.md) | How deployment share distorts raw KEV counts and what the normalized rates reveal |
| [Related Work](RELATED-WORK.md) | Prior art, academic references, and vendor reports this dataset builds on or diverges from |

---

## Analysis

| Document | Description |
|----------|-------------|
| [CWE Analysis](CWE-ANALYSIS.md) | Which weakness classes keep appearing in exploited edge devices, and why they persist |
| [Time-to-Exploit](TIME-TO-EXPLOIT.md) | Measured lag between CVE disclosure and in-the-wild exploitation across vendors |
| [Cross-Vendor Patterns](ANALYSIS.md) | Structural patterns in vulnerability classes, disclosure behavior, and exploitation timelines |
| [Vendor Matrix](VENDOR-MATRIX.md) | Side-by-side comparison of all 11 vendors across KEV count, CVSS, CWE class, and patch lag |

---

## Threat Intelligence

| Document | Description |
|----------|-------------|
| [Threat Actors](THREAT-ACTORS.md) | Nation-state and criminal groups documented targeting edge appliances, with TTPs |
| [Threat Attribution](THREAT-ATTRIBUTION.md) | CVE-level attribution mapping: which actors exploited which vulnerabilities |

---

## Psychology and Decision-Making

| Document | Description |
|----------|-------------|
| [Cognitive Biases](COGNITIVE-BIASES.md) | Seven cognitive biases that distort vendor selection and patch-prioritization decisions |
| [What-If Scenarios](WHAT-IF-SCENARIOS.md) | Counterfactual risk analysis: what your exposure profile looks like under a different vendor choice |

---

## Practical

| Document | Description |
|----------|-------------|
| [Defender Playbook](DEFENDER-PLAYBOOK.md) | Operational guidance for edge appliance security: detection, response, and hardening |
| [Vendor Questions](VENDOR-QUESTIONS.md) | 20 data-driven questions to ask your edge vendor before signing or renewing |

---

## Vendor Profiles

Each profile covers KEV-listed CVEs in full, exploitation timeline, patch behavior, and threat actor activity.

| Vendor | KEV Entries | Document |
|--------|-------------|----------|
| Fortinet (FortiGate) | 18 | [Fortinet.md](Fortinet.md) |
| Ivanti (Connect Secure / Pulse) | 13 | [Ivanti.md](Ivanti.md) |
| Cisco (ASA / FTD) | 13 | [Cisco.md](Cisco.md) |
| Citrix (NetScaler ADC / Gateway) | 11 | [Citrix.md](Citrix.md) |
| Palo Alto Networks | 12 | [PaloAlto.md](PaloAlto.md) |
| SonicWall | 12 | [SonicWall.md](SonicWall.md) |
| F5 (BIG-IP) | 6 | [F5.md](F5.md) |
| Sophos Firewall | 6 | [Sophos.md](Sophos.md) |
| Zyxel | 6 | [Zyxel.md](Zyxel.md) |
| Juniper Networks | 4 | [Juniper.md](Juniper.md) |
| Check Point | 2 | [CheckPoint.md](CheckPoint.md) |

---

## Interactive Visualizations

Standalone HTML files — open in any browser, no server required.

| File | Description |
|------|-------------|
| [edge-kev-chart.html](../assets/edge-kev-chart.html) | KEV counts by vendor over time, interactive bar/timeline chart |
| [cwe-heatmap.html](../assets/cwe-heatmap.html) | CWE weakness-class heatmap across vendors and years |
| [tte-explorer.html](../assets/tte-explorer.html) | Time-to-exploit explorer: disclosure-to-exploitation lag by CVE |
