# Methodology

This repository ranks perimeter and edge security vendors by **demonstrated operator risk**, not by raw vulnerability counts. This document explains the ranking model, why raw counts mislead, the data we use, the limitations we acknowledge up front, and how to correct us.

Intellectual honesty is the point. Where a claim is derived reasoning rather than a published statistic, we say so. Where a figure could not be verified, we flag it rather than cite it.

---

## Why Raw Counts Mislead

The intuitive metric — "which vendor has the most CVEs / KEV entries?" — is confounded by two variables that have nothing to do with how secure a product is:

1. **Installed base.** More deployed units mean more researcher attention and more attacker ROI. Both produce more disclosed and more exploited vulnerabilities. Fortinet's count is inflated by a claimed 50%+ *unit* market share; Cisco's ~82 KEV entries span its entire product portfolio, not its firewalls.

2. **Researcher attention.** Popular, high-value targets get disproportionate scrutiny. A vendor can look "worse" simply because more capable people are looking at it.

A high count is therefore partly a *popularity tax*. To compare vendors fairly, you have to normalize for these confounders — and then look at the signals market share *cannot* explain.

---

## The Three Metrics That Actually Predict Risk

### 1. Per-unit KEV density

How many known-exploited vulnerabilities a vendor accrues **relative to its deployed footprint and product breadth**. This corrects the installed-base confounder: four pre-auth RCEs in a *single daemon* (Fortinet `sslvpnd`) or a single product line (Ivanti Connect Secure) is a stronger risk signal than a larger raw count spread across dozens of product families (Cisco).

> **Critical limitation:** Per-unit KEV density is **derived analytical reasoning, not a published statistic.** No authority publishes "KEVs per deployed device," and deployed-device counts are themselves estimates. Where we invoke density — including the observation that Juniper's profile *looks* dense relative to its share — we present it as a lens, never as a benchmark figure. Claims like "worst per-unit density" are explicitly labeled as reasoning, not fact.

### 2. Time from disclosure / PoC to mass exploitation

The window between a vulnerability becoming known and being weaponized at scale. This is the metric **market share cannot fake** — it measures how fast an operator must respond, independent of vendor popularity. Examples from this dataset:

- **Pre-patch zero-day** (worst case): Palo Alto CVE-2024-3400 (CVSS 10.0) was found *in active exploitation* before any patch; Ivanti's January 2024 chain was exploited before disclosure.
- **~8 days** advisory-to-mass-exploitation: Juniper's 2023 J-Web chain (advisory Aug 17 → watchTowr PoC + same-day exploitation Aug 25).
- **~24–48 hours** PoC-to-surge: Palo Alto's November 2024 CVE-2024-0012 + CVE-2024-9474 chain.
- **Same/next-day advisory + KEV**: Fortinet CVE-2024-21762 (advisory Feb 8 2024; CISA KEV Feb 9 2024 — within ~24h), a CISA signal that exploitation was already active.

### 3. Disclosure transparency + vendor-side security

Transparency is treated as a **security control**, because an operator's ability to triage depends on accurate, timely vendor information. We weigh:

- **Silent patching** — shipping a fix before (or without) an advisory. Fortinet's XORtigate (CVE-2023-27997) firmware shipped ~3–4 days before disclosure; researchers reverse-engineered the patch delta and reproduced the bug before customers were told it existed. This is the worst pattern in the dataset.
- **Patch distribution model** — firmware-only updates (no discrete security patches) deny operators the ability to assess and prioritize.
- **Accuracy of disclosure** — SonicWall's 5%→100% scope revision (held three weeks, no explanation) shows that disclosing *inaccurately* can be worse than disclosing late.
- **Disputed findings during active incidents** — Ivanti publicly disputed CISA's factory-reset persistence finding mid-crisis.
- **Vendor-side / management-plane security** — the infrastructure *around* the device is part of the attack surface. SonicWall's MySonicWall cloud backup breach and Palo Alto's Expedition credential store both converted vendor systems into pivots.

By contrast, Cisco's multi-agency coordinated disclosure of ArcaneDoor, with indicators released alongside patches, and its honest retroactive CVSS elevation, represent the model we score *favorably*.

---

## How the Three Combine Into a Ranking

There is no single weighted formula; combining three partly-qualitative signals into one number would imply false precision. Instead, placement reflects **risk concentration and recency**:

- A vendor rises when multiple metrics compound (SonicWall: mass exploitation **and** a vendor-side breach **and** inaccurate disclosure, within 12 months).
- Recurrence is weighted heavily (Ivanti and Cisco both had repeat critical-RCE events a year apart).
- Transparency failures are weighted as multipliers on technical risk, not standalone scores.

**Rank #6 (Fortinet) is not "safest."** It is last on demonstrated incident *impact within the review window*, while holding the worst transparency posture here. Ranking measures risk concentration, not a clean bill of health.

---

## Data Sources

- **[CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — the spine of "actually exploited" determinations.
- **[NVD](https://nvd.nist.gov/)** — CVE metadata and CVSS scores (cross-checked against vendor PSIRTs, since vendor and chain scores can differ).
- **Vendor PSIRT advisories** — Cisco, Palo Alto, Fortinet, Ivanti, Juniper, SonicWall.
- **[CISA Emergency Directives](https://www.cisa.gov/news-events/directives)** and alerts (e.g., ED 24-01 for Ivanti).
- **Independent research and reporting** — Cisco Talos, Mandiant / Google Threat Intelligence, watchTowr, Rapid7, Wiz, Volexity, Arctic Wolf, Huntress, Shadowserver, VulnCheck, BleepingComputer, The Hacker News, CyberScoop, Cybersecurity Dive.

Every factual claim in the README and vendor docs carries an inline source URL.

---

## Limitations We Acknowledge

1. **Per-unit density is derived, not published.** (Restated because it matters most.) Treat all density language as analytical reasoning.
2. **Market-share normalization is approximate.** Unit share ≠ revenue share; conflating them inflates perceived dominance (a trap we specifically flag in the Fortinet doc).
3. **Exposure counts vary by source and date.** Example: Juniper J-Web exposed instances are reported as ~8,200 (Shadowserver) and near 12,000 (Rapid7/VulnCheck) — we attribute each number to its source rather than picking one.
4. **Attribution is probabilistic.** Threat-actor attributions (UNC5221, UNC3886, UAT4356/STORM-1849, UTA0218) reflect vendor/government assessments, not courtroom proof.
5. **This is a bounded snapshot.** Vendor behavior changes; a poor record here is not a permanent verdict.
6. **Unverified figures are excluded, not cited.** The "~438,000 exposed SonicWall devices" figure could not be confirmed against any primary source and is flagged as unverified, not used as evidence.
7. **Ranking ≠ procurement advice.** We measure demonstrated incident risk and disclosure posture, not total product quality, support, or fit.

---

## Corrections Applied During Verification

This dataset was adversarially fact-checked. Notable corrections we *applied* (and that you should hold us to):

- **SonicWall — compromise count:** "100+ organizational compromises" was inflated. Arctic Wolf documented **over 30** Akira/Fog intrusions tied to CVE-2024-40766 (~75% Akira). We use the 30+ figure.
- **SonicWall — resurgence date:** The **July 2025** resurgence date is **correct** (Arctic Wolf's July 2025 uptick report). An earlier draft wrongly "corrected" it to August; the August events (Huntress 28/week, SonicWall <40) are the later peak. We restored July.
- **SonicWall — citation hygiene:** The 2024 Akira/Fog campaign is cited to Arctic Wolf's Fog/Akira SSL VPN reporting, not the cloud-backup-incident post.
- **Juniper — CVE-2025-21590 role:** Clarified that UNC3886 gained access via **stolen legitimate credentials**, then used CVE-2025-21590 (local, requires shell) for in-memory injection / Veriexec bypass — not for initial access.
- **Juniper — exposure count:** Both ~8,200 (Shadowserver) and ~12,000 (Rapid7/VulnCheck) figures are presented with attribution.
- **Cisco — implant mechanism:** Line Runner persistence is attributed to CVE-2024-20359 (disk0 write + VPN pre-load hook); CVE-2024-20353 supplied the controlled reboot step.
- **Fortinet — date consistency:** Harmonized CVE-2024-21762 to "advisory Feb 8 2024; CISA KEV Feb 9 2024 (next day)" across all references.

---

## Corrections Welcome

This is a security-education resource and we would rather be accurate than confident. If you find a wrong figure, a stale source, a misattributed citation, or a derived claim presented as fact:

- **Open an issue** with the specific claim and a **primary source** (CISA, NVD, vendor PSIRT, or named first-party research).
- Corrections that flip a fact will be reflected in the affected vendor doc and credited.
- Unverifiable figures will be flagged as unverified rather than silently included — the same standard we hold ourselves to with the SonicWall device-count claim.
