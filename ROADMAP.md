# ROADMAP — Edge Security Ground Truth

> Reproducible CISA-KEV edge-appliance exploitation dataset. This roadmap is the single source of truth for what to fix, what to build, and how to become the field-leading reference for edge-device exploitation.

---

## Session status — 2026-06-18 (crash recovery + expansion)

**Shipped** (commits `2cc1239` → `ac3b43c`):
- ✅ Recovered the crashed session's uncommitted work (interactive explorers, bias/what-if/numbers docs, threat-actor schema, INDEX).
- ✅ **P0 correctness** — fixed the critical `analyze_tte.py --no-fetch` reproducibility bug (was emitting "0 vendors"); Fortinet zero-days 5→7; stale per-vendor ransomware counts; atomic counts-write; 5 dead links. *(CVE-2026-24858 ransomware flag left `N` — live CISA confirms `Unknown`; the audit's flip suggestion was refuted.)*
- ✅ **Dataset expanded to 13 vendors / 115 CVEs** — added WatchGuard (4) + Array Networks (2); fixed the Citrix `^NetScaler$` undercount (11→13). The two falsified METHODOLOGY invariants corrected. Spread unchanged at **2–18** (core thesis reinforced, not overturned). New cited vendor docs authored.
- ✅ **Numbers propagated** through ~25 docs: χ²(12)=33.65 p=0.0008, 38 zero-days, 47 ransomware (41%), median TTE 36d.
- ✅ **P1 statistical hardening** — exact conditional-binomial pairwise tests (only 2/78 survive Bonferroni), quasi-Poisson overdispersion-adjusted trend SE (z 6.13→3.47, still significant), per-(vendor,CWE) Fisher exact + Bonferroni.

**Still open** (details in P2 / North Star below):
- ⏳ Regenerate `assets/edge-kev-chart.png` — still renders 11 bars (alt text + data updated; PNG needs a re-render).
- ⏳ README tail dedupe — the second "Analysis tools"/"Deep-dive documents" sections (P2-3).
- ⏳ `daily-kev-sync.yml` runs only the counter, not enrichment (P2-2). Pipeline-order bug: `enrich_nvd.py --skip-existing` strips the KEV-metadata fields, so `enrich_kev.py` must run **last** (or `enrich_nvd` be made field-preserving).
- ⏳ CI correctness gates (P2-1), Zenodo DOI + Croissant (P2-6), and the North-Star research program.

---

## 1. Executive Summary

**Current state (honest).** The repo is already strong for a public threat-intel dataset: 107 CVEs across 11 vendors, an internally-consistent core stat block (36 zero-days, 43% ransomware, chi² p=0.020, median TTE 40d), a reproducible KEV counter (`scripts/build_kev_counts.py`), an HTML TTE explorer that exactly matches the CVE list, transparent scope rules, and named confounds. It is methodologically *above* the industry baseline (VulnCheck/Eclypsium/runZero all ship raw counts with no normalization and no significance testing). It already has a `CITATION.cff` and two GitHub Actions (`daily-kev-sync.yml`, `validate.yml`).

**But the project's entire value proposition is the word "reproducible," and the flagship reproducibility path is broken.** `scripts/analyze_tte.py --no-fetch` — the documented offline path (README line 20) — silently emits `"107 edge CVEs analyzed across 0 vendors"` and zero TTE data, because it reads `dateAdded` only from the live-fetch lookup and never falls back to the enriched JSON that already has every value. Anyone who clones the repo and runs the offline command gets garbage and concludes the dataset doesn't reproduce.

**The single most important thing to fix: the `analyze_tte.py --no-fetch` fallback (REPRO-001).** It is a one-line change, it is verdict-`confirmed`, and it is the difference between "reproducible" being true and being a lie. Everything else in P0 is credibility hygiene; this one is existential.

Second-order theme: the repo has **count-correctness drift** (Fortinet zero-day count, per-vendor ransomware counts, two missing in-scope vendors, two missing Citrix CVEs from a CISA product-name change). For a "ground truth" artifact, every published number must equal what the build script produces. Several do not.

---

## 2. P0 — Correctness & Integrity (must-fix)

*Only verdict `confirmed` / `partial` findings. These protect the repo's credibility. Refuted/overstated items are footnoted at the end of this section.*

### P0-1 · REPRO-001 — `analyze_tte.py --no-fetch` outputs "0 vendors" (CRITICAL, verdict: confirmed)
- **What.** The documented offline/reproducible path produces all-zero TTE output. `load_data` reads `kev_date_str = kev_entry.get("dateAdded")` from the live lookup (`scripts/analyze_tte.py:141`); with `--no-fetch`, `kev_lookup={}`, so all 107 CVEs get `tte_days=None`, `vendor_tte` stays empty, and the markdown header reads `**107** edge CVEs analyzed across 0 vendors.`
- **Evidence.** Verified at `scripts/analyze_tte.py:138/141/144`. All 107 CVEs in `scripts/kev_edge_enriched.json` already have `kev_date_added`, `published`, and `kev_due_date` populated (0 missing). Patched run restores `n=107`, `vendor_tte=11`, full histogram, matching the documented "107 CVEs across 11 vendors."
- **Exact fix.** At line 141: `kev_date_str = kev_entry.get("dateAdded") or cve_data.get("kev_date_added")`. At line 144: `due_date = parse_date(kev_entry.get("dueDate") or cve_data.get("kev_due_date"))`.
- **Effort.** Trivial. **Automatable now.** Add a CI assertion (P2) that `--no-fetch` yields `vendor_tte==11`.

### P0-2 · GAP-03 — Citrix undercounted by 2; CISA product-name drift to bare "NetScaler" (HIGH, verdict: confirmed)
- **What.** `CVE-2025-7775` (2025-08-26, memory-overflow RCE/DoS) and `CVE-2026-3055` (2026-03-30, OOB read as SAML IDP) have `vendorProject="Citrix"`, `product="NetScaler"` (bare) in the live feed. The Citrix include regex (`scripts/build_kev_counts.py:42`) requires `NetScaler ADC|NetScaler Gateway|Citrix ...|Application Delivery Controller`, so bare `NetScaler` fails and both are dropped. Citrix should be **13**, not 11.
- **Evidence.** Reproduced against live KEV (catalogVersion 2026.06.18). Exactly two bare-`NetScaler` products exist; the fix captures precisely these two with no over-capture.
- **Exact fix.** Add `|^NetScaler$` to the Citrix include pattern (anchored, verified safe). Re-run `build_kev_counts.py`, regenerate `kev_edge_enriched.json`, add both CVEs to `docs/Citrix.md` (CVE-2025-7775 CWE-119, CVE-2026-3055 CWE-125), and update README / VENDOR-MATRIX / all derived stats (107→109, vendor totals, chi²).
- **Effort.** Small (re-derivation cascade). **Automatable** for the regex + rebuild; **human-judgment** for the doc prose in Citrix.md.

### P0-3 · GAP-01 — WatchGuard Firebox/XTM entirely absent (4 in-scope KEV entries) (HIGH→see note, verdict: confirmed)
- **What.** WatchGuard Firebox (SSL-VPN + firewall appliance, identical role to Fortinet/Sophos/Check Point) has 4 qualifying in-scope, in-window KEV entries and is not in the dataset. `METHODOLOGY.md:495` falsely says WatchGuard has "few or no qualifying KEV entries" — it has *more* (4) than the included Check Point (2).
- **Evidence.** Live-feed-verified: `CVE-2022-26318` (unauth RCE), `CVE-2022-23176` (priv-esc via mgmt session, Cyclops Blink/Sandworm anchor), `CVE-2025-9242` (Firebox iked OOB-write pre-auth RCE), `CVE-2025-14733` (Fireware iked OOB write). Proposed regex captures exactly these 4.
- **Exact fix.** Add WatchGuard as the 12th vendor: in `scripts/build_kev_counts.py` SCOPE dict add `include=r"Firebox|XTM|Fireware"`, `exclude=r"AuthPoint|Endpoint"`. Create `docs/WatchGuard.md`, add to README table, `VENDOR-MATRIX.md`, and rebuild all stats. Note: this is a **coverage** gap, not an error in the existing 11 vendors' published numbers; it *reinforces* the core "2–18 spread, no vendor dramatically cleaner" thesis. Treat as P0 because `METHODOLOGY.md:495`'s exclusion rationale is factually false.
- **Effort.** Medium (new vendor doc + re-derivation). **Human-judgment** (vendor doc authoring + attribution verification).

### P0-4 · GAP-02 — Array Networks AG/vxAG entirely absent (2 in-scope KEV entries) (HIGH, verdict: confirmed)
- **What.** Array Networks AG/vxAG (CISA's own words: "SSL VPN gateway") has 2 qualifying in-scope KEV entries and is absent. This directly **falsifies `METHODOLOGY.md:153`** which asserts "No vendor with qualifying KEV entries was excluded."
- **Evidence.** Live-verified: `CVE-2023-28461` (2024-11-25, missing-auth file-read+code-exec on SSL-VPN gateway, ransomware=Known, CWE-306) and `CVE-2025-66644` (2025-12-08, OS command injection, CWE-78). Exactly 2 Array entries exist.
- **Exact fix.** Add Array Networks as a vendor (the **12th** alongside the existing 11; combined with WatchGuard, the dataset goes to 13 vendors). Robust matcher: `include=r"ArrayOS|AG/vxAG|vxAG"` (live product strings are `"AG/vxAG ArrayOS"` and `"ArrayOS AG"`). Create `docs/ArrayNetworks.md`, rebuild, fix `METHODOLOGY.md:153` and `:495`.
- **Effort.** Small–medium. **Human-judgment** (doc + the China-nexus attribution claim is unverified offline — carry as a supporting anchor, not reproduced evidence).

### P0-5 · DATA-001 — Fortinet.md says "5 confirmed zero-days"; actual is 7 (HIGH, verdict: confirmed)
- **What.** `docs/Fortinet.md:32` and `:180` say 5; the canonical logic (`analyze_tte.py`: zero-day iff in `KNOWN_ZERO_DAYS` OR TTE≤0) gives 7. `docs/TIME-TO-EXPLOIT.md` and `docs/VENDOR-MATRIX.md` both already say 7. Fortinet.md is the internally-inconsistent outlier. Two CVEs are mis-marked `N` in its KEV table: `CVE-2021-44168` (TTE=−25d, line 16) and `CVE-2023-27997` (TTE=0d, watchTowr/Lexfo silent patch, line 23).
- **Exact fix.** `docs/Fortinet.md`: change `:32` and `:180` "5"→"7"; flip the Zero-Day column `N`→`Y` for CVE-2021-44168 (line 16) and CVE-2023-27997 (line 23).
- **Effort.** Small. **Automatable** (sed) with review.

### P0-6 · DATA-002 — Stale per-vendor ransomware counts in VENDOR-MATRIX.md & TIME-TO-EXPLOIT.md (HIGH, verdict: confirmed)
- **What.** Live truth (`ransomware=="Known"`): Ivanti=8, SonicWall=7, Palo Alto=5. Both docs show stale Ivanti=5, SonicWall=6, PAN=4. The headline total "46 ransomware CVEs" is correct; only the per-vendor breakdown drifted, which is the subtle, credibility-damaging kind.
- **Exact fix.** In `docs/VENDOR-MATRIX.md` (table + narrative headers "Ivanti (…5 ransomware)", "Palo Alto Networks (…4 ransomware)") and `docs/TIME-TO-EXPLOIT.md` ransomware table (~lines 277–286): Ivanti 5→8, SonicWall 6→7, PAN 4→5. Verify: `python3 -c 'import json;d=json.load(open("scripts/kev_edge_enriched.json"));print({v:sum(1 for c,e in cv.items() if e.get("ransomware")=="Known") for v,cv in d.items() if v!="_metadata"})'`.
- **Effort.** Small. **Automatable** with the verify command as a CI guard.

### P0-7 · LINK-001 — Dead CyberScoop URL ("ortinet" typo) in 5 places (MEDIUM, verdict: null→treat as confirmed, mechanically verified)
- **What.** `cyberscoop.com/ortinet-zero-day-cve-2026-24858-...` (missing leading "f") appears 5× — `docs/Fortinet.md` ×4 and `README.md` ×1 (count re-verified this session).
- **Exact fix.** `sed -i '' 's|cyberscoop.com/ortinet-zero-day|cyberscoop.com/fortinet-zero-day|g' docs/Fortinet.md README.md`
- **Effort.** Trivial. **Automatable now.** (Add a link-check step in `validate.yml` — P2.)

### P0-8 · DATA-003 — Fortinet KEV table marks CVE-2026-24858 as NOT ransomware (N) but enriched + CISA say Known (MEDIUM, verdict: null, claimed conf 0.9)
- **What.** `docs/Fortinet.md` row for CVE-2026-24858 has ransomware column `N`; `kev_edge_enriched.json` and the CISA catalog both flag `knownRansomwareCampaignUse="Known"`.
- **Exact fix.** Flip the last column `N`→`Y` for the CVE-2026-24858 row. Confirm Fortinet ransomware total (12) is unaffected (it is the count that's authoritative).
- **Effort.** Trivial. **Automatable** with review. *(Re-verify against live CISA before flipping — verdict was not adversarially confirmed.)*

### P0-9 · REPRO-002 — `kev_edge_counts.json` corruptible to single-vendor output (MEDIUM, verdict: null)
- **What.** During the audit, `scripts/kev_edge_counts.json` was overwritten with Citrix-only data (31 lines vs 198). Full rebuild regenerates correctly (all 11 vendors). The on-disk file is fragile to interrupted/partial writes.
- **Exact fix.** In `build_kev_counts.py`, write atomically and only after all vendors processed: build the full dict in memory → write to a temp file → `os.replace()`. Add a CI assertion in `validate.yml` that the output has exactly the expected vendor-key count (≥11, soon 13).
- **Effort.** Trivial. **Automatable now.**

### P0-10 · DATA-004 — `KNOWN_ZERO_DAYS` missing CVE-2022-40684 & CVE-2021-44168 (LOW, verdict: null, conf 0.95)
- **What.** Both Fortinet CVEs have negative TTE so they're already counted as zero-days via the threshold path, but they're absent from the explicit `KNOWN_ZERO_DAYS` dict in `analyze_tte.py`. Fortinet.md prose calls CVE-2022-40684 "a true zero-day" — confusing for maintainers. Documentation-consistency, **no output change**.
- **Exact fix.** Add both to `KNOWN_ZERO_DAYS` with `source` notes (private notifications / KEV-precedes-NVD). Verify computed output is byte-identical before/after.
- **Effort.** Trivial. **Automatable** with a no-change-to-output assertion.

> **Refuted / overstated (do NOT action as bugs):**
> - **STAT-02** (market-share chi² E<5) — verdict **partial / downgraded to MEDIUM**. The E<5 cell-count violation is real, but a Monte-Carlo exact test reproduces the same "strongly reject" verdict (p≈0.0005 / ~0 / ~0). **No conclusion is invalid.** Fix is documentation hygiene only (note the violation, cite the exact-test p-value) — moved to P1, not P0.
> - **STAT-01** (pairwise 2×2 double-counting) — confirmed defect but **0 significance-decision flips at α=0.05** on this data; downgrade to MEDIUM. The shipped pairwise tests are wrong-by-construction and must be fixed (P1), but no published conclusion changes.
> - **GAP-01 severity** corrected high→medium (coverage gap, not an error in existing numbers) — retained in P0 here only because it falsifies a stated methodology invariant.

---

## 3. P1 — High-Value Rigor & Coverage Upgrades

*Methodology hardening, coverage, and missing analytical dimensions. Grounded in the 2026 SOTA: every major edge report (VulnCheck, GTIG, GreyNoise, Eclypsium, runZero KEVology) ships **raw counts with no normalization and no significance testing** — that gap is exactly where this repo can lead.*

### Statistical rigor (clears the peer-review bar that industry reports do not)
- **P1-1 · STAT-01 — Fix pairwise vendor tests.** Replace the `[[ci, N−ci],[cj, N−cj]]` table (effective n=2N=214, double-counts every CVE) at `analyze_statistics.py:367–383` with a **conditional binomial** (`Binom(n=ci+cj, k=ci)` testing p=0.5) or Fisher's exact. Flag the 3 pairs with E<5 (Check Point vs F5/Sophos/Zyxel). *Small.*
- **P1-2 · STAT-04 — Quasi-Poisson / negative-binomial trend SE.** `STATISTICS.md:135` already admits overdispersion (2020 spike=19). Compute dispersion φ and multiply SE by √φ (z drops ~5.5→~2.5–3.5, still significant, correctly stated). Document in `STATISTICS.md`. *Small.* **The negative-binomial GLM is the SOTA-recommended framework for overdispersed CVE counts (arXiv:2604.16038).**
- **P1-3 · STAT-08 — Formal CWE systemic tests + Bonferroni.** Add a "Statistical Significance of Recurring Weaknesses" section to `CWE-ANALYSIS.md`: one-sided Fisher exact per vendor-category vs rest, Bonferroni α=0.00076 (66 tests). Result: **only Juniper auth (p=0.0005) survives**; Fortinet auth (p=0.082) does not. Downgrade "severe systemic" language accordingly. *Medium.*
- **P1-4 · STAT-02 + STAT-03 — Market-share doc hygiene.** Add the E<5 note + Monte-Carlo exact-test confirmation to `MARKET-SHARE-SENSITIVITY.md` §4. Add a log-log elasticity model (β with 95% CI) to test the sublinear-saturation assumption the doc already asserts (§3/§5), and a Monte-Carlo over analyst market-share intervals (Fortinet 32–50%) instead of three point estimates. *Medium.*
- **P1-5 · STAT-05/06/07 — TTE framing & internal consistency.** (a) Label the two zero-day tables in `TIME-TO-EXPLOIT.md` distinctly ("Zero-Days (TTE≤0 only)" =26 vs "TTE≤0 + incident-confirmed" =36). (b) Change "Unambiguously yes" → "Yes, with caveats for pre-2021 entries" and add the KEV-backfill-latency caveat for 2014–2019. (c) Reframe TTE as "upper bound on **CISA-confirmation latency**, not attacker speed" (cite CVE-2024-3400's 19-day pre-disclosure window). *Trivial each.*
- **P1-6 · STAT-10/11/12 — Selection bias, partial-year, citations.** Document the survivorship caveat (population = "vendors with ≥1 qualifying KEV," list zero-count vendors evaluated). Annualize or exclude partial-2026 from the Poisson trend (report both ways). Fix RELATED-WORK.md citations: Spring et al. 2023→2024, reattribute the 35–82% CVSS-coverage figure from Dong et al. 2019 to **Anwar et al. 2020 (arXiv:2006.15074)**. *Trivial–small.*

### Coverage (close the gaps after P0 vendors land)
- **P1-7 · GAP-04 — F5 CVE-2021-22986 scope edge case.** F5 exclude `BIG-IQ|NGINX` drops `CVE-2021-22986` (product="BIG-IP and BIG-IQ Centralized Management", ransomware=Known) even though exploitation is via the **BIG-IP iControl REST** API. **Human judgment required:** decide whether BIG-IQ-combined products are in-scope, then anchor the regex (`^BIG-IQ`) or allowlist the CVE; add a scope comment. *Trivial code, real decision.*
- **P1-8 · GAP-05 — Ivanti Sentry boundary.** `CVE-2023-38035` + `CVE-2026-10520` (pre-auth root RCE, BOD 26-04). Sentry is an internet-facing MDM gateway, currently silently excluded. Make an **explicit documented** include/exclude decision in `METHODOLOGY.md`. *Small, human judgment.*

### Missing analytical dimensions (turn the dataset from descriptive into operational)
- **P1-9 · GAP-06 — MITRE ATT&CK technique mapping.** Zero T-numbers in 27 docs (DEFENDER-PLAYBOOK's "T4356" is an actor ID, not a technique). Add `mitre_attack_techniques` to enriched JSON via `scripts/enrich_attack.py` (CWE/exploitation-type → T1190 Exploit Public-Facing App, T1133 External Remote Services, T1212, T1068). Add `MITRE-ATTACK.md`. **High value: only 424/1488 CISA KEVs have ATT&CK mappings (runZero KEVology) — this makes the dataset directly SOC-consumable.** *Large.*
- **P1-10 · GAP-09 — EOL/EOS status per CVE.** Add `eol_at_kev_date` boolean; populate known cases (CVE-2015-7755 ScreenOS, CVE-2020-29574 CyberoamOS, CVE-2020-15069 XG v17.x). Add `EOL-EXPOSURE.md`. **Operationalizes VulnCheck's 42.5%-of-edge-CVEs-hit-EOL finding and CISA BOD 26-02's Feb-2026 EOL-decommission mandate — a regulatory-relevant figure CISA itself has no public baseline for.** *Medium.*
- **P1-11 · GAP-08 — CISA Emergency Directives as structured data.** Add `cisa_emergency_directive` field. Document **ED 25-03** (Cisco ASA/FTD, CVE-2025-20333+CVE-2025-20362 ArcaneDoor follow-on) in `docs/Cisco.md` (currently absent). Add an ED column to VENDOR-MATRIX and a `CISA-EMERGENCY-DIRECTIVES.md` (ED 24-01 Ivanti, ED 25-03 Cisco). *Trivial–small.*
- **P1-12 · GAP-11 / GAP-10 — `pre_auth` flag + patch cadence.** Add `pre_auth` boolean (only 32% of CISA KEVs enable unauth remote initial access per KEVology — a strong prioritization signal) and `patch_date`/`patch_cadence_days` (negative = silent patch, e.g. CVE-2023-27997, CVE-2022-30525 — the primary signal for the vendor-transparency dimension). *Small / medium.*
- **P1-13 · GAP-07 — Shodan/Censys exposure counts.** Optional `scripts/enrich_exposure.py` (Censys Academic / Shodan academic tier) storing `exposure_count_*` + `query_date`. Enables per-install normalization (see North Star). Static fallbacks from published CISA/Censys advisories acceptable. *Large.*

---

## 4. P2 — Presentation, Distribution & Polish

- **P2-1 · `validate.yml` correctness gates.** Add CI assertions that lock the P0 fixes: (a) `analyze_tte.py --no-fetch` yields `vendor_tte == <vendor count>`; (b) `kev_edge_counts.json` has the expected vendor-key count; (c) per-vendor ransomware counts match `kev_edge_enriched.json`; (d) a markdown link-checker over `README.md` + `docs/` (catches the next "ortinet"); (e) doc-vs-script stat parity (Fortinet zero-days=7, etc.). **Automatable now.**
- **P2-2 · Daily sync completeness.** `daily-kev-sync.yml` runs only `build_kev_counts.py --format json` — it updates counts but **never re-enriches `kev_edge_enriched.json`**, so enrichment drifts as new CVEs land. Add `enrich_kev.py`/`enrich_nvd.py`/`enrich_epss.py` to the workflow (or a weekly enrichment job) + auto-PR on diff. **Automatable now.**
- **P2-3 · README dedupe + INDEX completeness.** Audit `docs/INDEX.md` for all 27 docs (and the new vendor docs). Single-source the headline stat block (107→109, vendor count 11→13) so it isn't restated divergently across README/EXECUTIVE-SUMMARY/THE-NUMBERS.
- **P2-4 · Machine-readable API surface.** Publish `kev_edge_enriched.json` + a flat CSV as versioned release assets; document the schema (one row per CVE, all enrichment fields). This is the artifact downstream researchers cite.
- **P2-5 · Interactive explorer wiring.** Wire the HTML TTE explorer + CWE heatmap (`assets/`) to the regenerated data and link from README; add the new vendors.
- **P2-6 · Zenodo DOI + badges.** Mint a Zenodo DOI (USENIX Sec '26 mandates permanent artifact archival — Zenodo is the recommended host), wire `CITATION.cff` to it, add a **Croissant** (`croissant.json`) metadata file — the MLCommons standard adopted by HF/Kaggle that even CVEfixes lacks. Add badges: DOI, CI status, last-KEV-sync date, CVE/vendor counts.

---

## 5. North Star — The Field-Leading Edge-Exploitation Reference

**The thesis.** Every 2026 SOTA source (Mandiant M-Trends, GTIG, Verizon DBIR, GreyNoise, VulnCheck, Eclypsium) agrees edge/perimeter devices are the **#1 exploitation category** (8× jump to 22% of exploitation breaches; mean TTE now **negative**). Yet **no public, peer-review-grade, edge-device-specific, reproducible dataset exists** — VulnCheck is commercial/opaque, EPSS has no device-class breakdown, and the academic datasets (VulZoo, CVEfixes, CVE-Bench) have *zero* edge categorization. CISA BOD 26-02 (Feb 2026) created immediate regulatory demand for exactly this artifact. **This repo is positioned to be the first citable, vendor-neutral ground truth for the device class.**

**Pillar 1 — Living dataset + KEV-watch (the moat).** Daily auto-sync that detects new in-scope edge KEVs, opens a PR with enrichment pre-filled, and posts a diff. The reproducibility infrastructure (versioned snapshots + atomic builds + CI parity gates) is the durable advantage industry reports lack. *Effort: medium; mostly P0-9 + P2-1/P2-2 compounded.*

**Pillar 2 — Defensible, peer-review-grade methodology (the credentialing).** Land P1-1..P1-6, then build **per-install-normalized cross-vendor comparison** — the single biggest open gap in the field. Negative-binomial GLM with installed-base denominators (IDC/Gartner/Shodan census) reporting rate ratios with 95% CIs, plus a **Bayesian hierarchical rate model** (Stan/`brms`) that partially pools sparse vendors (Check Point=2, Zyxel=6, WatchGuard=4) using EPSS base rates as informative priors. This is the standard pharmacovigilance/epidemiology solution to rare-event rate comparison and has **never** been applied to edge-KEV counts. It directly answers MITRE's own warning that small-N KEV rankings are "highly sensitive to a single CVE." *Effort: 3–4 months; the per-install denominators are the hard part.*

**Pillar 3 — Novel research questions only this dataset can answer:**
1. **Exploitation-velocity index** — device-class-stratified time-to-first-exploitation using survival analysis (Kaplan-Meier / stratified Cox PH with vendor × device-class × EPSS-band covariates). **No peer-reviewed paper applies survival analysis to TTE at the vendor/product-class level** despite TTE going negative — a clean publication.
2. **Exposure × exploitation correlation** — join Censys/Shodan exposure counts (P1-13) against KEV exploitation; quantify whether attacker attention tracks deployment base or vendor identity (separates "weaker security" from "bigger target").
3. **EOL-exploitation correlation at scale** — operationalize VulnCheck's 42.5% with a controlled base rate (what fraction of *exposed* edge devices are EOL?) — the regulatory-relevant figure CISA's BOD 26-02 lacks a baseline for.
4. **Disclosure-behavior / vendor-transparency scoring** — from `patch_cadence_days` (P1-12): silent-patch detection (negative cadence) as a per-vendor transparency metric, a dimension absent from every existing report.
5. **EPSS edge-domain adaptation** — measure EPSS v4's AUC/precision/recall **stratified for edge appliances** against this ground truth. EPSS publishes no device-class breakdown; this would be the first empirical critique of EPSS domain specificity — a direct contribution to the FIRST EPSS working group. *Effort: low-medium (P2-4 + the public EPSS CSV).*

**Publication / impact path.** Reproducibility package (Zenodo DOI + Croissant + CITATION.cff, P2-6) clears the USENIX Sec '26 open-science floor. Sequence: (a) workshop paper / FIRST EPSS contribution on the EPSS edge-domain evaluation (cheapest, fast); (b) the normalized cross-vendor comparison + survival-analysis TTE study targeting USENIX Security / IEEE S&P / ACM CCS; (c) position the living dataset as the citable baseline CISA BOD 26-02 implicitly demands. **Honest effort:** Pillars 1–2 + research Q5 are ~1 quarter of focused work; the full survival/exposure studies (Q1–Q3) are 4–6 months each and gate on external data access (Censys Academic, Shodan academic, installed-base estimates).

---

## 6. Sequenced Execution Plan

> Legend: **[AUTO]** safe to automate now · **[REVIEW]** automate then human-review · **[JUDGMENT]** requires a human decision before acting.

**Phase 0 — Stop the bleeding (do first, same PR or stacked).**
1. [AUTO] P0-1 — patch `analyze_tte.py:141/144` `--no-fetch` fallback.
2. [AUTO] P0-7 — sed-fix 5× "ortinet" dead links.
3. [AUTO] P0-9 — atomic write in `build_kev_counts.py`.
4. [REVIEW] P0-5 — Fortinet.md 5→7 zero-days + flip 2 table cells.
5. [REVIEW] P0-6 — per-vendor ransomware counts (Ivanti/SonicWall/PAN) in 2 docs.
6. [REVIEW] P0-8 — CVE-2026-24858 ransomware N→Y (re-verify vs live CISA first).
7. [AUTO] P0-10 — add 2 entries to `KNOWN_ZERO_DAYS` (assert output unchanged).

**Phase 1 — Fix the counts (re-derivation cascade; one rebuild at the end).**
8. [AUTO] P0-2 — Citrix `^NetScaler$` regex (Citrix 11→13).
9. [JUDGMENT] P0-3 — add WatchGuard vendor (+ `docs/WatchGuard.md`, fix METHODOLOGY:495).
10. [JUDGMENT] P0-4 — add Array Networks vendor (+ doc, fix METHODOLOGY:153).
11. [AUTO] rebuild `kev_edge_counts.json` + re-enrich; **propagate 107→109+ and vendor 11→13 through README / EXECUTIVE-SUMMARY / THE-NUMBERS / VENDOR-MATRIX / STATISTICS / chi²**.
12. [AUTO] P2-1 — add CI correctness gates that lock items 1–11.

**Phase 2 — Rigor hardening.**
13. [REVIEW] P1-1 pairwise conditional-binomial; P1-2 quasi-Poisson SE; P1-3 CWE Fisher+Bonferroni.
14. [REVIEW] P1-4 market-share exact-test + log-log; P1-5 TTE framing/labels; P1-6 selection-bias + citations.
15. [JUDGMENT] P1-7 F5 BIG-IQ scope; P1-8 Ivanti Sentry scope (documented decisions).

**Phase 3 — Operational dimensions.**
16. [REVIEW] P1-11 CISA EDs (incl. ED 25-03 in Cisco.md); P1-12 `pre_auth` + patch-cadence fields.
17. [JUDGMENT/large] P1-9 MITRE ATT&CK mapping; P1-10 EOL status; P1-13 exposure enrichment.

**Phase 4 — Distribution & North Star.**
18. [AUTO] P2-2 enrichment in daily CI; P2-3 README/INDEX dedupe; P2-4 release assets + schema; P2-5 explorer wiring.
19. [REVIEW] P2-6 Zenodo DOI + Croissant + badges.
20. [JUDGMENT] North Star research track: per-install normalization → Bayesian hierarchical rates → survival-analysis TTE → EPSS edge-domain eval → publication.
