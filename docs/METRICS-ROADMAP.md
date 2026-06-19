# Metrics Roadmap — Accurate Signals to Integrate

The dataset's weakest input is **market share**: the per-install normalization and the
Poisson elasticity model rest on *analyst-estimated* share brackets (no error bars,
unit≠revenue≠device-count). They are heavily caveated and reported as brackets, but
they are estimates, not measurements.

This roadmap ranks **accurate, obtainable** metrics that would strengthen the project —
prioritising hard data over estimates — by **accuracy × tractability**. Each entry notes
the source, whether it is buildable now (stdlib + free) or gated on external access, and
how it enhances the project. Nothing here ships until it can be sourced accurately; we do
not fabricate denominators.

---

## A. Replace the soft denominator (directly fixes the market-share weakness)

### A1 — Internet-exposed device counts (Censys / Shodan) — **highest value**
- **What:** the real number of internet-facing devices per vendor product (e.g. FortiOS
  SSL-VPN, NetScaler Gateway), via Censys/Shodan queries by product banner.
- **Why it matters:** this is the *correct* normalizer. A per-**exposed-device**
  exploitation rate replaces estimated market share with a measured denominator —
  exactly the gap that currently weakens `analyze_normalization.py` /
  `analyze_regression.py`. It also enables the North-Star **exposure × exploitation**
  study.
- **Accuracy:** high (direct measurement, point-in-time). **Gated:** Censys/Shodan
  academic or API access required; record `query`, `count`, `as_of` for reproducibility.
- **Sources:** [Censys](https://censys.com/), [Shodan](https://www.shodan.io/) — Censys
  scans all 65,535 ports vs Shodan's ~1,237 (more complete service detection).

### A2 — Active-exploitation breadth (GreyNoise) — real-world, edge-focused
- **What:** per-CVE internet-wide scanning/exploitation activity (unique source IPs,
  session volume, "mass-exploited" tags) from GreyNoise's sensor network.
- **Why:** distinguishes a CVE exploited once by a nation-state from one mass-scanned by
  botnets — a dimension KEV's binary flag cannot capture. GreyNoise's
  [2026 State of the Edge Report](https://www.greynoise.io/resources/2026-state-of-the-edge-report)
  is edge-device-specific and corroborates this project's thesis (>50% of RCE attempts
  from previously-unseen IPs; edge is where attacks concentrate).
- **Accuracy:** high (observed activity). **Gated:** GreyNoise API (community/free tier
  is limited; per-CVE tags need a key).

---

## B. Accurate + free + buildable now (no external access gating)

### B1 — Weaponization / public-exploit availability — **best free next build**
- **What:** per-CVE booleans + a `weaponization` score from cross-referencing the CVE IDs
  against curated public-exploit indices: **Nuclei templates** (ProjectDiscovery), **Metasploit**
  modules, and **ExploitDB**. Add `has_nuclei_template`, `has_metasploit_module`,
  `in_exploitdb`.
- **Why:** turns "exploited" into "how *accessible* is the exploit" — a strong, defender-
  relevant prioritisation signal that pairs naturally with the existing EPSS edge-eval.
- **Accuracy:** high **if curated sources are used.** Caveat (2026): there is an explosion
  of AI-generated, low-quality PoCs on GitHub — so prefer the curated indices
  (Nuclei/Metasploit/ExploitDB) over raw "CVE PoC" scraper repos, and label the source.
- **Build path:** fetch the three indices' CVE-ID lists, set membership flags, document as
  a heuristic weaponization signal. Free, scriptable, stdlib + one fetch each.
- **Sources:** [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates),
  Metasploit Framework modules, [Exploit-DB](https://www.exploit-db.com/).

### B2 — CISA remediation urgency — zero external data, buildable immediately
- **What:** `remediation_window_days` = `kev_due_date − kev_date_added`; flag the
  emergency short deadlines (the 3-day Fortinet/Check Point cases). Already have both dates.
- **Why:** a small, fully-accurate operational signal (how fast CISA demanded the fix).

### B3 — Temporal EPSS (FIRST historical API) — free, accurate
- **What:** EPSS score at/near disclosure vs at enrichment time, per CVE, from FIRST's
  historical EPSS API.
- **Why:** sharpens the EPSS edge-domain evaluation — shows whether EPSS *lagged* edge
  exploitation rather than just its current value. Free API.
- **Source:** [FIRST EPSS](https://www.first.org/epss/) (time-series endpoint).

---

## C. Accurate, needs a feed or manual collection

### C1 — VulnCheck KEV cross-coverage
- **What:** flag edge CVEs that are in **VulnCheck KEV** but not (yet) in CISA KEV — a
  coverage-gap signal (VulnCheck's catalog is broader/faster). **Gated:** VulnCheck API.

### C2 — Patch / advisory timing → disclosure-behaviour scoring
- **What:** collect vendor PSIRT advisory + fix dates per CVE → true patch-to-exploit
  window and a per-vendor **silent-patch / transparency** score (negative cadence = patched
  before advisory). **Tractability:** per-CVE manual/semi-automated collection from PSIRTs.

---

## Recommended sequence

1. **B1 weaponization** + **B2 remediation urgency** — free, accurate, buildable now;
   biggest enhancement per unit effort.
2. **B3 temporal EPSS** — free, sharpens an existing analysis.
3. **A1 exposure counts** (when Censys/Shodan access is available) — the real fix for the
   market-share weakness; promote it from estimate to measurement and re-run normalization
   on a measured denominator.
4. **A2 GreyNoise** + **C1 VulnCheck** — when API keys are available.
5. **C2 disclosure scoring** — as a focused manual-collection pass.

**Integrity rule:** every new metric records its source and `as_of`, is labelled
measured vs. estimated vs. heuristic, and ships only when it can be sourced accurately —
the same standard as the rest of the dataset.
