# Weaponization & Remediation Urgency

Two operational signals layered onto every CVE by [`scripts/enrich_signals.py`](../scripts/enrich_signals.py):
public-exploit availability ("weaponization") and CISA remediation urgency. Both are
fully reproducible from public data.

---

## Public-exploit availability (weaponization)

Per CVE: whether a **curated** public exploit or detection template exists.

| Field | Meaning |
|-------|---------|
| `in_exploitdb` | An [Exploit-DB](https://www.exploit-db.com/) entry references the CVE |
| `has_nuclei_template` | A [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei-templates) template exists |
| `public_exploit` | Either of the above |

**48 of 115 edge CVEs (42%) have a curated public exploit** (Exploit-DB: 19, nuclei: 43).

We deliberately use **curated indices only** — *not* raw GitHub "CVE PoC" scraper repos —
because 2026 has seen an explosion of AI-generated, low-quality PoCs of wildly uneven
reliability. This is a heuristic **accessibility** signal (how reachable a working exploit
is), not a guarantee that a reliable exploit exists.

### Per-vendor weaponization rate

| Vendor | Public exploit / KEV | Rate |
|--------|---------------------:|-----:|
| Check Point | 2/2 | 100% |
| Citrix | 7/13 | 54% |
| F5 | 3/6 | 50% |
| Juniper | 4/8 | 50% |
| Palo Alto Networks | 6/12 | 50% |
| Sophos | 3/6 | 50% |
| Cisco | 6/13 | 46% |
| Ivanti | 6/13 | 46% |
| Fortinet | 6/18 | 33% |
| Zyxel | 2/6 | 33% |
| SonicWall | 3/12 | 25% |
| Array Networks | 0/2 | 0% |
| WatchGuard | 0/4 | 0% |

**This is not a vendor-quality metric.** Weaponization rate tracks researcher/community
tooling attention, which itself scales with install base — the same *popularity tax* that
governs raw counts. Note the pattern: Fortinet's raw-highest count (18) has the **lowest**
weaponization rate among the majors (33%), while low-count vendors sit high — consistent
with the per-install normalization finding ([STATISTICS.md](STATISTICS.md#market-share-elasticity-poisson-regression)).
Small-N rates (Check Point 2/2, Array/WatchGuard 0/2 and 0/4) are not statistically meaningful.

---

## CISA remediation urgency

| Field | Meaning |
|-------|---------|
| `remediation_window_days` | `kev_due_date − kev_date_added` (days CISA allowed for the fix) |
| `cisa_emergency` | remediation window ≤ 7 days |

**27 of 115 (23%) carry an emergency (≤ 7-day) CISA deadline** — the CVEs CISA treated as
most urgent. The shortest, **1-day** deadlines: Cisco ArcaneDoor follow-on
(CVE-2025-20333, CVE-2025-20362) and Citrix CVE-2025-5777. The Juniper J-Web chain
(CVE-2023-36844…36851) all carried 4-day deadlines. This is a CISA *policy* signal (how
fast remediation was mandated), distinct from time-to-exploit (how fast attackers moved).

---

## Reproducibility & caveats

Regenerate: `python3 scripts/enrich_signals.py` (fetches Exploit-DB + nuclei live; the
remediation fields come from CISA KEV dates already in the dataset). The script **aborts
without writing** if a weaponization source is unreachable, so it never records a
misleading "no exploit" when the truth is "could not check." Weaponization is a heuristic
curated-index membership signal, not a measure of exploit quality or reliability; the
remediation window reflects CISA policy at listing time. See [METRICS-ROADMAP.md](METRICS-ROADMAP.md)
for higher-fidelity signals (measured internet-exposure counts, GreyNoise activity) still to integrate.
