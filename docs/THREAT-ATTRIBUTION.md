# Threat Actor Attribution: Edge Security CVEs

**Scope:** Known public attribution for CISA KEV-listed CVEs affecting the 13 edge/perimeter vendors tracked in this project (firewalls, SSL-VPNs, remote-access gateways). Attribution covers 2020–2026 based on reporting from Mandiant/GTIG, Volexity, CrowdStrike, Talos, CISA, Sophos, and named academic/industry researchers.

> **Caveat up front:** Attribution in the threat-intelligence industry is probabilistic, not forensic. UNC/UAT/UTA designations are working hypotheses from private-sector analysts, not judicial findings. Government attributions (US, UK, Five Eyes) carry more formal process but remain incomplete. Many CVEs have zero public attribution — absence of a name does not mean absence of a threat actor. Multiple private vendors frequently assign different names to the same cluster of activity. This document reflects the public record as of 2026-06-18 and should be read as an intelligence summary, not ground truth.

---

## 1. Attribution Matrix

The table below maps high-profile KEV-listed edge CVEs to publicly attributed threat actors. "None confirmed" means no public attribution exists in named vendor or government reporting; it does not mean the CVE was not weaponized.

| Vendor | CVE | Attributed Actor(s) | Actor Aliases | Nexus | Source(s) |
|--------|-----|--------------------|-|-------|---------|
| Fortinet | CVE-2022-42475 | UNC3886 | — | China | Mandiant GTIG |
| Fortinet | CVE-2024-21762 | China-nexus (unspecified) | — | China | CISA, Mandiant |
| Fortinet | CVE-2026-24858 | None confirmed | — | Unknown | Arctic Wolf, CISA |
| Ivanti | CVE-2023-46805 + CVE-2024-21887 | UNC5221 | — | China | Mandiant GTIG |
| Ivanti | CVE-2025-0282 | UNC5337 | — | China | Mandiant GTIG |
| Cisco | CVE-2024-20353 + CVE-2024-20359 | UAT4356 / STORM-1849 | ArcaneDoor actor | Unknown (state-suspected) | Talos, Microsoft |
| Palo Alto | CVE-2024-3400 | UTA0218 | — | China-suspected | Volexity, Palo Alto Unit 42 |
| Citrix | CVE-2023-4966 (CitrixBleed) | LockBit 3.0 ransomware affiliates | — | Criminal | Boeing disclosure, Mandiant |
| Citrix | CVE-2023-3519 | China-nexus (unspecified) | — | China | CISA advisory AA23-201A |
| Sophos | CVE-2022-1040 | DriftingCloud; TA413 | — | China | Volexity, Recorded Future |
| Sophos | CVE-2022-3236 | China-nexus (Pacific Rim cluster) | Volt Typhoon TTPs overlap | China | Sophos Pacific Rim |
| Sophos | CVE-2020-12271 | Asnarok cluster (Pacific Rim) | Volt Typhoon / APT31 / APT41 TTP overlap | China | Sophos Pacific Rim |
| Juniper | CVE-2025-21590 | UNC3886 | — | China | Mandiant GTIG |
| SonicWall | CVE-2024-40766 | Akira ransomware; Fog ransomware | — | Criminal | Arctic Wolf, Sophos MTDR |
| SonicWall | MySonicWall breach (2021) | State-sponsored (unspecified) | — | Unknown | CISA advisory |
| Zyxel | CVE-2023-28771 chain | Mirai-variant botnets | Dark.IoT, others | Criminal/botnet | Fortinet FortiGuard Labs, CISA |
| Zyxel | CVE-2024-11667 | Helldown ransomware | — | Criminal | Sekoia, Halcyon |
| Check Point | CVE-2024-24919 | Iran-nexus (unspecified) | — | Iran | Check Point Research, Microsoft |
| F5 BIG-IP | (major CVEs) | None confirmed publicly | — | Unknown | — |

### Notes on the matrix

- **UNC3886** is Mandiant's designation for a China-nexus espionage actor with a documented preference for edge appliances and hypervisor-level persistence. It is responsible for both the Fortinet CVE-2022-42475 campaign and the Juniper CVE-2025-21590 MX-router backdoor operation — the same cluster operating across different vendors, years apart.
- **UNC5221** and **UNC5337** are Mandiant designations for China-linked groups exploiting Ivanti Connect Secure. Whether these represent the same cluster at different operational phases or genuinely distinct actors is not resolved in public reporting.
- **UAT4356 / STORM-1849** refer to the ArcaneDoor actor responsible for the Cisco ASA/FTD zero-days. Talos (Cisco) and Microsoft Threat Intelligence Center assigned separate labels to the same campaign. National nexus is assessed as state-sponsored but not publicly attributed to a specific country by either Talos or Microsoft as of this writing.
- **Pacific Rim** is Sophos's umbrella term for overlapping China-nexus clusters — not a single actor. Sophos documented TTP overlap with Volt Typhoon, APT31, and APT41 across a five-year span but did not collapse them into one attribution.

---

## 2. Actor Taxonomy

### 2.1 Nation-State Espionage — China

The largest identified category. China-nexus actors dominate the high-value enterprise VPN and firewall segment.

| Actor Designation | Known CVEs Exploited | Reporting Source |
|---|---|---|
| UNC3886 | CVE-2022-42475 (Fortinet), CVE-2025-21590 (Juniper) | Mandiant GTIG |
| UNC5221 | CVE-2023-46805 + CVE-2024-21887 (Ivanti) | Mandiant GTIG |
| UNC5337 | CVE-2025-0282 (Ivanti) | Mandiant GTIG |
| UTA0218 | CVE-2024-3400 (Palo Alto) | Volexity, Unit 42 |
| DriftingCloud | CVE-2022-1040 (Sophos) | Volexity |
| TA413 | CVE-2022-1040 (Sophos) — Tibetan targeting | Recorded Future |
| Pacific Rim cluster (multi-group) | CVE-2020-12271, CVE-2022-1040, CVE-2022-3236 (Sophos) | Sophos |
| Unnamed | CVE-2024-21762 (Fortinet), CVE-2023-3519 (Citrix), CVE-2024-40766 (partially) | CISA, Mandiant |

### 2.2 Nation-State Espionage — Iran

| Actor | Known CVEs Exploited | Source |
|---|---|---|
| Iran-nexus (unattributed) | CVE-2024-24919 (Check Point) | Check Point Research, Microsoft |

### 2.3 Nation-State / State-Sponsored — Attribution Contested or Undisclosed

| Actor | Known CVEs Exploited | Notes |
|---|---|---|
| UAT4356 / STORM-1849 | CVE-2024-20353 + CVE-2024-20359 (Cisco ArcaneDoor) | Suspected state-sponsored; country not publicly confirmed |
| Unknown (Fortinet) | CVE-2026-24858 | No public attribution; targeted initially before patch |

### 2.4 Ransomware Operators

| Actor | CVEs Exploited | Source |
|---|---|---|
| LockBit 3.0 affiliates | CVE-2023-4966 (Citrix CitrixBleed) | Boeing incident, Mandiant |
| Akira ransomware | CVE-2024-40766 (SonicWall) | Arctic Wolf |
| Fog ransomware | CVE-2024-40766 (SonicWall) | Sophos MTDR |
| Helldown ransomware | CVE-2024-11667 (Zyxel) | Sekoia, Halcyon |

### 2.5 Botnets and Commodity Exploitation

| Actor | CVEs Exploited | Source |
|---|---|---|
| Mirai-variant (Dark.IoT et al.) | CVE-2023-28771 chain (Zyxel) | Fortinet FortiGuard Labs |
| Unattributed mass-scanning campaigns | Multiple (SonicWall, Zyxel, Citrix) | Shadowserver, Shodan scanning data |

---

## 3. Targeting Patterns

### 3.1 China-Nexus: High-Value Enterprise VPNs

China-linked espionage actors — Mandiant's UNC/UTA clusters, Volt Typhoon, APT31, APT41 — consistently prioritize **remote-access VPN and SSL-VPN gateways deployed by large enterprises and critical infrastructure operators.** The operational logic is clear: a compromised VPN gateway provides pre-authenticated access to internal networks without triggering endpoint detection, enables credential harvesting at scale (all VPN auth flows through the device), and supports long-term, low-noise persistence.

Targets documented in public reporting include: telecommunications providers, defense contractors, US federal agencies (Ivanti CISA ED 24-01), nuclear energy suppliers, military hospitals, central government ministries across South Asia (Sophos Pacific Rim), and managed security service providers.

Fortinet FortiOS, Ivanti Connect Secure, Palo Alto PAN-OS, and Sophos Firewall are the primary China-nexus targets in this dataset. Of the 13 tracked vendors, 8 have documented China-nexus exploitation. The concentration on enterprise-focused vendors aligns with their market share in the VPN/firewall space, not with any demonstrated weakness differential vs. peers. WatchGuard and Array Networks have no public nation-state attribution.

**UNC3886's vendor-agnosticism** is notable: the same cluster exploited Fortinet CVE-2022-42475, then returned years later to exploit Juniper CVE-2025-21590 on MX-series routers — targeting core routing infrastructure in addition to VPN gateways. This suggests an interest in network topology and traffic interception beyond simple remote-access.

### 3.2 Iran-Nexus: Opportunistic Enterprise Firewall Access

The Iran-nexus campaign exploiting Check Point CVE-2024-24919 is documented as broader and more opportunistic than the China espionage cluster — targeting enterprise perimeter firewalls across multiple sectors without the surgical targeting profile of Volt Typhoon or UNC3886. Check Point Research and Microsoft both noted exploitation across diverse victim verticals.

### 3.3 Ransomware Operators: Mid-Market and High-Availability Targets

Ransomware affiliates (LockBit, Akira, Fog, Helldown) target edge devices as **initial access brokers** — using the VPN or firewall compromise to establish a beachhead, then pivoting to deploy ransomware internally. Their targets skew toward **mid-market organizations** (hospitals, logistics, manufacturing) where patching velocity is lower and the business disruption impact of a ransom demand is higher.

- **CitrixBleed (CVE-2023-4966):** LockBit affiliates exploited Citrix NetScaler in the Boeing breach and numerous others. The vulnerability allowed session hijacking without credentials.
- **SonicWall CVE-2024-40766:** Both Akira and Fog ransomware groups were documented exploiting SonicOS authentication failures. SonicWall's strong position in the SMB firewall market makes it a high-density target for ransomware operators seeking volume over precision.
- **Helldown / Zyxel CVE-2024-11667:** Helldown ransomware operators exploited a path traversal in Zyxel's ATP/USG FLEX management interface to gain credentials and establish VPN access before lateral movement.

### 3.4 Botnets: SMB-Market Devices

Commodity botnets (Mirai variants, Moobot, others) target **edge devices with weak default credentials and exposed management interfaces**, predominantly in the SOHO and small-business market. Zyxel's ATP and USG FLEX series — priced and marketed for SMBs — appear repeatedly in botnet exploitation chains. The CVE-2023-28771 command-injection vulnerability in Zyxel's firewall was rapidly incorporated into multiple Mirai forks, consistent with the botnet operator playbook: scan globally for newly-patched CVEs, exploit before the long tail of unpatched devices closes.

Botnets generally do not perform targeted espionage; they assemble infrastructure (proxies, DDoS nodes, cryptomining) from mass-exploited devices.

---

## 4. Edge Devices as the Preferred Entry Vector

Mandiant's 2024 M-Trends / Google Threat Intelligence Group reporting found that **44% of zero-days exploited in 2024 targeted security and edge appliances** — the single largest category, exceeding browsers, operating systems, and enterprise software. The edge has become the primary zero-day battleground for nation-state actors for reasons that are operational, not accidental:

1. **No EDR.** Network edge appliances run proprietary firmware and are largely incompatible with endpoint detection and response tools. There is no CrowdStrike or SentinelOne agent watching process behavior on a FortiGate or ASA.
2. **Always on, always internet-facing.** Edge devices have no patch window — they cannot be taken offline for routine maintenance without disrupting connectivity.
3. **Privileged network position.** A compromised edge device can inspect, intercept, and modify all traffic transiting the perimeter — including authentication flows, MFA tokens, and encrypted VPN sessions.
4. **Persistence is durable.** Post-exploitation techniques (symlink persistence on FortiGate surviving firmware upgrades; hypervisor-level implants via ESXi documented in UNC3886 campaigns; MX router backdoors in Juniper CVE-2025-21590) mean a successful compromise can outlast patching cycles.
5. **Attribution is harder.** Traffic originating from a compromised edge device blends with legitimate network flows; SIEM and NDR tools typically trust traffic from the firewall itself.

VulnCheck's 2026 State of Exploitation report corroborated the picture from the remediation side: **42.5% of exploited vulnerabilities in 2025 hit end-of-life devices**, devices that cannot receive patches regardless of vendor response speed. The combination of no-EDR, always-on, and patching-impossible creates an asymmetric attack surface.

---

## 5. Caveats on Attribution

### 5.1 Private-Sector Designations Are Working Hypotheses

UNC (Mandiant), UAT (Talos), UTA (Volexity), TAG (Google), DEV- (Microsoft) prefixes signal **uncategorized or emerging clusters** — the analyst does not have sufficient confidence to merge the cluster with a named APT. When a cluster is later attributed (e.g., UNC2452 → Cozy Bear / SVR), the prior UNC reporting is retroactively linked. This means the actors in the matrix above may be subsequently merged, split, or re-attributed as more evidence accumulates.

### 5.2 Government Attributions Differ From Private-Sector

US government attributions (DOJ indictments, NSA/CISA advisories, Five Eyes joint advisories) follow a higher evidentiary bar than private-sector threat intelligence. A Mandiant UNC designation may map to a state actor that the US government has not formally accused. Conversely, some government-named actors (Volt Typhoon, APT40) have not been attributed to specific CVE exploitations in the same detail as private-sector reporting.

### 5.3 Many CVEs Have No Public Attribution

For the majority of edge CVEs in the CISA KEV catalog — including CVE-2026-24858 (Fortinet), multiple SonicWall entries, and all F5 BIG-IP entries — no public threat actor attribution exists. "No attribution" does not mean "not exploited by a sophisticated actor." It means either: (a) the exploitation has not been detected and analyzed in a way that produced public reporting; (b) it was detected but the victim or analyst has not published; or (c) exploitation was observed but actor attribution was not possible from available artifacts.

### 5.4 Overlapping Attribution and Shared Infrastructure

China-nexus actor clusters frequently share infrastructure, tooling, and targeting mandates. The Sophos Pacific Rim report documented TTP overlap across Volt Typhoon, APT31, and APT41 within a single campaign — the clusters are not cleanly separable. Similarly, ransomware "affiliates" operate across multiple ransomware-as-a-service programs: an Akira affiliate in one operation may be a Fog affiliate in another. The actor names in the matrix are the most specific attributions available in public reporting; they should not be interpreted as clean, mutually exclusive entities.

### 5.5 Absence of Attribution for F5, WatchGuard, and Array Networks

No major public attribution exists for F5 BIG-IP KEV-listed CVEs (e.g., CVE-2022-1388, CVE-2023-46747), nor for WatchGuard or Array Networks KEV entries. This absence is consistent with the overall pattern: these vendors have smaller edge-appliance footprints than Fortinet, Ivanti, or Cisco in the targeted verticals, making them lower-priority targets for documented nation-state campaigns. It does not indicate those CVEs were not exploited — CISA's KEV listing confirms in-the-wild exploitation. The exploiting actors are simply not named in public reporting. Array Networks CVE-2023-28461 is CISA-flagged ransomware-associated, indicating criminal (not state) exploitation.

---

## Sources

- **Mandiant / Google Threat Intelligence Group (GTIG):** UNC3886, UNC5221, UNC5337 cluster reporting; 2024 M-Trends (44% zero-day stat); Ivanti Connect Secure zero-day analysis
- **Volexity:** CVE-2024-3400 (UTA0218 / Operation MidnightEclipse); CVE-2022-1040 (DriftingCloud)
- **Talos (Cisco):** CVE-2024-20353 + CVE-2024-20359 (ArcaneDoor / UAT4356)
- **Microsoft Threat Intelligence Center:** STORM-1849 (ArcaneDoor); Iran-nexus Check Point campaigns
- **CISA:** KEV catalog; Emergency Directive 24-01 (Ivanti); AA23-201A (Citrix CVE-2023-3519); CVE-2026-24858 advisory
- **Sophos:** Pacific Rim report (October 2024) — five-year defensive operation against China-nexus clusters
- **Arctic Wolf:** CVE-2026-24858 (Fortinet, zero-day window documentation); CVE-2024-40766 (SonicWall / Akira)
- **Recorded Future:** TA413 exploitation of Sophos CVE-2022-1040 (Tibetan targeting)
- **Sekoia / Halcyon:** Helldown ransomware / Zyxel CVE-2024-11667
- **Fortinet FortiGuard Labs:** Mirai botnet exploitation of CVE-2023-28771 (Zyxel)
- **VulnCheck:** 2026 State of Exploitation report (42.5% EOL device stat)
- **CrowdStrike:** Adversary taxonomy (Panda/Bear/Kitten/Spider/Jackal naming convention); supporting context on China-nexus cluster boundaries
