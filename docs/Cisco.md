# Cisco

**Scope: Cisco ASA / FTD firewalls.** Cisco's portfolio-wide KEV total spans IOS, switches, routers, and SD-WAN — it is *not* attributed to ASA/FTD here. *(13 ASA/FTD edge KEV entries, 2020–2026.)*

---

## Market Position

Cisco is the world's dominant enterprise networking and perimeter security vendor. Its Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) product lines are embedded in government agencies, critical infrastructure operators, and Fortune 500 networks on every continent. That ubiquity is a double-edged sword: any exploitable vulnerability carries an outsized blast radius, and Cisco ASA/FTD in particular has become a high-value target for state-sponsored threat actors willing to invest in custom, product-specific tooling.

---

## The KEV Count — Label It Correctly

Cisco leads the CISA KEV catalog with approximately 82 known-exploited vulnerabilities, placing it third overall (behind Microsoft and Apple) and first among pure-play network security vendors. **This figure spans all Cisco product lines** — IOS/IOS XE, Small Business routers, Catalyst switches, VPN concentrators, and collaboration platforms — not ASA/FTD firewalls alone. Attributing the full count to "Cisco firewalls" is a common misread that inflates the firewall-specific risk picture. Per-product KEV density is the correct lens.

---

## ArcaneDoor: A State Actor With a Cisco Specialization

The defining incident in Cisco's recent security record is **ArcaneDoor** — an espionage campaign attributed by [Cisco Talos](https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/) to the actor cluster it calls UAT4356 (Microsoft designation: STORM-1849). The actor began standing up infrastructure in November 2023 and peaked in January 2024, compromising government-owned ASA and FTD devices globally using two zero-days disclosed on April 24, 2024:

- [**CVE-2024-20353**](https://nvd.nist.gov/vuln/detail/cve-2024-20353) (CVSS 8.6, High) — unauthenticated remote DoS/reboot via malformed HTTP header to the management/VPN web server.
- [**CVE-2024-20359**](https://nvd.nist.gov/vuln/detail/cve-2024-20359) (CVSS 6.0, retroactively re-rated High) — authenticated local code execution that persists across reboots via a legacy VPN client pre-load hook.

Chained together, they enabled the **Line Dancer** implant (a memory-resident shellcode interpreter that evades disk-based forensics) and **Line Runner** (a persistent backdoor that survived device reboots). Line Runner persistence was achieved through CVE-2024-20359 — a file written to `disk0` and loaded via the legacy VPN client pre-load hook — while CVE-2024-20353 supplied the controlled reload step that triggered installation. Both CVEs were added to CISA KEV. The campaign targeted government networks; telecommunications and energy sectors were flagged as additional areas of concern.

---

## Same Actor, New Zero-Days (2025)

UAT4356/STORM-1849 returned in 2025 with two additional ASA/FTD zero-days, [disclosed September 25, 2025](https://www.tenable.com/blog/cve-2025-20333-cve-2025-20362-faq-cisco-asa-ftd-zero-days-uat4356):

- **CVE-2025-20333** (CVSS 9.9, Critical) — RCE in the VPN web server.
- **CVE-2025-20362** (CVSS 6.5, Medium) — unauthorized access, chained with CVE-2025-20333 for full unauthenticated device takeover.

The 2025 toolset introduced **RayInitiator** (a bootkit) and **LINE VIPER** (a shellcode loader), indicating continued investment in Cisco-specific offensive capability. Both CVEs were confirmed exploited in the wild at the time of disclosure.

---

## Disclosure Transparency: Above Average

Cisco PSIRT's handling of ArcaneDoor is a credible example of coordinated responsible disclosure. The April 2024 advisory was developed over months in collaboration with [CISA, Australia's ASD ACSC, Canada's CCCS, and the UK NCSC](https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_attacks_event_response), releasing actionable indicators of compromise simultaneously with the patch. The retroactive elevation of CVE-2024-20359's severity to reflect real-world persistence impact reflects honest post-hoc reassessment rather than minimization. No silent-patch behavior was identified in this review — a meaningful contrast to documented Fortinet practices.

---

## Risk Verdict

The raw KEV count is noisy. The structural concern is not the number but the pattern: a single well-resourced actor has now burned **four ASA/FTD zero-days across two confirmed campaigns** and is iterating its implant toolset. Government operators running Cisco perimeter devices face a durable adversary whose investment in Cisco-specific capability shows no sign of exhaustion. Patching remains necessary but not sufficient — the ArcaneDoor implants demonstrated the ability to survive standard remediation paths, and Line Runner specifically required a firmware-level response.

