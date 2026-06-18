# Check Point Software

**Scope: Check Point Quantum Security Gateways (SSL VPN / Remote Access VPN / Mobile Access blade).** *(2 edge KEV entries — the lowest count of any vendor in this repo.)*

---

## Market Position

Check Point is a [Gartner Magic Quadrant Leader for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336) and one of the three incumbents that dominate enterprise firewall revenue alongside Fortinet and Palo Alto Networks. Market analysts estimate Check Point holds roughly **10–12% enterprise firewall revenue share**. Its flagship line — the **Quantum Security Gateway** family — is widely deployed in financial services, government, and critical infrastructure, particularly in Europe and the Middle East.

---

## Key Incidents

| CVE | CVSS | Class | Product | KEV Added |
|-----|------|-------|---------|-----------|
| [CVE-2024-24919](https://nvd.nist.gov/vuln/detail/CVE-2024-24919) | 8.6 | Path traversal / information disclosure | Quantum Security Gateway (Remote Access VPN / Mobile Access blade enabled) | May 30 2024 |
| CVE-2026-50751 | — | Security Gateway vulnerability (limited public detail at time of writing) | Security Gateway | Jun 8 2026 |

### CVE-2024-24919

This is the most significant Check Point edge vulnerability in the KEV window. An SSL VPN path traversal bug allowing an **unauthenticated remote attacker to read arbitrary files** from the gateway — including password hashes and SSH keys — on any Quantum Security Gateway with the Remote Access VPN or Mobile Access blade enabled.

[Check Point issued an advisory on May 28, 2024](https://support.checkpoint.com/results/sk/sk182337), two days before CISA added it to KEV on May 30. Exploitation was attributed by multiple researchers to **Iran-nexus threat actors**, who used extracted credentials to move laterally into enterprise environments. Within **48 hours of PoC publication**, over [10,000 internet-facing Check Point devices were observed being actively scanned](https://www.bleepingcomputer.com/news/security/check-point-warns-of-vpn-attacks-exploiting-their-zero-day-vulnerability/) by opportunistic actors beyond the initial targeted campaigns.

The initial Check Point advisory characterized the issue narrowly. External researchers — including teams at [Watchtowr](https://labs.watchtowr.com/) and Mnemonic — subsequently confirmed that the scope of exploitation was broader than the framing implied, and that the path traversal primitive was trivially weaponizable. CISA's KEV listing and a follow-on [Check Point hardening guide](https://support.checkpoint.com/results/sk/sk182336) both recommend treating any affected device as potentially compromised, not merely patched.

### CVE-2026-50751

Added to the CISA KEV catalog on June 8, 2026, affecting the Security Gateway product line. At the time of writing, limited public technical detail is available. CISA's inclusion confirms exploitation in the wild; organizations with internet-facing Quantum Gateways should treat this as requiring immediate remediation regardless of current advisory framing.

---

## Transparency Assessment

Check Point publishes security advisories via its [PSIRT portal (sk-articles)](https://support.checkpoint.com/results/sk/sk182337). The disclosure record for CVE-2024-24919 was mixed: an advisory appeared within the disclosure window, and patches were available before the KEV listing. However, **the initial framing underestimated exploitation scope** — external researchers, not Check Point, confirmed the mass-scanning activity and the full reach of the vulnerability. There are no documented **silent-patch episodes** comparable to Fortinet's XORtigate disclosure failure. Check Point's disclosure posture is reactive but not systematically deceptive.

---

## Risk Summary

Check Point has the **lowest edge KEV count (2) of all vendors in this repo**. That figure reflects two things in combination — neither of which is simply "Check Point is safe."

First, Check Point's gateway product has historically shown **fewer pre-auth RCE vulnerabilities** compared to Fortinet's SSL-VPN daemon or Ivanti Connect Secure. The Quantum Gateway architecture has not produced the same pattern of recurring heap-overflow chains that characterize FortiOS's worst years.

Second, Check Point attracts **lower researcher attention** than Fortinet or Palo Alto. Raw KEV counts partly reflect how intensively a product family is analyzed — a factor METHODOLOGY.md calls the "popularity tax." A product with a smaller researcher community generates fewer public CVE disclosures, which can suppress counts without reflecting genuine security improvement.

CVE-2024-24919 should be read as a corrective to low-count complacency: a single information-disclosure vulnerability enabled nation-state lateral movement across thousands of enterprises within days. **Low count is not equivalent to low risk.** It means fewer confirmed, cataloged exploitation events — a meaningful but incomplete signal.

---

> **Note on raw counts:** Check Point's count of 2 is the lowest in this dataset. As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base and researcher attention ("popularity tax"), not security engineering quality alone. The count is reproducible and cited; its interpretation requires weighting both the vulnerability record *and* the relative researcher coverage each vendor receives.
