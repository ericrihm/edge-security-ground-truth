# Palo Alto Networks

**Scope: PAN-OS firewall (GlobalProtect portal/gateway, NGFW management interface, User-ID Authentication Portal).** Palo Alto Networks is one of three Gartner Magic Quadrant Leaders for enterprise firewall alongside Fortinet and Check Point. Expedition and other non-edge products are out of scope; where relevant, they are noted separately. *(12 edge KEV entries, 2017--2026.)*

---

## KEV Summary Table

| CVE | CVSS (v3.1) | CWE Class | KEV Added | Zero-Day | Ransomware |
|-----|:-----------:|-----------|:---------:|:--------:|:----------:|
| [CVE-2017-15944](https://security.paloaltonetworks.com/CVE-2017-15944) | 9.8 | CWE-20 Improper Input Validation | Aug 18 2022 | N | N |
| [CVE-2019-1579](https://security.paloaltonetworks.com/CVE-2019-1579) | 8.1 | CWE-134 Format String | Jan 10 2022 | N | N |
| [CVE-2020-2021](https://security.paloaltonetworks.com/CVE-2020-2021) | 10.0 | CWE-347 Improper Signature Verification | Mar 25 2022 | N | N |
| [CVE-2022-0028](https://security.paloaltonetworks.com/CVE-2022-0028) | 8.6 | CWE-406 Network Amplification | Aug 22 2022 | N | N |
| [CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400) | 10.0 | CWE-77 Command Injection | Apr 12 2024 | Y | N |
| [CVE-2024-0012](https://security.paloaltonetworks.com/CVE-2024-0012) | 9.3 | CWE-306 Missing Authentication | Nov 18 2024 | Y | N |
| [CVE-2024-9474](https://security.paloaltonetworks.com/CVE-2024-9474) | 6.9 | CWE-78 OS Command Injection | Nov 18 2024 | Y | N |
| [CVE-2024-3393](https://security.paloaltonetworks.com/CVE-2024-3393) | 8.7 | CWE-754 Improper Exceptional Condition Check | Dec 30 2024 | N | N |
| [CVE-2025-0108](https://security.paloaltonetworks.com/CVE-2025-0108) | 9.1 | CWE-306 Missing Authentication | Feb 18 2025 | N | N |
| [CVE-2025-0111](https://security.paloaltonetworks.com/CVE-2025-0111) | 7.1 | CWE-73 External File Path Control | Feb 20 2025 | N | N |
| [CVE-2026-0300](https://security.paloaltonetworks.com/CVE-2026-0300) | 9.8 | CWE-787 Out-of-bounds Write | May 6 2026 | Y | N |
| [CVE-2026-0257](https://security.paloaltonetworks.com/CVE-2026-0257) | 9.1 | CWE-565 Cookie Validation Bypass | May 29 2026 | N | N |

**12 total KEV entries.** Six carry CVSS scores of 9.0 or higher. Four were exploited as zero-days (pre-patch or near-zero-day). No documented ransomware-operator exploitation -- the threat actor profile is overwhelmingly nation-state espionage (see Attribution below).

---

## Market Position

Palo Alto Networks is a [Gartner Magic Quadrant Leader for Hybrid Mesh Firewall](https://www.bankinfosecurity.com/palo-alto-fortinet-check-point-control-firewall-gartner-mq-a-29336) and the enterprise firewall revenue leader. PAN-OS devices protect a disproportionate share of high-value enterprise and government networks. That deployment profile directly shapes the threat actor landscape: nation-state actors invest in PAN-OS-specific offensive tooling because the payoff -- access to sensitive internal networks -- justifies the R&D cost. Market position is a confounding variable in any raw-count analysis.

---

## Timeline

### Pre-2020: Management Interface RCE

**CVE-2017-15944** (CVSS 9.8) is a pre-authentication remote code execution chain in the PAN-OS management web interface, affecting versions before 6.1.19, 7.0.19, 7.1.14, and 8.0.6. [Published December 2017](https://nvd.nist.gov/vuln/detail/CVE-2017-15944), it was not added to the CISA KEV catalog until August 2022 -- a five-year gap indicating that exploitation persisted long after disclosure. Public exploit code appeared on Exploit-DB within weeks of disclosure ([exploit-db.com/exploits/43342](https://www.exploit-db.com/exploits/43342/)).

**CVE-2019-1579** (CVSS 8.1) is a format-string vulnerability in GlobalProtect allowing unauthenticated remote code execution when the portal or gateway interface is exposed. [Disclosed July 2019](https://security.paloaltonetworks.com/CVE-2019-1579), it affected PAN-OS 7.1.x through 8.1.2. This was the first GlobalProtect-specific KEV entry, foreshadowing the attack-surface pattern that would intensify in 2024--2026. [Added to KEV January 10, 2022](https://nvd.nist.gov/vuln/detail/CVE-2019-1579).

### 2020--2022: SAML Bypass and Amplification

**CVE-2020-2021** (CVSS 10.0) is a SAML authentication bypass in PAN-OS that permits unauthenticated access to protected resources when SAML authentication is enabled and the identity provider certificate validation is disabled -- a [configuration Palo Alto documented as a valid deployment option](https://security.paloaltonetworks.com/CVE-2020-2021). The CVSS 10.0 score reflects the combination of no-auth, network-accessible, and full-scope impact. [Published June 29, 2020](https://nvd.nist.gov/vuln/detail/CVE-2020-2021); CISA [issued an emergency alert the same day](https://www.cisa.gov/news-events/alerts/2020/06/29/palo-alto-networks-releases-critical-pan-os-update). Added to KEV March 25, 2022.

**CVE-2022-0028** (CVSS 8.6) is a reflected amplification DoS vulnerability: a misconfigured URL filtering policy on an external-facing interface could be abused to amplify TCP denial-of-service attacks originating from the firewall itself. [Added to KEV August 22, 2022](https://nvd.nist.gov/vuln/detail/CVE-2022-0028). While requiring a specific (and inadvisable) configuration, the vulnerability was confirmed exploited in the wild. CISA required remediation by September 12, 2022.

### 2024: The Year of the Zero-Day

2024 produced four KEV entries -- three of them zero-days -- and fundamentally changed the PAN-OS threat profile.

#### CVE-2024-3400: Operation MidnightEclipse

[CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400) (CVSS 10.0) is a command injection in the GlobalProtect gateway feature of PAN-OS, allowing unauthenticated remote code execution as root. It is the single most significant PAN-OS vulnerability in the KEV catalog.

[Volexity discovered active exploitation on April 10, 2024](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), with earliest evidence of attacker testing traced to **March 26, 2024** -- more than two weeks before any advisory or patch. The campaign, dubbed **Operation MidnightEclipse**, was attributed to **UTA0218**, assessed by Volexity as "highly likely a state-backed threat actor" with suspected China nexus ([Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/cve-2024-3400/)).

UTA0218 deployed the **UPSTYLE** backdoor -- a custom Python implant that parsed web server error logs for command patterns and wrote output to legitimate CSS files, then restored originals after execution. Post-exploitation included reverse shells, GOST tunneling, configuration exfiltration, credential harvesting, and lateral movement into internal environments ([Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/)).

CISA [added it to KEV on April 12](https://www.cisa.gov/news-events/alerts/2024/04/12/palo-alto-networks-releases-guidance-vulnerability-pan-os-cve-2024-3400); [hotfixes shipped April 14--18](https://security.paloaltonetworks.com/CVE-2024-3400). Mandiant M-Trends 2025 identified CVE-2024-3400 as the **#1 most frequently exploited vulnerability** across all investigated incidents that year ([Mandiant](https://cloud.google.com/security/resources/m-trends)). EPSS at time of measurement: 0.99999 (100th percentile).

Days-to-mass-exploitation: zero (pre-patch zero-day). The attack was discovered externally, not by the vendor.

#### CVE-2024-0012 + CVE-2024-9474: The Management Interface Chain

These two vulnerabilities chain cleanly for unauthenticated root access to the firewall.

**CVE-2024-0012** (CVSS 9.3, CWE-306) bypasses authentication on the PAN-OS management web interface, granting unauthenticated admin access. **CVE-2024-9474** (CVSS 6.9, CWE-78) escalates that admin access to root via OS command injection. Both were [disclosed November 18, 2024](https://security.paloaltonetworks.com/CVE-2024-0012), though Palo Alto had issued an [initial warning on November 8](https://www.bleepingcomputer.com/news/security/palo-alto-networks-patches-two-firewall-zero-days-used-in-attacks/) (PAN-SA-2024-0015), ten days before publishing the CVE. Exploitation was confirmed active before any patch existed.

Within **48 hours** of a public proof-of-concept on November 19, [Wiz observed exploitation surge dramatically](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild), with at least [2,000 instances compromised worldwide](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild) (ShadowServer Foundation). Independent scans identified approximately [11,000 exposed PAN-OS management interfaces](https://www.bleepingcomputer.com/news/security/palo-alto-networks-patches-two-firewall-zero-days-used-in-attacks/) (Shodan). Post-exploitation payloads included web shells, Sliver implants, and cryptocurrency miners -- a mix of targeted and opportunistic activity ([Wiz](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild)).

The attack surface -- externally exposed management interfaces -- is a configuration Palo Alto [explicitly documents as inadvisable](https://docs.paloaltonetworks.com/best-practices/10-1/internet-gateway-best-practices/network-security/management-interface-access), yet widely deployed. CISA added both to KEV on November 18 with a remediation deadline of December 9 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0012)).

#### CVE-2024-3393: DNS Security DoS

[CVE-2024-3393](https://security.paloaltonetworks.com/CVE-2024-3393) (CVSS 8.7, CWE-754) is a denial-of-service vulnerability in the PAN-OS DNS Security feature. Unauthenticated attackers can send crafted packets through the firewall's data plane that cause device reboots; repeated triggering forces the firewall into maintenance mode. Exploitation requires DNS Security License and DNS Security logging to be enabled. [Published December 27, 2024](https://security.paloaltonetworks.com/CVE-2024-3393); [added to KEV December 30, 2024](https://nvd.nist.gov/vuln/detail/CVE-2024-3393) -- a three-day turnaround from disclosure to KEV listing.

### 2025: Chained Exploitation of the Management Interface

The February 2025 cluster demonstrates a compounding exploitation pattern against the same PAN-OS management interface surface.

**CVE-2025-0108** (CVSS 9.1, CWE-306) is another authentication bypass in the PAN-OS management web interface. [Assetnote researchers published a proof-of-concept](https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/) on February 12, 2025, demonstrating how it could be chained with the November 2024 CVE-2024-9474 for privilege escalation. [GreyNoise detected exploitation from 2 IP addresses on February 13, escalating to 25 sources shortly after](https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/). [CISA added it to KEV on February 18](https://nvd.nist.gov/vuln/detail/CVE-2025-0108).

**CVE-2025-0111** (CVSS 7.1, CWE-73) is an authenticated file-read vulnerability in the management interface. Published the same day as CVE-2025-0108 (February 12, 2025), it was quickly observed being [chained with CVE-2025-0108 and CVE-2024-9474](https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/) in a three-CVE attack chain: auth bypass (0108) to file read (0111) to privilege escalation (9474). [Added to KEV February 20, 2025](https://nvd.nist.gov/vuln/detail/CVE-2025-0111).

Macnica research at the time of exploitation found approximately [3,490 exposed PAN-OS management interfaces, with 65% vulnerable to all three chained flaws](https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/) and only a few dozen devices patched.

The structural pattern: CVE-2024-0012 (November 2024) and CVE-2025-0108 (February 2025) are both authentication bypasses in the same management web interface, three months apart. The second vulnerability arose on an attack surface that was already under active exploitation from the first.

### 2026: Two More Zero-Days

**CVE-2026-0300** (CVSS 9.8, CWE-787) is a buffer overflow in the PAN-OS **User-ID Authentication Portal** that permits unauthenticated remote code execution as root on PA-Series and VM-Series firewalls. [Added to KEV May 6, 2026](https://nvd.nist.gov/vuln/detail/CVE-2026-0300) with a **3-day remediation deadline** (May 9) -- among the shortest CISA has ever assigned. Patches were not released until May 13, meaning defenders faced a week-long window with no vendor fix and a CISA mandate to mitigate. [Palo Alto confirmed "limited exploitation" targeting exposed authentication portals](https://security.paloaltonetworks.com/CVE-2026-0300). Cloud NGFW, Prisma Access, and Panorama are unaffected.

**CVE-2026-0257** (CVSS 9.1, CWE-565) is an authentication bypass in the **GlobalProtect portal and gateway** that allows an attacker to establish an unauthorized VPN connection by exploiting weak cookie validation when authentication override cookies are enabled. [Published May 13, 2026](https://security.paloaltonetworks.com/CVE-2026-0257); [added to KEV May 29, 2026](https://nvd.nist.gov/vuln/detail/CVE-2026-0257) with a 3-day remediation deadline (June 1). Palo Alto confirmed ["limited exploit attempts observed"](https://security.paloaltonetworks.com/CVE-2026-0257). Exploitation requires a specific configuration (auth override cookies enabled with particular certificate setup), which narrows the attack surface but does not eliminate it.

The 2026 entries span two different PAN-OS attack surfaces -- User-ID Authentication Portal and GlobalProtect -- continuing the pattern of distinct product surfaces each generating critical pre-auth vulnerabilities.

---

## Attack Surface Pattern Analysis

PAN-OS KEV entries cluster around three distinct product surfaces:

| Attack Surface | KEV CVEs | Pattern |
|---------------|----------|---------|
| **Management web interface** | CVE-2017-15944, CVE-2024-0012, CVE-2024-9474, CVE-2025-0108, CVE-2025-0111 | 5 entries across 9 years. Two authentication bypasses 3 months apart (2024-0012, 2025-0108). Attackers chain bugs in this surface for escalation. |
| **GlobalProtect portal/gateway** | CVE-2019-1579, CVE-2024-3400, CVE-2026-0257 | 3 entries. Includes the CVSS 10.0 zero-day (CVE-2024-3400). The internet-facing VPN surface most aligned with nation-state targeting. |
| **Other (SAML, DNS Security, URL filtering, User-ID)** | CVE-2020-2021, CVE-2022-0028, CVE-2024-3393, CVE-2026-0300 | 4 entries across distinct subsystems. CVE-2026-0300 (User-ID Auth Portal) introduces a new pre-auth RCE surface. |

The management interface cluster is the most concerning recurring pattern. Five KEV entries against the same product surface -- including two authentication bypasses discovered three months apart and routinely chained together -- indicate a systemic challenge in hardening management-plane authentication, not isolated implementation bugs.

---

## Threat Actor Attribution

Palo Alto Networks products are documented targets of **China-nexus state espionage actors**. No ransomware-operator exploitation of PAN-OS has been confirmed in public reporting.

| Actor | CVE(s) | Campaign | Confidence | Source |
|-------|--------|----------|:----------:|--------|
| **UTA0218** | CVE-2024-3400 | Operation MidnightEclipse | Moderate (China suspected) | [Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), [Unit 42](https://unit42.paloaltonetworks.com/cve-2024-3400/) |

**UTA0218** is a Volexity designation for the actor behind Operation MidnightEclipse. Volexity assessed the group as "highly likely a state-backed threat actor based on the resources required to develop and exploit a vulnerability of this nature." The custom UPSTYLE backdoor was purpose-built for PAN-OS internals. National attribution to China is assessed at moderate confidence ([Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/cve-2024-3400/)).

Post-PoC exploitation of CVE-2024-0012/CVE-2024-9474 included [Daggerfly (a China-nexus group) deploying Linux implant variants](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild), alongside opportunistic actors deploying web shells and crypto miners ([Wiz](https://www.wiz.io/blog/cve-2024-0012-pan-os-vulnerability-exploited-in-the-wild)). No formal actor attribution has been published for the remaining 2025--2026 KEV entries.

**Structural note:** Palo Alto's threat actor profile is similar to Cisco's (state actors only, no ransomware) and distinct from Fortinet's or SonicWall's (state actors plus ransomware). The absence of ransomware-operator exploitation likely reflects PAN-OS's market position in large enterprises and government -- targets where state espionage yields higher value than ransom payments, and where defenders tend to patch more aggressively than SMB environments.

---

## Disclosure and Transparency Assessment

Palo Alto Networks publishes advisories via a [public security advisory portal](https://security.paloaltonetworks.com/) and maintains a dedicated PSIRT. The company does not have a documented pattern of silent patching comparable to [Fortinet's XORtigate episode](./Fortinet.md). Advisories are published and CVEs are assigned.

However, several disclosure patterns are worth noting:

1. **Reactive discovery.** CVE-2024-3400 -- the most severe PAN-OS vulnerability in the window -- was discovered by [Volexity](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/), not by Palo Alto. The vendor responded within days, but the exploit had been active for at least two weeks before any advisory or patch.

2. **Staged disclosure with delayed CVE assignment.** CVE-2024-0012 was initially disclosed as informational bulletin PAN-SA-2024-0015 on November 8, 2024, without a CVE. The [severity was raised on November 14 due to "observed threat activity"](https://security.paloaltonetworks.com/CVE-2024-0012), and the CVE was not assigned until November 18 -- ten days after the initial warning. During that window, defenders lacked the CVE identifier needed to track the vulnerability in standard tooling.

3. **Patch-before-KEV gap on CVE-2026-0300.** CISA added CVE-2026-0300 to KEV on May 6 with a May 9 deadline, but [patches did not ship until May 13](https://security.paloaltonetworks.com/CVE-2026-0300). For seven days, defenders had a federal mandate to mitigate with no vendor patch available -- only the workaround of restricting portal access to trusted zones.

4. **Advisory quality is generally strong.** PAN-OS advisories include affected version matrices, workarounds, and IOC indicators. The vendor has improved transparency since 2024, likely in response to the intensity of the CVE-2024-3400 incident.

Overall: Palo Alto's disclosure posture is better than the industry median for edge vendors. It is reactive rather than proactive on the highest-severity issues, and the staged-disclosure pattern for CVE-2024-0012 created a brief window where defenders had warning but not actionable remediation identifiers.

---

## Defender Implications

### 1. Restrict the management interface -- this is the single highest-leverage mitigation

Five of twelve KEV entries target the PAN-OS management web interface. Palo Alto's own [best-practices documentation](https://docs.paloaltonetworks.com/best-practices/10-1/internet-gateway-best-practices/network-security/management-interface-access) recommends restricting management access to trusted internal IPs only. Despite this, [11,000+ exposed management interfaces were found on Shodan](https://www.bleepingcomputer.com/news/security/palo-alto-networks-patches-two-firewall-zero-days-used-in-attacks/) at the time of the November 2024 exploitation wave, and [3,490 remained exposed during the February 2025 chain attacks](https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/). If the management interface is not internet-accessible, CVE-2024-0012, CVE-2024-9474, CVE-2025-0108, and CVE-2025-0111 are all eliminated as remote attack vectors. No patch cadence can substitute for this architectural control.

### 2. Treat any GlobalProtect zero-day as a potential state-actor indicator

CVE-2024-3400 was the #1 most exploited vulnerability in Mandiant's 2024 investigations ([M-Trends 2025](https://cloud.google.com/security/resources/m-trends)). It was deployed by a suspected state-backed actor using purpose-built malware. If you discover exploitation of a GlobalProtect zero-day, scope the incident response for state-level post-exploitation: lateral movement, credential harvesting, and persistent backdoors -- not just the firewall itself. Patching the firewall without investigating the internal environment is insufficient when the attacker has already moved laterally.

### 3. Monitor for chained exploitation and assume compounding risk

The February 2025 episode demonstrates a practical reality: attackers chain PAN-OS vulnerabilities across disclosure cycles. CVE-2025-0108 (February 2025) was immediately chained with CVE-2024-9474 (November 2024). Organizations that patched the November chain but did not patch February were still vulnerable to the combined attack. Treat PAN-OS security advisories as cumulative -- each new management-interface vulnerability should trigger re-assessment of prior patches, not just the current one.

---

> **Note on raw counts:** Palo Alto's 12 KEV entries place it in the middle of the range across vendors tracked in this repo (Fortinet: 18, Cisco: 13, Ivanti: 13, Palo Alto: 12). As [METHODOLOGY.md](../METHODOLOGY.md) documents, raw KEV counts partly reflect installed base, researcher attention, and adversary investment -- all of which are elevated for Palo Alto given its enterprise market position. The signal that market position alone does not explain: four pre-patch zero-days (CVE-2024-3400, CVE-2024-0012, CVE-2024-9474, CVE-2026-0300), and five management-interface vulnerabilities including two authentication bypasses three months apart. Weigh both the count and the pattern against your deployment and patch cadence.
