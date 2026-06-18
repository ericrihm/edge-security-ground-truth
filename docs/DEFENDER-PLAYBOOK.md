# Defender Playbook: Edge Appliance Security Operations

A practical response guide for security teams managing firewalls, SSL-VPNs, and remote-access gateways. Every recommendation below maps to a documented exploitation pattern from this repository. No theory without precedent.

---

## 1. Architecture

### Management Plane Isolation

Expose the management interface to the internet and you will be compromised. This is not a risk statement; it is the documented outcome for every vendor in this dataset.

- **Bind management interfaces to a dedicated OOB VLAN** with no route to the internet. The CVE-2024-0012 + CVE-2024-9474 PAN-OS chain exploited internet-exposed management interfaces to gain root. Palo Alto explicitly documents this configuration as inadvisable; thousands of customers ran it anyway.
- **ACL management access to named jump hosts only.** ArcaneDoor (CVE-2024-20353 + CVE-2024-20359) targeted government ASA/FTD management planes directly. Line Runner persisted across reboots via a legacy VPN client pre-load hook on `disk0`.
- **Disable unused management protocols.** J-Web on Juniper SRX/EX was the attack surface for the 2023 chain (CVE-2023-36844 and siblings). If you do not use J-Web, disable it. Same for TMUI on F5 BIG-IP (CVE-2020-5902) and iControl REST (CVE-2022-1388).

### VPN Segmentation

- **Terminate SSL-VPN on a dedicated interface/VLAN**, not on the same interface as management. Fortinet's `sslvpnd` has produced four separate KEV entries (CVE-2020-12812, CVE-2022-42475, CVE-2023-27997, CVE-2024-21762) -- co-locating VPN and management doubles the pre-auth attack surface.
- **Enforce MFA on all VPN sessions.** CVE-2020-12812 bypassed FortiOS 2FA via username-case manipulation; CVE-2023-4966 (CitrixBleed) leaked session tokens that bypassed MFA entirely. MFA is necessary but not sufficient when session tokens themselves are exfiltrable.
- **Rotate VPN credentials on hardware migration.** Arctic Wolf documented 30+ Akira/Fog ransomware intrusions through SonicWall CVE-2024-40766 where operators reused Gen 6 credentials on Gen 7 hardware without resetting passwords.

### Logging Requirements

- **Ship logs off-box in real time.** UNC3886 backdoors on Juniper MX routers included scripts that explicitly disabled logging. If logs live only on the appliance, a compromised appliance erases its own trail.
- **Log all management-plane authentication** (success and failure), configuration changes, firmware upgrades, and VPN session establishment/teardown.
- **Retain edge device logs for a minimum of 90 days.** The ArcaneDoor actor (UAT4356) began staging infrastructure in November 2023 and peaked in January 2024 -- a multi-month dwell time that 30-day retention would miss.
- **Alert on any outbound connection initiated by the edge device itself** to a destination not in your infrastructure (NTP, syslog, update servers). Edge devices should not initiate arbitrary outbound connections.

---

## 2. Patch Cadence

### Why Monthly Cycles Fail for Edge Devices

The 2024 Mandiant/GTIG average time-to-exploit was **negative one day** -- exploited before the patch existed. 44% of 2024 zero-days targeted security/edge appliances specifically. A monthly patch window means you run unpatched for weeks against threats that weaponize in hours.

Documented exploitation timelines from this dataset:

| CVE | Vendor | Advisory-to-mass-exploitation |
|-----|--------|-------------------------------|
| CVE-2022-1388 | F5 | **2 days** from PoC to mass compromise |
| CVE-2023-36844 chain | Juniper | **8 days** from advisory to mass exploitation |
| CVE-2024-0012 + CVE-2024-9474 | Palo Alto | **~48 hours** from PoC |
| CVE-2024-3400 | Palo Alto | **0 days** (pre-patch zero-day) |
| CVE-2023-46805 + CVE-2024-21887 | Ivanti | **0 days** (exploited before advisory) |
| CVE-2024-21762 | Fortinet | **~1 day** (KEV added day after disclosure) |

**Establish an emergency patch window for edge devices: 24-48 hours from vendor advisory for critical/KEV-listed vulnerabilities.** This is separate from your regular patch cycle.

### Monitoring CISA KEV for Your Vendors

- **RSS feed:** Subscribe to `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` -- parse daily, filter by your vendor product strings.
- **CISA KEV API:** Pull the JSON catalog programmatically. Filter by `vendorProject` matching your deployed vendors. Trigger alerts on new entries.
- **GitHub Actions automation:** Run a scheduled workflow (every 6 hours) that fetches the KEV JSON, diffs against the prior run, and posts to Slack/Teams/PagerDuty on new entries matching your vendor list. The `scripts/build_kev_counts.py` script in this repo demonstrates the vendor-product filtering logic.
- **VulnCheck and Shadowserver** provide supplementary exploitation telemetry for edge devices. Cross-reference KEV with these sources for exploitation velocity context.

---

## 3. When a KEV Drops -- Response Procedure

### Hours 0-4: Triage and Containment Decision

1. **Confirm applicability.** Match the CVE against your asset inventory: exact product, version, feature enablement (e.g., GlobalProtect enabled, Remote Access VPN blade enabled, J-Web exposed). CVE-2024-24919 affected Check Point only with Remote Access VPN or Mobile Access blade enabled.
2. **Check pre-auth status.** If the CVE is pre-authentication and your appliance is internet-facing, treat it as actively exploited against you until proven otherwise. Do not wait for vendor confirmation of in-the-wild exploitation -- CISA already confirmed it by adding it to KEV.
3. **Containment decision matrix:**
   - Pre-auth RCE + internet-facing = **immediate containment** (restrict access to the vulnerable service via upstream ACL or take offline if operationally feasible).
   - Auth-required or local-only = **accelerated patch** (24h window).
   - If the vulnerability is in a feature you can disable (J-Web, TMUI, iControl REST), **disable it now** as a compensating control while patching.
4. **Notify your IR team.** Open an incident ticket even if you assess low risk. The ticket becomes the audit trail if you later discover compromise.

### Hours 4-24: Patch or Compensating Control

1. **Apply the vendor patch.** For Fortinet, this means a full firmware upgrade -- Fortinet does not ship discrete security patches. Plan for the reboot. Validate the firmware hash against the vendor's published checksum.
2. **If the patch is not yet available** (as happened with Ivanti CVE-2023-46805 + CVE-2024-21887 and Citrix CVE-2019-19781): apply vendor-supplied mitigations, restrict access to the vulnerable interface via ACL, and prepare to disconnect the device entirely per CISA ED 24-01 precedent.
3. **Deploy virtual patches** (IPS/WAF signatures) upstream if available. These are stopgaps, not fixes.
4. **Document the pre-patch state.** Capture a configuration backup and a full packet capture sample from the management/VPN interface before patching. This is your forensic baseline.

### Hours 24-72: Assume-Breach Hunt

Patching closes the door. It does not tell you whether anyone walked through it first.

1. **Review logs for the exploitation window** -- from the date the vulnerability became publicly known (or earlier if a zero-day) through patch application. Look for:
   - Anomalous authentication events (unexpected admin logins, VPN sessions from unusual geolocations).
   - Configuration changes you did not make.
   - New user accounts, modified ACLs, or altered routing.
   - Outbound connections from the appliance to non-infrastructure IPs.
2. **Run vendor-specific IOC checks** (see Section 4).
3. **Check for lateral movement** from the edge device into your internal network. Compromised edge devices are pivot points, not final targets. The Marquis/SonicWall breach chain went: MySonicWall backup breach -> firewall compromise -> ransomware across 74 banks.
4. **Engage your SIEM.** Correlate edge device logs with endpoint telemetry. Look for credential reuse from accounts that authenticated through the compromised VPN.

### Post-Patch: Verify No Prior Compromise

1. **Validate the patch.** Confirm the running firmware/software version matches the patched version. For Fortinet, diff the running build against the advisory's fixed version list -- silent patches mean the version number alone may not tell the full story.
2. **Rotate all credentials** that transited the edge device: VPN user passwords, admin passwords, API keys, certificates. CitrixBleed (CVE-2023-4966) demonstrated that session tokens leaked pre-patch remain valid post-patch until explicitly invalidated.
3. **Re-run integrity checks** (where available) 7 and 30 days post-patch to detect delayed persistence activation.

---

## 4. Vendor-Specific Post-Patch Steps

### Fortinet: Symlink Persistence (CVE-2022-42475, CVE-2023-27997, CVE-2024-21762)

In April 2025, CISA alerted that threat actors maintained **read-only persistent access** to patched FortiGates via symlink manipulation in the SSL-VPN filesystem. This technique survives firmware upgrades.

- **Check for symlinks in the SSL-VPN language directory** that point outside the expected webroot. Fortinet published [guidance](https://www.fortinet.com/blog/psirt-blogs/analysis-of-threat-actor-activity) for detecting this.
- **Examine `sslvpnd` crash logs** for heap corruption indicators consistent with CVE-2022-42475/CVE-2023-27997 exploitation.
- **If symlink persistence is found:** the device was compromised pre-patch. Initiate full IR. A firmware upgrade alone is insufficient -- the symlink persists through it.
- **FortiBleed context (June 2026):** ~74,000 FortiGate credentials surfaced from a convergence of CVE-2026-24858, legacy hashing, and credential reuse. If your device was internet-facing and running a vulnerable version, assume credential exposure and rotate everything.

### SonicWall: Cloud Backup Exposure (MySonicWall Breach)

The September 2025 MySonicWall breach exposed AES-256-encrypted credentials, MFA scratch codes, VPN configurations, and network topology for **all cloud-backup customers** (initially stated as <5%, revised to 100%).

- **If you ever used MySonicWall cloud backup:** assume your firewall configuration, credentials, and MFA seeds are compromised. Rotate all credentials. Regenerate MFA tokens. Review firewall rules for unauthorized modifications.
- **Check for configurations deployed from stolen backups.** The Marquis attack used extracted configuration data to compromise a SonicWall firewall before SonicWall's public disclosure.
- **Disable cloud backup** until SonicWall provides verifiable remediation evidence. Store configuration backups locally or on infrastructure you control.

### Citrix: Session Invalidation (CitrixBleed Lesson)

CVE-2023-4966 (CitrixBleed) leaked session tokens that **remained valid after patching**. LockBit used this to hit Boeing, ICBC, DP World, and Allen & Overy.

- **After any Citrix NetScaler patch: kill all active sessions and force re-authentication.** Patching without session invalidation leaves stolen tokens usable.
- **Search for webshells** in standard NetScaler web directories. CVE-2023-3519 resulted in 2,000+ devices backdoored with PHP webshells pre-patch.
- Common webshell paths: `/netscaler/ns_gui/vpn/`, `/var/vpn/bookmark/`, `/var/tmp/`.

### Palo Alto Networks: UPSTYLE Backdoor (CVE-2024-3400)

Operation MidnightEclipse (UTA0218) deployed the UPSTYLE backdoor via CVE-2024-3400 and moved laterally into victim networks.

- **Check for UPSTYLE indicators:** anomalous cron jobs, unexpected Python processes, files in `/opt/panlogs/tmp/` or `/var/log/pan/` that are not standard PAN-OS artifacts.
- **Review GlobalProtect access logs** for sessions originating from known UTA0218 infrastructure (consult Volexity and Palo Alto's published IOCs).
- **For CVE-2024-0012 + CVE-2024-9474:** check for unauthorized admin accounts created via the management interface auth bypass. Any account created during the exposure window is suspect.

### Ivanti: Integrity Checker Limitations + Factory Reset

CISA found that Ivanti's Integrity Checker Tool (ICT) **can be defeated** by sophisticated adversaries, and that factory resets **may not remove root-level persistence**. Ivanti disputes the factory-reset finding.

- **Run the external ICT** (not the built-in version) after patching. Treat a clean result as one signal, not proof of integrity.
- **For high-assurance environments: factory reset and rebuild from known-good configuration** rather than patching in place. This is CISA's recommendation despite Ivanti's objection.
- **Check for SPAWN, DRYHOOK, and PHASEJAM malware families** (CVE-2025-0282 post-exploitation).
- **Monitor for webshells** deployed by UNC5221: paths vary but commonly target the Ivanti web application directories.

### Cisco ASA/FTD: ArcaneDoor Implants

UAT4356/STORM-1849 deployed Line Dancer (memory-resident) and Line Runner (persistent across reboots) via CVE-2024-20353 + CVE-2024-20359, and RayInitiator + LINE VIPER via CVE-2025-20333 + CVE-2025-20362.

- **Check `disk0:` for unexpected files** in the VPN client pre-load directory (Line Runner persistence path).
- **Memory-resident implants (Line Dancer) do not survive reboot** but indicate prior compromise requiring full IR.
- **Follow Cisco PSIRT's ArcaneDoor response guide** and cross-reference with the joint CISA/ASD/CCCS/NCSC indicators published alongside the April 2024 advisory.

### F5 BIG-IP

- **After CVE-2022-1388 (iControl REST) or CVE-2020-5902 (TMUI):** check for unauthorized bash commands executed via the REST API. Exploitation left clear forensic artifacts in `/var/log/restjavad.0.log`.
- **After CVE-2023-46747 + CVE-2023-46748:** check for SQL injection artifacts in the Configuration Utility database and unauthorized configuration changes.

### Juniper SRX/EX

- **After the J-Web chain (CVE-2023-36844 siblings):** check `/webauth_operation.php` access logs for exploitation attempts. Look for environment variable injection payloads.
- **For UNC3886 (CVE-2025-21590 on MX routers):** TINYSHELL-based backdoors injected into legitimate Junos processes in memory. Standard file-based IOC scans will miss them. Require a process-integrity check against known-good baselines.

---

## 5. Assume-Breach Indicators

### Common IOCs Across Edge Device Compromises

These patterns recur across vendors and campaigns documented in this repository:

- **Unexpected admin accounts or modified admin credentials** -- check immediately post-patch.
- **Webshells in vendor web directories** -- PHP, JSP, or ASPX files outside the vendor's standard file manifest.
- **Cron jobs or scheduled tasks not in the vendor baseline** -- UPSTYLE (Palo Alto), Line Runner (Cisco), and UNC3886 (Juniper) all used persistence mechanisms tied to scheduled execution.
- **Modified or missing log files** -- the absence of logs during the exploitation window is itself an indicator. UNC3886 backdoors explicitly disabled logging on Juniper devices.
- **Unexpected certificates or SSH keys** -- CVE-2024-24919 (Check Point) exfiltrated SSH keys and password hashes.

### Network-Level Detection

- **Outbound connections from edge devices to non-infrastructure IPs.** Your firewall should talk to NTP, syslog, DNS, and update servers. Anything else is anomalous. Alert on it.
- **DNS queries from edge devices to domains not in your resolver allowlist.** C2 callbacks from implants commonly use DNS for exfiltration.
- **Encrypted tunnel establishment from the edge device** (not through it) to external endpoints. This is the hallmark of a reverse shell or C2 channel.
- **Traffic volume anomalies.** A firewall exfiltrating configuration data or credential databases will show unusual upload patterns on its management interface.

### Configuration Tampering Indicators

- **Firewall rule changes during the exploitation window** -- diff current ruleset against your last known-good backup.
- **New VPN profiles, authentication realms, or RADIUS/LDAP server entries** you did not create.
- **Routing table modifications** -- particularly static routes pointing internal subnets toward external next-hops.
- **Disabled security features** -- IPS signatures turned off, logging disabled, integrity monitoring stopped.
- **Certificate replacements** -- if the appliance's TLS certificate was replaced, assume a MitM capability was established.

---

## Appendix: Quick-Reference Response Checklist

```
[ ] KEV drops for your vendor
[ ] Confirm product/version/feature applicability
[ ] Pre-auth + internet-facing? -> Immediate containment (restrict or offline)
[ ] Capture pre-patch forensic baseline (config + pcap)
[ ] Apply patch or compensating control within 24h
[ ] Run vendor-specific IOC checks (Section 4)
[ ] Kill all active sessions, force re-authentication
[ ] Rotate all credentials that transited the device
[ ] Hunt for lateral movement into internal network
[ ] Review logs for the full exploitation window
[ ] Validate patch, re-check integrity at day 7 and day 30
[ ] Update asset inventory and close incident ticket
```

---

*Cite specific CVEs, advisories, and threat actors from the [edge-security-ground-truth](../README.md) repository. Last updated 2026-06-18.*
