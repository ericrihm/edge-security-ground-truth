# Citrix (NetScaler ADC / NetScaler Gateway)

**Scope: NetScaler ADC and NetScaler Gateway (formerly Citrix ADC / Citrix Gateway / Citrix SD-WAN WANOP).** Remote access gateway and application delivery controller. 11 edge KEV entries. Product is now owned by Cloud Software Group following the 2022 acquisition from Elliott Management.

## Market Position

NetScaler ADC and NetScaler Gateway are among the most widely deployed SSL-VPN and remote-access platforms in enterprise and government environments globally. Alongside Ivanti Connect Secure and Fortinet FortiGate, Citrix/NetScaler completes the dominant trio of edge remote-access products with sustained CISA KEV representation. The product is embedded deeply in healthcare, financial services, and federal agencies — the same sectors repeatedly targeted by ransomware groups and nation-state actors hunting these devices specifically.

---

## The Defining Events

### CVE-2019-19781 — The Original Citrix Mass Exploitation (KEV: 2021-11-03)

[CVE-2019-19781](https://nvd.nist.gov/vuln/detail/CVE-2019-19781) (CVSS 9.8) is a path traversal vulnerability in Citrix ADC, Gateway, and SD-WAN WANOP that enables unauthenticated remote code execution. Citrix disclosed it on December 17, 2019. A patch did not exist until January 19, 2020 — a 33-day window during which tens of thousands of devices were exposed with no vendor-supplied fix.

[Mass exploitation began in January 2020](https://unit42.paloaltonetworks.com/threat-brief-cve-2019-19781-citrix-adc-and-citrix-gateway-vulnerability/) before patches were available. Multiple threat actors deployed webshells, cryptominers, and backdoors at scale. [CISA issued an advisory](https://www.cisa.gov/news-events/alerts/2020/01/13/critical-vulnerability-unpatched-citrix-application-delivery-controller) warning of active exploitation. Researchers later estimated [over 80,000 companies were vulnerable](https://www.zdnet.com/article/over-80000-companies-may-be-affected-by-citrix-vulnerability/) at peak. CVE-2019-19781 remains one of the most impactful edge appliance CVEs ever documented — the 33-day unpatched window combined with trivial exploitation prerequisites enabled a level of opportunistic compromise that defined the threat model for this entire product category.

### CVE-2023-3519 — Pre-Patch Zero-Day, Thousands Backdoored (KEV: 2023-07-19)

[CVE-2023-3519](https://nvd.nist.gov/vuln/detail/CVE-2023-3519) (CVSS 9.8) is an unauthenticated remote code execution vulnerability in NetScaler ADC and Gateway. Citrix patched it on July 18, 2023. CISA added it to the KEV catalog the following day — the simultaneous KEV listing confirmed the vulnerability had been exploited before the patch was released.

[CISA issued a dedicated advisory](https://www.cisa.gov/news-events/alerts/2023/07/20/cisa-releases-cybersecurity-advisory-threat-actors-exploiting-citrix-software-as-zero-day) reporting that threat actors — tracked by Mandiant as [UNC5027 and associated clusters](https://www.mandiant.com/resources/blog/citrix-bleed-exploitation) — had backdoored at least **2,000 NetScaler devices** before a patch existed, planting webshells and PHP backdoors. Post-patch, Shadowserver and others documented exploitation attempts continuing at scale against unpatched devices. The pre-patch exploitation window for CVE-2023-3519 mirrors CVE-2019-19781 but in a more compressed timeframe — adversaries had clearly established active access to zero-days affecting this product line.

### CVE-2023-4966 — "CitrixBleed", LockBit Ransomware, Critical Infrastructure (KEV: 2023-10-18)

[CVE-2023-4966](https://nvd.nist.gov/vuln/detail/CVE-2023-4966) (CVSS 9.4), publicly named **CitrixBleed**, is a sensitive information disclosure vulnerability enabling unauthenticated session token leakage from NetScaler ADC and Gateway. An attacker can hijack authenticated sessions without credentials, bypassing MFA entirely. Citrix disclosed and patched it on October 10, 2023, initially assigning a "High" severity rating — a characterization [widely criticized by researchers](https://www.bleepingcomputer.com/news/security/critical-citrix-bleed-vulnerability-exploited-by-lockbit-ransomware/) given that session hijack with MFA bypass in a gateway product is functionally equivalent to a critical compromise primitive.

Within weeks of public disclosure, **LockBit ransomware operators leveraged CitrixBleed** in high-profile attacks on [Boeing](https://www.securityweek.com/lockbit-ransomware-exploiting-citrix-bleed-vulnerability/), the Industrial and Commercial Bank of China (ICBC), DP World, and the law firm Allen & Overy. The ICBC breach caused disruption to U.S. Treasury markets. [CISA, FBI, and ACSC issued a joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) in November 2023 detailing exploitation patterns and urging immediate patching. The speed from public patch to mass ransomware exploitation — measured in days — reflects CitrixBleed's accessibility as an exploitation primitive once PoC code circulated.

---

## Transparency Assessment

Citrix publishes security bulletins and has a defined disclosure process. However, the three defining incidents reveal gaps in severity calibration: CVE-2019-19781 was disclosed without a patch and remained unpatched for 33 days; CVE-2023-3519 was exploited as a zero-day before any patch existed; and CVE-2023-4966 was initially rated "High" rather than "Critical" despite enabling unauthenticated session hijack and MFA bypass in a remote access gateway. In the latter case, the mismatch between initial vendor severity and real-world impact contributed to slower organizational prioritization during the window that mattered most.

---

## Risk Summary

With 11 edge KEV entries, Citrix sits in the middle of the pack among major edge appliance vendors — fewer than Fortinet (18), comparable to Ivanti. The distribution tells the more important story: the **2023 cluster** (CVE-2023-3519 in July, CVE-2023-4966 in October, CVE-2023-6548 and CVE-2023-6549 in January 2024) represents four exploited vulnerabilities in approximately six months, two of which enabled pre-auth RCE or session hijack at enterprise scale. The 2025 additions (CVE-2025-6543 and CVE-2025-5777, both NetScaler ADC and Gateway, KEV-listed June and July 2025) signal continued active exploitation of this product line. Organizations relying on NetScaler for remote access should treat it as a persistent high-value target requiring aggressive patch cadence, network segmentation of the management plane, continuous IOC monitoring for webshell indicators, and session invalidation procedures following any Citrix patch cycle.
