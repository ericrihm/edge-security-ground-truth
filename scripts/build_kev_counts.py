#!/usr/bin/env python3
"""
Reproducible edge-KEV counter.

Counts CISA KEV entries for each vendor's INTERNET-FACING EDGE APPLIANCE
(firewall / SSL-VPN / remote-access gateway) only, by KEV dateAdded within the
scope window. This script IS the methodology for the `KEV (edge)` column —
re-run it against the live feed to reproduce or update every count.

Usage:
  curl -s -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  python3 build_kev_counts.py kev.json
"""
import json, sys, re

WINDOW = ("2020-01-01", "2026-12-31")  # by KEV dateAdded

# Per-vendor edge-product scope. include = regex that the `product` field must match;
# exclude = regex that disqualifies it. Scope = firewall + SSL-VPN/remote-access gateway ONLY.
SCOPE = {
    "SonicWall":            dict(include=r"SonicOS|SMA|SSLVPN|SSL[- ]?VPN|Secure Remote Access|SRA",
                                 exclude=r"Email Security"),
    "Ivanti":               dict(include=r"Connect Secure|Pulse Connect Secure|Policy Secure",
                                 exclude=r"MobileIron|Endpoint Manager|EPMM|EPM|Sentry|Cloud Services Appliance|Virtual Traffic Manager"),
    "Juniper":              dict(include=r"Junos OS|ScreenOS",  # SRX firewall / J-Web / ScreenOS VPN-firewall
                                 exclude=r""),
    "Cisco":                dict(include=r"Adaptive Security Appliance|ASA|Firepower Threat Defense|FTD|Secure Firewall",
                                 exclude=r"Management Center|FMC"),
    "Palo Alto Networks":   dict(include=r"PAN-OS",
                                 exclude=r"Expedition"),
    "Fortinet":             dict(include=r"FortiOS|FortiProxy",
                                 exclude=r"FortiClient|FortiManager|FortiWeb|FortiMail|FortiVoice|FortiNDR"),
}

def in_window(d):
    return WINDOW[0] <= d <= WINDOW[1]

def main(path):
    k = json.load(open(path))
    vulns = k.get("vulnerabilities", [])
    print(f"# CISA KEV catalog {k.get('catalogVersion')} — {len(vulns)} total entries")
    print(f"# Scope: internet-facing edge appliance (firewall / SSL-VPN / remote-access), by KEV dateAdded {WINDOW[0]}..{WINDOW[1]}\n")
    out = {}
    for vendor, rule in SCOPE.items():
        inc, exc = re.compile(rule["include"], re.I), (re.compile(rule["exclude"], re.I) if rule["exclude"] else None)
        rows = []
        for v in vulns:
            if v.get("vendorProject", "").lower() != vendor.lower():
                continue
            prod = v.get("product", "")
            desc = v.get("shortDescription", "")
            # CISA labels some in-scope CVEs with a generic "Multiple Products" product field
            # (e.g. FortiOS bugs CVE-2022-40684, CVE-2024-23113, CVE-2026-24858). For those, also
            # match the shortDescription so the edge product isn't silently dropped. Exclude rules
            # still test the product field only, so a generic-labeled entry isn't dropped merely
            # because its description lists an out-of-scope sibling product.
            hay = prod if "multiple" not in prod.lower() else prod + " " + desc
            if not inc.search(hay):
                continue
            if exc and exc.search(prod):
                continue
            if not in_window(v.get("dateAdded", "")):
                continue
            rows.append((v["cveID"], prod, v["dateAdded"]))
        rows.sort(key=lambda r: r[2])
        out[vendor] = [r[0] for r in rows]
        print(f"## {vendor}: {len(rows)} edge-KEV entries")
        for cve, prod, da in rows:
            print(f"   {cve:18} {da}  {prod}")
        print()
    json.dump(out, open("kev_edge_counts.json", "w"), indent=2)
    print("# wrote kev_edge_counts.json  |  counts:", {v: len(c) for v, c in out.items()})

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "kev.json")
