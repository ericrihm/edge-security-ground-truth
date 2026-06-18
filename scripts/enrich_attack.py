#!/usr/bin/env python3
"""
Operational ATT&CK / pre-auth / EOL enrichment for the edge-KEV dataset.

Adds three SOC-consumable fields to every CVE in kev_edge_enriched.json:

  attack_techniques  list[str]  Heuristic MITRE ATT&CK technique IDs derived
                                deterministically from CWE + exploitation
                                context (internet-facing edge appliance,
                                SSL-VPN / remote-access product family).
  pre_auth           bool       Conservative: True only where the CWE or the
                                CISA KEV shortDescription clearly indicates a
                                pre-authentication condition. Inferred, not
                                vendor-asserted.
  eol_at_kev_date    bool       True only for the documented end-of-life cases
                                (product was already EOL when CISA added the
                                CVE to KEV). Default False.

IMPORTANT — this is a HEURISTIC, OPERATIONAL mapping, NOT an authoritative
MITRE ATT&CK assignment. CISA does not publish per-CVE ATT&CK mappings for
most KEV entries, and CWE->technique is a many-to-many relationship. The
table below is a documented, reproducible best-effort to give defenders a
detection/hunting starting point. Treat every technique as a hypothesis to
validate against the actual exploit, not as ground truth. See
docs/MITRE-ATTACK.md for full methodology and limitations.

Reads:
  scripts/kev_edge_enriched.json   (CWE source — primary input, modified in place)
  CISA KEV catalog                 (shortDescription source for pre_auth signals)
                                   default: live CISA feed; override with --kev-file

Usage:
  python3 scripts/enrich_attack.py                       # auto-fetch live KEV feed
  python3 scripts/enrich_attack.py --kev-file kev.json    # use local KEV catalog
  python3 scripts/enrich_attack.py --dry-run              # report, do not write
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from collections import Counter, OrderedDict
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")
COUNTS_PATH = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ---------------------------------------------------------------------------
# Technique catalogue (IDs + names used in this enrichment).
# ---------------------------------------------------------------------------
TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1068": "Exploitation for Privilege Escalation",
    "T1078": "Valid Accounts",
    "T1212": "Exploitation for Credential Access",
    "T1552": "Unsecured Credentials",
    "T1505.003": "Server Software Component: Web Shell",
}

# ---------------------------------------------------------------------------
# Deterministic CWE -> technique table.
#
# Each CWE maps to the technique(s) most operationally relevant to how that
# weakness is exploited on an internet-facing edge appliance. T1190 (Exploit
# Public-Facing Application) is the base technique for nearly every edge CVE
# because the vulnerable surface is reachable over the network; it is added
# unconditionally for in-scope CVEs (see assign_techniques), so most CWE rows
# here only list the *additional* techniques beyond T1190.
#
# Categories:
#   auth bypass / missing auth (CWE-287/288/290/306/862/863/284/285) -> T1190
#       (+ T1078 Valid Accounts when the flaw yields a usable account/session)
#   memory-safety RCE (CWE-119/120/121/122/125/787/416/190/197/134/843/476)
#       -> T1190 (network-reachable code exec; no extra technique by default)
#   injection / code exec (CWE-77/78/89/94/502/434/611/918/917) -> T1190
#       (+ T1505.003 web shell when file-upload / web component is implicated)
#   path traversal / file disclosure (CWE-22/23/73/200/532/538/552)
#       -> T1190 (+ T1552 Unsecured Credentials when files/creds are exposed)
#   credential / session / token exposure (CWE-200/522/798/256/312/319/613)
#       -> T1212 / T1552 (CitrixBleed-class session-token theft)
#   privilege escalation / permissions (CWE-269/250/732/276/266/267/268)
#       -> T1068
#   crypto / signature / verification (CWE-295/327/347/345/924) -> T1190
#   everything else (input validation, logic, resource) -> T1190 only
#
# Mapping is documented in docs/MITRE-ATTACK.md and is intentionally
# conservative: when a CWE does not clearly imply a secondary technique, only
# the base T1190 is assigned rather than guessing.
# ---------------------------------------------------------------------------
CWE_TECHNIQUE_TABLE = {
    # --- Authentication bypass / missing authentication ---
    # The flaw itself is exploited over the network (T1190); where it yields a
    # usable valid account/session, T1078 is added.
    "CWE-287": ["T1190", "T1078"],   # Improper Authentication
    "CWE-288": ["T1190", "T1078"],   # Auth Bypass Using Alternate Path/Channel
    "CWE-290": ["T1190", "T1078"],   # Auth Bypass by Spoofing
    "CWE-306": ["T1190", "T1078"],   # Missing Authentication for Critical Function
    "CWE-862": ["T1190", "T1078"],   # Missing Authorization
    "CWE-863": ["T1190", "T1078"],   # Incorrect Authorization
    "CWE-284": ["T1190", "T1078"],   # Improper Access Control
    "CWE-285": ["T1190", "T1078"],   # Improper Authorization
    "CWE-639": ["T1190", "T1078"],   # Authorization Bypass Through User-Controlled Key
    "CWE-1390": ["T1190", "T1078"],  # Weak Authentication

    # --- Injection / code execution ---
    "CWE-77":  ["T1190"],            # Command Injection
    "CWE-78":  ["T1190"],            # OS Command Injection
    "CWE-89":  ["T1190"],            # SQL Injection
    "CWE-94":  ["T1190"],            # Code Injection
    "CWE-95":  ["T1190"],            # Eval Injection
    "CWE-502": ["T1190"],            # Deserialization of Untrusted Data
    "CWE-917": ["T1190"],            # Expression Language Injection
    "CWE-611": ["T1190"],            # XXE
    "CWE-918": ["T1190"],            # SSRF
    "CWE-434": ["T1190", "T1505.003"],  # Unrestricted File Upload -> web shell

    # --- Memory safety (network-reachable RCE) ---
    "CWE-119": ["T1190"],   # Buffer Errors
    "CWE-120": ["T1190"],   # Classic Buffer Overflow
    "CWE-121": ["T1190"],   # Stack Buffer Overflow
    "CWE-122": ["T1190"],   # Heap Buffer Overflow
    "CWE-125": ["T1190"],   # Out-of-bounds Read
    "CWE-787": ["T1190"],   # Out-of-bounds Write
    "CWE-416": ["T1190"],   # Use After Free
    "CWE-190": ["T1190"],   # Integer Overflow
    "CWE-197": ["T1190"],   # Numeric Truncation Error
    "CWE-134": ["T1190"],   # Format String
    "CWE-843": ["T1190"],   # Type Confusion
    "CWE-476": ["T1190"],   # NULL Pointer Dereference
    "CWE-835": ["T1190"],   # Infinite Loop / Uncontrolled Iteration

    # --- Path traversal / file & credential disclosure ---
    "CWE-22":  ["T1190", "T1552"],   # Path Traversal (often leaks creds/config)
    "CWE-23":  ["T1190", "T1552"],   # Relative Path Traversal
    "CWE-73":  ["T1190", "T1552"],   # External Control of File Name or Path
    "CWE-552": ["T1190", "T1552"],   # Files/Directories Accessible to External Parties

    # --- Credential / session / token exposure ---
    "CWE-200": ["T1190", "T1212", "T1552"],  # Info Exposure (CitrixBleed-class)
    "CWE-522": ["T1190", "T1552"],   # Insufficiently Protected Credentials
    "CWE-798": ["T1190", "T1552"],   # Hard-coded Credentials
    "CWE-256": ["T1190", "T1552"],   # Plaintext Storage of Password
    "CWE-312": ["T1190", "T1552"],   # Cleartext Storage of Sensitive Info
    "CWE-319": ["T1190", "T1552"],   # Cleartext Transmission of Sensitive Info
    "CWE-613": ["T1190", "T1212"],   # Insufficient Session Expiration
    "CWE-532": ["T1190", "T1552"],   # Sensitive Info in Log File

    # --- Privilege escalation / permission / ownership ---
    "CWE-269": ["T1068"],   # Improper Privilege Management
    "CWE-250": ["T1068"],   # Execution with Unnecessary Privileges
    "CWE-732": ["T1068"],   # Incorrect Permission Assignment
    "CWE-276": ["T1068"],   # Incorrect Default Permissions
    "CWE-266": ["T1068"],   # Incorrect Privilege Assignment
    "CWE-267": ["T1068"],   # Privilege Defined With Unsafe Actions
    "CWE-268": ["T1068"],   # Privilege Chaining

    # --- Crypto / signature / verification ---
    "CWE-295": ["T1190"],   # Improper Certificate Validation
    "CWE-327": ["T1190"],   # Broken/Risky Crypto Algorithm
    "CWE-347": ["T1190"],   # Improper Verification of Cryptographic Signature
    "CWE-345": ["T1190"],   # Insufficient Verification of Data Authenticity
    "CWE-924": ["T1190"],   # Improper Enforcement of Message Integrity
    "CWE-494": ["T1190"],   # Download of Code Without Integrity Check
    "CWE-565": ["T1190"],   # Reliance on Cookies w/o Validation
    "CWE-473": ["T1190"],   # PHP External Variable Modification
    "CWE-406": ["T1190"],   # Insufficient Control of Network Message Volume
    "CWE-653": ["T1190"],   # Improper Isolation/Compartmentalization
    "CWE-664": ["T1190"],   # Improper Control of a Resource Through its Lifetime
    "CWE-772": ["T1190"],   # Missing Release of Resource
    "CWE-754": ["T1190"],   # Improper Check for Unusual Conditions
    "CWE-79":  ["T1190"],   # XSS (reflected/stored on the appliance web UI)
    "CWE-20":  ["T1190"],   # Improper Input Validation
}

# Base technique applied to every in-scope edge CVE: the vulnerable surface is
# an internet-facing appliance, so initial access is Exploit Public-Facing App.
BASE_TECHNIQUE = "T1190"

# ---------------------------------------------------------------------------
# Product families whose primary function is SSL-VPN / remote-access. CVEs in
# these families also get T1133 (External Remote Services), because the abused
# surface is the remote-access service itself. Matched against the vendor name
# and the KEV product/shortDescription text.
# ---------------------------------------------------------------------------
REMOTE_ACCESS_VENDORS = {
    "Ivanti",          # Connect Secure / Pulse Connect Secure (SSL-VPN)
    "Citrix",          # NetScaler Gateway (SSL-VPN / ICA proxy)
    "Array Networks",  # ArrayOS AG SSL-VPN
}
# Regex over product + shortDescription that also flags a remote-access surface
# for vendors whose appliances span both firewall and VPN roles.
REMOTE_ACCESS_RE = re.compile(
    r"SSL[\s-]?VPN|SSLVPN|Secure Remote Access|Remote Access|"
    r"Connect Secure|Pulse Connect|NetScaler Gateway|Citrix Gateway|"
    r"SMA\s?\d|Secure Mobile Access|GlobalProtect|AnyConnect|Firebox\b.*VPN",
    re.I,
)

# ---------------------------------------------------------------------------
# Pre-auth inference.
#   CONSERVATIVE: pre_auth=True only when the CWE clearly denotes a missing /
#   bypassable authentication condition, OR the KEV shortDescription contains
#   an explicit pre-auth phrase. Everything else -> False. This is INFERRED,
#   never a vendor assertion.
# ---------------------------------------------------------------------------
PRE_AUTH_CWES = {
    "CWE-287",   # Improper Authentication
    "CWE-288",   # Auth Bypass Using Alternate Path/Channel
    "CWE-290",   # Auth Bypass by Spoofing
    "CWE-306",   # Missing Authentication for Critical Function
    "CWE-1390",  # Weak Authentication
}
PRE_AUTH_DESC_RE = re.compile(
    r"unauthenticated|without authentication|pre-?auth|prior to authentication|"
    r"missing authentication|authentication bypass|bypass authentication|"
    r"no authentication|does not require authentication|"
    r"allows? (?:a )?remote(?:,? )?(?:unauthenticated|anonymous)",
    re.I,
)

# ---------------------------------------------------------------------------
# Documented end-of-life cases: product was already past EOL / end-of-support
# when CISA added the CVE to KEV. These are the ONLY entries that get
# eol_at_kev_date=True; the set is hand-verified, not inferred.
# ---------------------------------------------------------------------------
EOL_CVES = {
    "CVE-2015-7755",   # Juniper ScreenOS (EOL line; backdoor 'Dual_EC' era)
    "CVE-2020-29574",  # Sophos CyberoamOS (Cyberoam acquired; OS sunset)
    "CVE-2020-15069",  # Sophos XG Firewall v17.x (firmware branch EOL)
}


def load_kev_catalog(kev_file):
    """Return {cveID: shortDescription} from a local KEV file or the live feed."""
    if kev_file:
        if not os.path.isfile(kev_file):
            sys.exit(f"ERROR: --kev-file not found: {kev_file}")
        with open(kev_file, encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        print(f"# Fetching live CISA KEV feed from {KEV_URL} ...", file=sys.stderr)
        req = urllib.request.Request(KEV_URL, headers={
            "Accept": "application/json",
            "User-Agent": "edge-security-ground-truth/1.0",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    desc = {}
    for v in data.get("vulnerabilities", []):
        desc[v.get("cveID", "")] = v.get("shortDescription", "") or ""
    return desc, data.get("catalogVersion", "unknown")


def assign_techniques(vendor, cwe, product_text):
    """Return an ordered, de-duplicated list of ATT&CK technique IDs."""
    techniques = OrderedDict()  # preserve order, dedupe
    techniques[BASE_TECHNIQUE] = None  # every in-scope edge CVE is T1190

    if cwe:
        for t in CWE_TECHNIQUE_TABLE.get(cwe, []):
            techniques[t] = None

    # Remote-access surface -> add External Remote Services.
    if vendor in REMOTE_ACCESS_VENDORS or REMOTE_ACCESS_RE.search(product_text or ""):
        techniques["T1133"] = None

    return list(techniques.keys())


def infer_pre_auth(cwe, short_desc):
    """CONSERVATIVE pre-auth inference. Returns bool."""
    if cwe in PRE_AUTH_CWES:
        return True
    if short_desc and PRE_AUTH_DESC_RE.search(short_desc):
        return True
    return False


def enrich(enriched, kev_desc):
    """Mutate enriched in place; return (counter, per_technique_rollup)."""
    tech_counter = Counter()
    pre_auth_count = 0
    eol_count = 0
    total = 0
    per_technique = {}  # technique -> list of CVEs

    for vendor, cves in enriched.items():
        if vendor.startswith("_") or not isinstance(cves, dict):
            continue
        for cve_id, fields in cves.items():
            total += 1
            cwe = fields.get("cwe")
            short_desc = kev_desc.get(cve_id, "")
            # product_text feeds the remote-access regex; the KEV short
            # description names the product/feature for non-pure-VPN vendors.
            product_text = short_desc

            techniques = assign_techniques(vendor, cwe, product_text)
            pre_auth = infer_pre_auth(cwe, short_desc)
            eol = cve_id in EOL_CVES

            fields["attack_techniques"] = techniques
            fields["pre_auth"] = pre_auth
            fields["eol_at_kev_date"] = eol

            for t in techniques:
                tech_counter[t] += 1
                per_technique.setdefault(t, []).append((vendor, cve_id))
            if pre_auth:
                pre_auth_count += 1
            if eol:
                eol_count += 1

    summary = {
        "total": total,
        "pre_auth_count": pre_auth_count,
        "eol_count": eol_count,
        "technique_counts": tech_counter,
    }
    return summary, per_technique


def print_summary(summary, per_technique, catalog_version):
    print("\n" + "=" * 70)
    print("ATT&CK / PRE-AUTH / EOL ENRICHMENT SUMMARY (heuristic)")
    print("=" * 70)
    print(f"\nKEV catalog version: {catalog_version}")
    print(f"Total CVEs enriched: {summary['total']}")
    print(f"  pre_auth = True:        {summary['pre_auth_count']}")
    print(f"  pre_auth = False:       {summary['total'] - summary['pre_auth_count']}")
    print(f"  eol_at_kev_date = True: {summary['eol_count']}")

    print(f"\nATT&CK technique distribution (CVEs per technique):")
    for t, n in summary["technique_counts"].most_common():
        name = TECHNIQUE_NAMES.get(t, t)
        bar = "#" * n
        print(f"  {t:<12} {n:>3}  {name:<42} {bar}")

    print(f"\nEOL-at-KEV-date CVEs:")
    for cve in sorted(EOL_CVES):
        rollup = [v for techs in per_technique.values() for (v, c) in techs if c == cve]
        vendor = rollup[0] if rollup else "?"
        print(f"  {cve:<18} {vendor}")


def main():
    parser = argparse.ArgumentParser(
        description="Heuristic ATT&CK / pre-auth / EOL enrichment for the edge-KEV dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--enriched", default=ENRICHED_PATH,
                        help=f"Enriched JSON to modify in place (default: {ENRICHED_PATH})")
    parser.add_argument("--kev-file", default=None,
                        help="Local CISA KEV catalog JSON for shortDescription "
                             "(default: auto-fetch live CISA feed)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute and print summary but do not write the file")
    args = parser.parse_args()

    if not os.path.isfile(args.enriched):
        sys.exit(f"ERROR: enriched file not found: {args.enriched}")

    with open(args.enriched, encoding="utf-8") as fh:
        enriched = json.load(fh)

    kev_desc, catalog_version = load_kev_catalog(args.kev_file)

    summary, per_technique = enrich(enriched, kev_desc)

    # Verify EOL targets actually exist in the dataset.
    all_cves = set()
    for vendor, cves in enriched.items():
        if vendor.startswith("_") or not isinstance(cves, dict):
            continue
        all_cves.update(cves.keys())
    missing_eol = EOL_CVES - all_cves
    if missing_eol:
        sys.exit(f"ERROR: documented EOL CVEs not found in dataset: {sorted(missing_eol)}")

    # Record provenance in metadata.
    meta = enriched.setdefault("_metadata", {})
    meta["attack_enriched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta["attack_kev_catalog_version"] = catalog_version
    meta["attack_mapping"] = (
        "heuristic CWE+exploitation->ATT&CK technique mapping; "
        "see docs/MITRE-ATTACK.md — NOT an authoritative MITRE assignment"
    )
    meta["attack_pre_auth_count"] = summary["pre_auth_count"]
    meta["attack_eol_count"] = summary["eol_count"]

    print_summary(summary, per_technique, catalog_version)

    if args.dry_run:
        print("\n[DRY RUN] No file written.")
        return 0

    with open(args.enriched, "w", encoding="utf-8") as fh:
        json.dump(enriched, fh, indent=2)
    print(f"\n# Wrote {args.enriched}")

    if summary["total"] != 115:
        sys.exit(f"ERROR: expected 115 CVEs, enriched {summary['total']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
