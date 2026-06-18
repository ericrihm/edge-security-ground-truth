#!/usr/bin/env python3
"""
CWE weakness-class analysis for edge-security-ground-truth.

Analyzes Common Weakness Enumeration patterns across CISA KEV edge-device
CVEs using NVD-enriched data.  Four dimensions:

  (a) Top 10 CWEs across all edge CVEs
  (b) Per-vendor CWE distribution
  (c) CWE evolution over time (era comparison)
  (d) Universal CWEs (5+ vendors) vs vendor-specific

Usage:
  python3 scripts/analyze_cwe.py                        # text tables
  python3 scripts/analyze_cwe.py --format markdown      # markdown
  python3 scripts/analyze_cwe.py --format json          # machine-readable
"""
import argparse
import collections
import json
import math
import os
import sys


# ---------------------------------------------------------------------------
# Exact statistics (stdlib-only): Fisher exact test from first principles
# ---------------------------------------------------------------------------
def _log_choose(n, k):
    """log(n choose k) via lgamma; 0 outside the valid range."""
    if k < 0 or k > n or n < 0:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _hypergeom_logpmf(a, row1, col1, total):
    """log P(X = a) for the hypergeometric distribution of the (1,1) cell of a
    2x2 table with row1 = a+b, col1 = a+c, and grand total N."""
    return (_log_choose(col1, a)
            + _log_choose(total - col1, row1 - a)
            - _log_choose(total, row1))


def fisher_exact_one_sided(a, b, c, d):
    """One-sided (right tail) Fisher exact test for the 2x2 table
        [[a, b],
         [c, d]]
    Tests for ENRICHMENT of the (1,1) cell: P(X >= a) under the
    hypergeometric null with fixed margins. Pure stdlib.
    """
    row1 = a + b
    col1 = a + c
    total = a + b + c + d
    if total == 0:
        return 1.0
    a_min = max(0, col1 - (total - row1))
    a_max = min(row1, col1)
    p = 0.0
    for x in range(a, a_max + 1):
        if x < a_min:
            continue
        p += math.exp(_hypergeom_logpmf(x, row1, col1, total))
    return min(1.0, p)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_PATH = os.path.join(SCRIPT_DIR, "kev_edge_enriched.json")

# ---------------------------------------------------------------------------
# Meta-categories: group related CWEs into SDL weakness themes
# ---------------------------------------------------------------------------
CWE_CATEGORIES = {
    "Memory Safety": {
        "cwes": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
                 "CWE-787", "CWE-416", "CWE-190", "CWE-197", "CWE-772",
                 "CWE-835"},
        "desc": "Buffer overflows, out-of-bounds read/write, use-after-free, "
                "integer truncation, resource leaks, infinite loops",
    },
    "Auth / Access Control": {
        "cwes": {"CWE-287", "CWE-288", "CWE-284", "CWE-285", "CWE-306",
                 "CWE-862", "CWE-863", "CWE-639", "CWE-1390", "CWE-290",
                 "CWE-565", "CWE-653", "CWE-347", "CWE-473"},
        "desc": "Auth bypass, missing/improper authorization, weak auth, "
                "cookie reliance, insufficient verification",
    },
    "Injection": {
        "cwes": {"CWE-77", "CWE-78", "CWE-89", "CWE-94", "CWE-917"},
        "desc": "OS command, SQL, code, expression language injection",
    },
    "Path Traversal / File": {
        "cwes": {"CWE-22", "CWE-59", "CWE-552", "CWE-434", "CWE-73"},
        "desc": "Directory traversal, symlink, file upload, file path control",
    },
    "Credential Management": {
        "cwes": {"CWE-798", "CWE-522", "CWE-307", "CWE-330", "CWE-532"},
        "desc": "Hardcoded creds, weak storage, brute-force",
    },
    "Input Validation": {
        "cwes": {"CWE-20", "CWE-1287", "CWE-134"},
        "desc": "Generic improper input validation, format string",
    },
    "Web / Session": {
        "cwes": {"CWE-79", "CWE-352", "CWE-601", "CWE-613", "CWE-444"},
        "desc": "XSS, CSRF, open redirect, session issues",
    },
    "Deserialization / Code Loading": {
        "cwes": {"CWE-502", "CWE-829", "CWE-494"},
        "desc": "Untrusted deserialization, code loading without integrity",
    },
    "Information Exposure": {
        "cwes": {"CWE-200", "CWE-668", "CWE-669"},
        "desc": "Sensitive data leak, wrong-sphere exposure",
    },
}

# Fallback CWE name lookup (enriched data has cwe_name, but keep a
# static table for display when data is missing)
_CWE_NAMES_STATIC = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-73": "External Control of File Name or Path",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Memory Buffer Bounds",
    "CWE-120": "Buffer Copy w/o Size Check",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow",
    "CWE-197": "Numeric Truncation Error",
    "CWE-200": "Information Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Auth Bypass via Alternate Path",
    "CWE-290": "Auth Bypass by Spoofing",
    "CWE-306": "Missing Auth for Critical Function",
    "CWE-307": "Excessive Auth Attempts",
    "CWE-330": "Insufficient Randomness",
    "CWE-345": "Insufficient Data Authenticity Verification",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "CSRF",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-406": "Insufficient Control of Network Message Volume",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-459": "Incomplete Cleanup",
    "CWE-473": "PHP External Variable Modification",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Info in Log File",
    "CWE-552": "Externally Accessible Files",
    "CWE-565": "Reliance on Cookies Without Validation",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE",
    "CWE-613": "Insufficient Session Expiry",
    "CWE-639": "Auth Bypass via User Key",
    "CWE-653": "Improper Isolation or Compartmentalization",
    "CWE-664": "Improper Control of a Resource Through its Lifetime",
    "CWE-668": "Wrong Sphere Exposure",
    "CWE-669": "Incorrect Resource Transfer",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-770": "Allocation Without Limits",
    "CWE-772": "Missing Release of Resource After Effective Lifetime",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hardcoded Credentials",
    "CWE-829": "Untrusted Control Sphere",
    "CWE-835": "Infinite Loop",
    "CWE-843": "Incompatible Type Access",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-912": "Hidden Functionality",
    "CWE-918": "SSRF",
    "CWE-1287": "Improper Type Validation",
    "CWE-1390": "Weak Authentication",
    "NVD-CWE-noinfo": "No CWE Info",
    "NVD-CWE-Other": "Other",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def categorize_cwe(cwe_id):
    """Map a CWE-ID to its meta-category."""
    for cat, info in CWE_CATEGORIES.items():
        if cwe_id in info["cwes"]:
            return cat
    return "Other / Unclassified"


def cwe_display_name(cwe_id, data_name=None):
    """Best-effort human name for a CWE."""
    if data_name and data_name != cwe_id:
        return data_name
    return _CWE_NAMES_STATIC.get(cwe_id, cwe_id)


def year_to_era(year_int):
    """Bucket years into eras for temporal analysis."""
    if year_int <= 2019:
        return "<=2019"
    elif year_int <= 2021:
        return "2020-2021"
    elif year_int <= 2023:
        return "2022-2023"
    else:
        return "2024+"


def load_enriched(path):
    """Load vendor dict from enriched JSON, skip metadata keys."""
    with open(path) as f:
        data = json.load(f)
    vendors = {}
    for key, val in data.items():
        if key.startswith("_"):
            continue
        if isinstance(val, dict):
            vendors[key] = val
    return vendors


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def analyze(vendors):
    """Build all analysis structures from vendor data."""
    r = {
        "total": 0,
        "total_with_cwe": 0,
        "total_without_cwe": 0,
        # Global counters
        "global_cwe": collections.Counter(),
        "global_cat": collections.Counter(),
        # Per-vendor
        "vendor_cwe": {},
        "vendor_cat": {},
        "vendor_details": {},
        # CWE -> set of vendors
        "cwe_vendors": collections.defaultdict(set),
        # CWE name lookup from data
        "cwe_names": {},
        # Era -> category counter
        "era_cat": collections.defaultdict(collections.Counter),
        "era_cwe": collections.defaultdict(collections.Counter),
        "era_totals": collections.Counter(),
        # Severity stats per category
        "cat_severities": collections.defaultdict(list),
    }

    for vendor, cves in sorted(vendors.items()):
        v_cwe = collections.Counter()
        v_cat = collections.Counter()
        details = []

        for cve_id, info in cves.items():
            r["total"] += 1
            cwe = info.get("cwe")
            cwe_name_raw = info.get("cwe_name")
            published = info.get("published", "")
            cvss = info.get("cvss")
            severity = info.get("cvss_severity", "")

            # Determine era
            try:
                year = int(published[:4])
            except (ValueError, TypeError):
                year = 0
            era = year_to_era(year) if year else "Unknown"

            # CWE classification
            if not cwe or cwe in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
                r["total_without_cwe"] += 1
                cat = "Other / Unclassified"
            else:
                r["total_with_cwe"] += 1
                cat = categorize_cwe(cwe)

            if cwe:
                r["global_cwe"][cwe] += 1
                v_cwe[cwe] += 1
                r["cwe_vendors"][cwe].add(vendor)
                r["era_cwe"][era][cwe] += 1
                if cwe_name_raw:
                    r["cwe_names"][cwe] = cwe_name_raw

            r["global_cat"][cat] += 1
            v_cat[cat] += 1
            r["era_cat"][era][cat] += 1
            r["era_totals"][era] += 1
            if cvss is not None:
                r["cat_severities"][cat].append(cvss)

            details.append({
                "cve": cve_id,
                "cwe": cwe or "None",
                "cwe_name": cwe_display_name(cwe, cwe_name_raw) if cwe else "N/A",
                "category": cat,
                "cvss": cvss,
                "severity": severity,
                "year": year,
                "era": era,
                "vendor": vendor,
            })

        r["vendor_cwe"][vendor] = v_cwe
        r["vendor_cat"][vendor] = v_cat
        r["vendor_details"][vendor] = details

    return r


# ---------------------------------------------------------------------------
# (a) Top 10 CWEs
# ---------------------------------------------------------------------------
def section_top_cwes(r, top_n=10):
    """Return list of (cwe, name, count, pct, num_vendors)."""
    rows = []
    for cwe, count in r["global_cwe"].most_common(top_n):
        name = cwe_display_name(cwe, r["cwe_names"].get(cwe))
        pct = 100 * count / r["total"]
        n_vendors = len(r["cwe_vendors"].get(cwe, set()))
        rows.append((cwe, name, count, pct, n_vendors))
    return rows


# ---------------------------------------------------------------------------
# (b) Per-vendor CWE distribution
# ---------------------------------------------------------------------------
def section_vendor_cats(r):
    """Return {vendor: [(cat, count, pct)]} + sorted cat list."""
    cats_ordered = [c for c, _ in r["global_cat"].most_common()
                    if c != "Other / Unclassified"]
    cats_ordered.append("Other / Unclassified")
    result = {}
    for vendor in sorted(r["vendor_cat"]):
        total_v = sum(r["vendor_cat"][vendor].values())
        rows = []
        for cat in cats_ordered:
            cnt = r["vendor_cat"][vendor].get(cat, 0)
            pct = 100 * cnt / total_v if total_v else 0
            rows.append((cat, cnt, pct))
        result[vendor] = (rows, total_v)
    return result, cats_ordered


# ---------------------------------------------------------------------------
# (c) CWE evolution over time
# ---------------------------------------------------------------------------
def section_evolution(r):
    """Return era rows: [(era, total, [(cat, count, pct)])]."""
    era_order = ["<=2019", "2020-2021", "2022-2023", "2024+"]
    cats_ordered = [c for c, _ in r["global_cat"].most_common()]
    rows = []
    for era in era_order:
        total_era = r["era_totals"].get(era, 0)
        if total_era == 0:
            continue
        cat_rows = []
        for cat in cats_ordered:
            cnt = r["era_cat"][era].get(cat, 0)
            pct = 100 * cnt / total_era if total_era else 0
            cat_rows.append((cat, cnt, pct))
        rows.append((era, total_era, cat_rows))
    return rows, cats_ordered


def section_evolution_top_cwes(r):
    """Top CWEs per era."""
    era_order = ["<=2019", "2020-2021", "2022-2023", "2024+"]
    result = {}
    for era in era_order:
        if era not in r["era_cwe"]:
            continue
        top = r["era_cwe"][era].most_common(5)
        result[era] = [(cwe, cnt, cwe_display_name(cwe, r["cwe_names"].get(cwe)))
                       for cwe, cnt in top]
    return result


# ---------------------------------------------------------------------------
# (d) Universal vs vendor-specific CWEs
# ---------------------------------------------------------------------------
def section_universality(r, threshold=5):
    """Split CWEs into universal (>= threshold vendors) and single-vendor."""
    universal = []
    multi = []
    single = []
    for cwe, vendors in sorted(r["cwe_vendors"].items(),
                                key=lambda x: -len(x[1])):
        name = cwe_display_name(cwe, r["cwe_names"].get(cwe))
        count = r["global_cwe"][cwe]
        n = len(vendors)
        entry = (cwe, name, count, n, sorted(vendors))
        if n >= threshold:
            universal.append(entry)
        elif n == 1:
            single.append(entry)
        else:
            multi.append(entry)
    return universal, multi, single


# ---------------------------------------------------------------------------
# Recurring weakness indicators (3+ same-category CVEs per vendor)
# ---------------------------------------------------------------------------
def section_recurring(r, min_count=3):
    """Return [(vendor, cat, count, [cve_ids])]."""
    results = []
    for vendor in sorted(r["vendor_cat"]):
        vc = r["vendor_cat"][vendor]
        for cat, count in vc.most_common():
            if count >= min_count and cat != "Other / Unclassified":
                cve_ids = [d["cve"] for d in r["vendor_details"][vendor]
                           if d["category"] == cat]
                results.append((vendor, cat, count, cve_ids))
    return results


# ---------------------------------------------------------------------------
# Statistical significance of recurring weaknesses
# ---------------------------------------------------------------------------
def section_weakness_significance(r):
    """One-sided Fisher exact test per (vendor, CWE-category) vs the rest.

    For each vendor V and category C, build the 2x2 table
        [[ a, b ],
         [ c, d ]]
    where
        a = CVEs of vendor V in category C
        b = CVEs of vendor V NOT in category C
        c = CVEs of all OTHER vendors in category C
        d = CVEs of all OTHER vendors NOT in category C
    and test (one-sided, right tail) whether category C is ENRICHED for
    vendor V relative to the rest of the corpus.

    Multiple-testing is controlled with a Bonferroni correction:
    alpha_corrected = alpha / number_of_tests.  Returns the full test list
    plus which survive Bonferroni.
    """
    total = r["total"]
    # Category totals across the whole corpus.
    cat_total = collections.Counter()
    for vendor in r["vendor_cat"]:
        for cat, cnt in r["vendor_cat"][vendor].items():
            cat_total[cat] += cnt

    vendor_total = {v: sum(c.values()) for v, c in r["vendor_cat"].items()}

    # Candidate (vendor, category) pairs: every category a vendor actually has,
    # excluding the catch-all bucket which is not an interpretable weakness.
    tests = []
    for vendor in sorted(r["vendor_cat"]):
        for cat, a in r["vendor_cat"][vendor].items():
            if cat == "Other / Unclassified" or a == 0:
                continue
            b = vendor_total[vendor] - a
            c = cat_total[cat] - a
            d = total - vendor_total[vendor] - c
            p = fisher_exact_one_sided(a, b, c, d)
            tests.append({
                "vendor": vendor,
                "category": cat,
                "a": a, "b": b, "c": c, "d": d,
                "vendor_cat_pct": round(100 * a / vendor_total[vendor], 1) if vendor_total[vendor] else 0,
                "corpus_cat_pct": round(100 * cat_total[cat] / total, 1) if total else 0,
                "p_value": p,
            })

    n_tests = len(tests)
    alpha = 0.05
    bonf_alpha = alpha / n_tests if n_tests else alpha
    for t in tests:
        t["bonferroni_significant"] = t["p_value"] < bonf_alpha
        t["raw_significant"] = t["p_value"] < alpha

    tests.sort(key=lambda x: (not x["bonferroni_significant"], x["p_value"]))

    return {
        "n_tests": n_tests,
        "alpha": alpha,
        "bonferroni_alpha": bonf_alpha,
        "n_raw_significant": sum(1 for t in tests if t["raw_significant"]),
        "n_bonferroni_significant": sum(1 for t in tests if t["bonferroni_significant"]),
        "tests": tests,
    }


# ---------------------------------------------------------------------------
# Output: text
# ---------------------------------------------------------------------------
def print_text(r):
    W = 80
    print("=" * W)
    print("CWE WEAKNESS-CLASS ANALYSIS -- Edge Security Ground Truth")
    print("=" * W)
    total = r["total"]
    wc = r["total_with_cwe"]
    print(f"\nDataset: {total} CISA KEV CVEs across {len(r['vendor_cat'])} "
          f"edge vendors")
    print(f"CWE coverage: {wc}/{total} ({100*wc/total:.0f}%) have NVD CWE "
          f"assignments\n")

    # (a) Top CWEs
    print("-" * W)
    print("(a) TOP 10 CWEs ACROSS ALL EDGE CVEs")
    print("-" * W)
    top = section_top_cwes(r, 10)
    print(f"{'#':<3} {'CWE':<10} {'Name':<42} {'N':>3} {'%':>5} {'Vendors':>7}")
    for i, (cwe, name, count, pct, nv) in enumerate(top, 1):
        nm = (name[:39] + "...") if len(name) > 42 else name
        bar = "#" * int(pct / 2)
        print(f"{i:<3} {cwe:<10} {nm:<42} {count:>3} {pct:>4.0f}% {nv:>7}  {bar}")

    # (b) Per-vendor
    print(f"\n{'-' * W}")
    print("(b) PER-VENDOR CWE CATEGORY DISTRIBUTION")
    print("-" * W)
    vdata, cats = section_vendor_cats(r)
    # compact: show top 6 categories
    show_cats = [c for c in cats if c != "Other / Unclassified"][:6]
    hdr = f"{'Vendor':<22}" + "".join(f"{c[:11]:>12}" for c in show_cats) + "  n"
    print(hdr)
    print("-" * len(hdr))
    for vendor, (rows, total_v) in sorted(vdata.items()):
        line = f"{vendor:<22}"
        for cat in show_cats:
            cnt = next((c for c2, c, _ in rows if c2 == cat), 0)
            line += f"{cnt if cnt else '.':>12}"
        line += f"  {total_v}"
        print(line)

    # (c) Evolution
    print(f"\n{'-' * W}")
    print("(c) CWE EVOLUTION OVER TIME")
    print("-" * W)
    evo, evo_cats = section_evolution(r)
    show_evo_cats = [c for c in evo_cats if c != "Other / Unclassified"][:6]
    hdr = f"{'Era':<14} {'n':>3}" + "".join(f"{c[:11]:>12}" for c in show_evo_cats)
    print(hdr)
    print("-" * len(hdr))
    for era, total_era, cat_rows in evo:
        line = f"{era:<14} {total_era:>3}"
        for cat in show_evo_cats:
            cnt = next((c for c2, c, _ in cat_rows if c2 == cat), 0)
            pct = 100 * cnt / total_era if total_era else 0
            line += f"{f'{cnt}({pct:.0f}%)':>12}" if cnt else f"{'--':>12}"
        print(line)

    print("\nTop CWEs by era:")
    era_top = section_evolution_top_cwes(r)
    for era, items in sorted(era_top.items()):
        cwes_str = ", ".join(f"{cwe}({cnt})" for cwe, cnt, _ in items)
        print(f"  {era}: {cwes_str}")

    # (d) Universal vs vendor-specific
    print(f"\n{'-' * W}")
    print("(d) UNIVERSAL vs VENDOR-SPECIFIC CWEs")
    print("-" * W)
    univ, multi, single = section_universality(r, 5)
    print(f"\nUniversal (5+ vendors) -- industry-wide systemic weaknesses:")
    for cwe, name, count, nv, vendors in univ:
        print(f"  {cwe} {name}: {count} CVEs across {nv} vendors")
        print(f"    Vendors: {', '.join(vendors)}")

    if multi:
        print(f"\nMulti-vendor (2-4 vendors):")
        for cwe, name, count, nv, vendors in multi:
            print(f"  {cwe} {name}: {count} CVEs, {nv} vendors ({', '.join(vendors)})")

    if single:
        print(f"\nVendor-specific (1 vendor only):")
        for cwe, name, count, nv, vendors in single:
            print(f"  {cwe} {name}: {count} CVEs ({vendors[0]})")

    # Recurring
    print(f"\n{'-' * W}")
    print("RECURRING WEAKNESS INDICATORS (3+ same-category CVEs, one vendor)")
    print("-" * W)
    recurring = section_recurring(r, 3)
    if recurring:
        for vendor, cat, count, cves in recurring:
            print(f"  {vendor}: {count}x {cat}")
            print(f"    {', '.join(cves)}")
    else:
        print("  (none found)")

    # Statistical significance of recurring weaknesses
    print(f"\n{'-' * W}")
    print("STATISTICAL SIGNIFICANCE OF RECURRING WEAKNESSES")
    print("-" * W)
    sig = section_weakness_significance(r)
    print(f"One-sided Fisher exact per (vendor, CWE-category) vs the rest.")
    print(f"  Tests: {sig['n_tests']}   alpha = {sig['alpha']}   "
          f"Bonferroni alpha = {sig['bonferroni_alpha']:.6f}")
    print(f"  Raw significant (p<0.05):      {sig['n_raw_significant']}")
    print(f"  Bonferroni significant:        {sig['n_bonferroni_significant']}")
    surviving = [t for t in sig["tests"] if t["bonferroni_significant"]]
    if surviving:
        print("\n  Surviving Bonferroni correction:")
        for t in surviving:
            print(f"    {t['vendor']} / {t['category']}: "
                  f"{t['a']} of {t['a']+t['b']} ({t['vendor_cat_pct']:.0f}% vs "
                  f"{t['corpus_cat_pct']:.0f}% corpus), p = {t['p_value']:.2e}")
    else:
        print("\n  No (vendor, category) pair survives Bonferroni correction.")


# ---------------------------------------------------------------------------
# Output: markdown
# ---------------------------------------------------------------------------
def print_markdown(r):
    total = r["total"]
    wc = r["total_with_cwe"]

    print("# CWE Weakness-Class Analysis\n")
    print(f"**Dataset:** {total} CISA KEV CVEs across "
          f"{len(r['vendor_cat'])} edge-device vendors  ")
    print(f"**CWE coverage:** {wc}/{total} ({100*wc/total:.0f}%) have NVD "
          f"CWE assignments\n")

    # (a) Top CWEs
    print("## (a) Top 10 CWEs Across All Edge CVEs\n")
    print("| # | CWE | Name | Count | % | Vendors |")
    print("|--:|-----|------|------:|--:|--------:|")
    for i, (cwe, name, count, pct, nv) in enumerate(section_top_cwes(r, 10), 1):
        print(f"| {i} | {cwe} | {name} | {count} | {pct:.0f}% | {nv} |")

    # Category rollup
    print("\n### Vulnerability Category Rollup\n")
    print("| Category | Count | % |")
    print("|----------|------:|--:|")
    for cat, count in r["global_cat"].most_common():
        pct = 100 * count / total
        print(f"| {cat} | {count} | {pct:.0f}% |")

    # (b) Per-vendor
    print("\n## (b) Per-Vendor CWE Category Distribution\n")
    vdata, cats = section_vendor_cats(r)
    show_cats = [c for c in cats if c != "Other / Unclassified"][:6]
    hdr = "| Vendor | " + " | ".join(c for c in show_cats) + " | n |"
    sep = "|--------|" + "|".join("---:" for _ in show_cats) + "|---:|"
    print(hdr)
    print(sep)
    for vendor, (rows, total_v) in sorted(vdata.items()):
        cells = []
        for cat in show_cats:
            cnt = next((c for c2, c, _ in rows if c2 == cat), 0)
            cells.append(str(cnt) if cnt else ".")
        print(f"| {vendor} | " + " | ".join(cells) + f" | {total_v} |")

    # (c) Evolution
    print("\n## (c) CWE Evolution Over Time\n")
    evo, evo_cats = section_evolution(r)
    show_evo = [c for c in evo_cats if c != "Other / Unclassified"][:6]
    hdr = "| Era | n | " + " | ".join(c for c in show_evo) + " |"
    sep = "|-----|--:|" + "|".join("---:" for _ in show_evo) + "|"
    print(hdr)
    print(sep)
    for era, total_era, cat_rows in evo:
        cells = []
        for cat in show_evo:
            cnt = next((c for c2, c, _ in cat_rows if c2 == cat), 0)
            pct = 100 * cnt / total_era if total_era else 0
            cells.append(f"{cnt} ({pct:.0f}%)" if cnt else ".")
        print(f"| {era} | {total_era} | " + " | ".join(cells) + " |")

    print("\n### Top CWEs by Era\n")
    era_top = section_evolution_top_cwes(r)
    for era, items in sorted(era_top.items()):
        cwes_str = ", ".join(f"{cwe} ({cnt})" for cwe, cnt, name in items)
        print(f"- **{era}:** {cwes_str}")

    # (d) Universal vs vendor-specific
    print("\n## (d) Universal vs Vendor-Specific CWEs\n")
    univ, multi, single = section_universality(r, 5)

    print("### Universal CWEs (5+ vendors)\n")
    print("These represent industry-wide systemic weaknesses in edge-device "
          "development:\n")
    if univ:
        print("| CWE | Name | CVEs | Vendors | Affected |")
        print("|-----|------|-----:|--------:|----------|")
        for cwe, name, count, nv, vendors in univ:
            print(f"| {cwe} | {name} | {count} | {nv} | "
                  f"{', '.join(vendors)} |")
    else:
        print("(None at the 5-vendor threshold.)\n")

    if multi:
        print("\n### Multi-Vendor CWEs (2-4 vendors)\n")
        print("| CWE | Name | CVEs | Vendors |")
        print("|-----|------|-----:|--------:|")
        for cwe, name, count, nv, vendors in multi:
            print(f"| {cwe} | {name} | {count} | {nv} |")

    if single:
        print("\n### Vendor-Specific CWEs (1 vendor)\n")
        print("| CWE | Name | CVEs | Vendor |")
        print("|-----|------|-----:|--------|")
        for cwe, name, count, nv, vendors in single:
            print(f"| {cwe} | {name} | {count} | {vendors[0]} |")

    # Recurring
    print("\n## Recurring Weakness Indicators\n")
    print("Vendors with 3+ exploited CVEs in the same category (signals a "
          "recurring SDL gap):\n")
    recurring = section_recurring(r, 3)
    if recurring:
        for vendor, cat, count, cves in recurring:
            print(f"- **{vendor}**: {count}x {cat}")
            print(f"  - {', '.join(cves)}")
    else:
        print("(None at the 3+ threshold.)\n")

    # Statistical significance of recurring weaknesses
    print("\n## Statistical Significance of Recurring Weaknesses\n")
    sig = section_weakness_significance(r)
    print("One-sided Fisher exact test per (vendor, CWE-category) versus the "
          "rest of the corpus, with Bonferroni correction for multiple "
          "comparisons.\n")
    print(f"- Tests: {sig['n_tests']}")
    print(f"- alpha = {sig['alpha']}, Bonferroni alpha = "
          f"{sig['bonferroni_alpha']:.6f}")
    print(f"- Raw significant (p < 0.05): {sig['n_raw_significant']}")
    print(f"- **Bonferroni significant: {sig['n_bonferroni_significant']}**\n")
    surviving = [t for t in sig["tests"] if t["bonferroni_significant"]]
    if surviving:
        print("| Vendor | Category | Vendor share | Corpus share | p-value |")
        print("|--------|----------|-------------:|-------------:|--------:|")
        for t in surviving:
            print(f"| {t['vendor']} | {t['category']} | "
                  f"{t['a']}/{t['a']+t['b']} ({t['vendor_cat_pct']:.0f}%) | "
                  f"{t['corpus_cat_pct']:.0f}% | {t['p_value']:.2e} |")
    else:
        print("*No (vendor, category) pair survives Bonferroni correction.*")


# ---------------------------------------------------------------------------
# Output: JSON
# ---------------------------------------------------------------------------
def print_json(r):
    total = r["total"]
    univ, multi, single = section_universality(r, 5)
    evo, _ = section_evolution(r)
    era_top = section_evolution_top_cwes(r)

    out = {
        "coverage": {
            "total": total,
            "with_cwe": r["total_with_cwe"],
            "without_cwe": r["total_without_cwe"],
            "pct": round(100 * r["total_with_cwe"] / total, 1) if total else 0,
        },
        "top_cwes": [
            {"cwe": cwe, "name": name, "count": count, "pct": round(pct, 1),
             "num_vendors": nv}
            for cwe, name, count, pct, nv in section_top_cwes(r, 20)
        ],
        "categories": {
            cat: {"count": count, "pct": round(100 * count / total, 1)}
            for cat, count in r["global_cat"].most_common()
        },
        "vendor_categories": {
            vendor: {cat: cnt for cat, cnt, _ in rows}
            for vendor, (rows, _) in section_vendor_cats(r)[0].items()
        },
        "vendor_totals": {
            vendor: total_v
            for vendor, (_, total_v) in section_vendor_cats(r)[0].items()
        },
        "evolution": {
            era: {
                "total": total_era,
                "categories": {cat: cnt for cat, cnt, _ in cat_rows if cnt > 0},
            }
            for era, total_era, cat_rows in evo
        },
        "evolution_top_cwes": {
            era: [{"cwe": cwe, "count": cnt, "name": name}
                  for cwe, cnt, name in items]
            for era, items in era_top.items()
        },
        "universal_cwes": [
            {"cwe": cwe, "name": name, "count": count, "num_vendors": nv,
             "vendors": vendors}
            for cwe, name, count, nv, vendors in univ
        ],
        "multi_vendor_cwes": [
            {"cwe": cwe, "name": name, "count": count, "num_vendors": nv,
             "vendors": vendors}
            for cwe, name, count, nv, vendors in multi
        ],
        "single_vendor_cwes": [
            {"cwe": cwe, "name": name, "count": count, "vendor": vendors[0]}
            for cwe, name, count, nv, vendors in single
        ],
        "recurring_weaknesses": [
            {"vendor": v, "category": cat, "count": cnt, "cves": cves}
            for v, cat, cnt, cves in section_recurring(r, 3)
        ],
        "weakness_significance": {
            k: (round(v, 8) if isinstance(v, float) else v)
            for k, v in section_weakness_significance(r).items()
            if k != "tests"
        },
        "weakness_significance_tests": [
            {
                "vendor": t["vendor"],
                "category": t["category"],
                "a": t["a"], "b": t["b"], "c": t["c"], "d": t["d"],
                "vendor_cat_pct": t["vendor_cat_pct"],
                "corpus_cat_pct": t["corpus_cat_pct"],
                "p_value": round(t["p_value"], 8),
                "raw_significant": t["raw_significant"],
                "bonferroni_significant": t["bonferroni_significant"],
            }
            for t in section_weakness_significance(r)["tests"]
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="CWE weakness-class analysis for edge-security-ground-truth.")
    parser.add_argument("--input", "-i", default=ENRICHED_PATH,
                        help="Path to enriched JSON (default: kev_edge_enriched.json)")
    parser.add_argument("--format", "-f", choices=["text", "markdown", "json"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--output", "-o",
                        help="Write output to file instead of stdout")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: enriched file not found: {args.input}", file=sys.stderr)
        print("Run enrich_nvd.py first to fetch CWE data from NVD.",
              file=sys.stderr)
        sys.exit(1)

    vendors = load_enriched(args.input)

    has_cwe = any(
        data.get("cwe")
        for cves in vendors.values()
        for data in cves.values()
    )
    if not has_cwe:
        print("Warning: no CWE data found in enriched file.", file=sys.stderr)
        print("Run enrich_nvd.py to populate CWE assignments.", file=sys.stderr)
        print("Proceeding with available data (all will be 'unclassified').\n",
              file=sys.stderr)

    if args.output:
        sys.stdout = open(args.output, "w")

    results = analyze(vendors)

    if args.format == "markdown":
        print_markdown(results)
    elif args.format == "json":
        print_json(results)
    else:
        print_text(results)


if __name__ == "__main__":
    main()
