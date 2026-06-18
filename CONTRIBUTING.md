# Contributing

This project publishes data, not rankings. Contributions that add precision or correct the record are welcome; contributions that argue vendor X is worse than vendor Y are not.

---

## Adding a New Vendor

1. **Register the scope** — open `scripts/build_kev_counts.py` and add an entry to the `SCOPE` dict:
   ```python
   "VendorName": re.compile(r"vendorname|product-a|product-b", re.IGNORECASE),
   ```
   Match on CPE vendor/product strings and CVE description text. Keep the regex narrow enough to avoid false positives from unrelated products sharing a name.

2. **Regenerate the counts** — run the script from the repo root:
   ```
   python scripts/build_kev_counts.py
   ```
   Review the diff to confirm the new row is plausible before committing.

3. **Create a vendor doc** — add `docs/VendorName.md` following the template below.

---

## Vendor Doc Template

```markdown
# VendorName — Edge Security Ground Truth

**Scope:** Products included in KEV counts (list CPE/product names).  
**KEV count as of YYYY-MM-DD:** N

## Market Position

One paragraph: what the product line does, market segment, rough install-base context.
Cite a named analyst report or vendor disclosure if possible.

## Key Incidents

| CVE | CVSS | Type | Exploited | Notes |
|-----|------|------|-----------|-------|
| CVE-YYYY-NNNNN | X.X | RCE/Auth-bypass/etc | Mass / Targeted / Unknown | [Source](url) |

## Transparency Assessment

How did the vendor handle disclosure, patching, and customer communication?
Cite vendor advisories, CISA alerts, or named researcher posts — not opinion pieces.

## Risk Summary

Two to four sentences. What does the KEV record say about this product line's
exploitation history? Avoid adjectives that imply a ranking.
```

---

## Correcting a Fact

Open an issue with:

- The specific claim and the file/line where it appears.
- A primary source that contradicts it (vendor advisory, NVD entry, CISA KEV export, or named security research publication).
- The corrected text you propose.

Pull requests that change factual content without a cited source will be closed.

---

## Improving the Methodology

Discuss the change in an issue before opening a PR. Explain what the current approach gets wrong, what the proposed change measures instead, and how to validate it against the existing dataset.

---

## Code Style

The build script (`scripts/build_kev_counts.py`) must remain stdlib-only — no third-party dependencies. Keep it readable: a contributor with basic Python should be able to audit the KEV-to-count mapping in under ten minutes. Prefer clarity over cleverness.

---

## Citation Standards

Every factual claim in a vendor doc needs an inline citation to a primary or named research source:

- **Primary:** NVD, CISA KEV, vendor security advisories, government CERT bulletins.
- **Named research:** Mandiant, Volexity, Rapid7, Censys, Shadowserver, academic papers. Link to the specific post, not a homepage.
- **Not acceptable:** press articles that themselves cite primary sources (go to the primary), anonymous blog posts, vendor marketing.

If a claim cannot be sourced, omit it.
