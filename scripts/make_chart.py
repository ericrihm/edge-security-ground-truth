#!/usr/bin/env python3
"""
Reproducible horizontal bar chart of exploited edge CVEs per vendor.

Reads scripts/kev_edge_counts.json (produced by build_kev_counts.py) and emits
a clean, self-contained SVG to assets/edge-kev-chart.svg. STDLIB ONLY — the SVG
is hand-rendered as raw markup, no matplotlib / no third-party deps, so the
chart regenerates from the same JSON the README counts come from.

Usage:
  python3 scripts/make_chart.py                 # write assets/edge-kev-chart.svg
  python3 scripts/make_chart.py -o out.svg       # custom output path
  python3 scripts/make_chart.py --counts f.json  # custom input counts file
"""
import argparse, json, os, sys
from xml.sax.saxutils import escape

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_COUNTS = os.path.join(SCRIPT_DIR, "kev_edge_counts.json")
DEFAULT_OUTPUT = os.path.join(REPO_DIR, "assets", "edge-kev-chart.svg")

# GitHub-dark palette, matching assets/edge-kev-chart.html so the two views look related.
BG = "#0d1117"
PANEL = "#161b22"
GRID = "#30363d"
TEXT = "#e6edf3"
TEXT_DIM = "#8b949e"
BAR = "#58a6ff"
BAR_TOP = "#f85149"  # highlight the highest-count vendor (the popularity-tax bar)


def load_counts(path):
    """Return a list of (vendor, count) sorted by count desc, then vendor asc."""
    with open(path) as f:
        data = json.load(f)
    meta = data.get("_metadata", {})
    counts = meta.get("counts")
    if counts:
        pairs = list(counts.items())
    else:
        # Fall back to counting the per-vendor CVE lists if _metadata.counts absent.
        pairs = [(k, len(v)) for k, v in data.items()
                 if k != "_metadata" and isinstance(v, list)]
    pairs.sort(key=lambda kv: (-kv[1], kv[0]))
    return pairs, meta


def build_svg(pairs, meta):
    n = len(pairs)
    vendors = [p[0] for p in pairs]
    values = [p[1] for p in pairs]
    total = sum(values)
    lo, hi = (min(values), max(values)) if values else (0, 0)

    # Layout (px). Plot area is to the right of the vendor-label gutter.
    margin_left = 200      # vendor name gutter
    margin_right = 56      # room for the count label past the bar end
    margin_top = 92        # title + subtitle band
    margin_bottom = 56     # x-axis ticks + caption
    row_h = 30
    bar_h = 18
    plot_w = 620
    width = margin_left + plot_w + margin_right
    height = margin_top + n * row_h + margin_bottom

    # X scale: 0..axis_max where axis_max is the next "nice" number above hi.
    axis_max = max(hi, 1)
    # round up to a multiple of 2 so ticks land on even numbers (matches 2..18 spread)
    if axis_max % 2:
        axis_max += 1
    tick_step = 2
    px_per_unit = plot_w / axis_max

    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Exploited edge CVEs by vendor, CISA KEV 2020 to 2026, {n} vendors">'
    )
    parts.append(
        '<style>'
        'text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;}'
        '</style>'
    )
    # Background.
    parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="{BG}"/>')

    # Title + subtitle.
    parts.append(
        f'<text x="{margin_left}" y="32" fill="{TEXT}" font-size="19" '
        f'font-weight="600">Exploited edge CVEs by vendor</text>'
    )
    cat = escape(str(meta.get("catalog_version", "")))
    sub = f"CISA KEV 2020–2026, {n} edge vendors, {lo}–{hi}"
    parts.append(
        f'<text x="{margin_left}" y="56" fill="{TEXT_DIM}" font-size="13">{escape(sub)}</text>'
    )
    if cat:
        parts.append(
            f'<text x="{margin_left}" y="76" fill="{TEXT_DIM}" font-size="11">'
            f'Source: CISA KEV catalog {cat} — reproduce with scripts/build_kev_counts.py'
            f'</text>'
        )

    plot_x0 = margin_left
    plot_y0 = margin_top
    plot_y1 = margin_top + n * row_h

    # Vertical gridlines + x-axis ticks.
    t = 0
    while t <= axis_max:
        gx = plot_x0 + t * px_per_unit
        parts.append(
            f'<line x1="{gx:.1f}" y1="{plot_y0}" x2="{gx:.1f}" y2="{plot_y1}" '
            f'stroke="{GRID}" stroke-width="1" opacity="0.5"/>'
        )
        parts.append(
            f'<text x="{gx:.1f}" y="{plot_y1 + 20}" fill="{TEXT_DIM}" font-size="11" '
            f'text-anchor="middle">{t}</text>'
        )
        t += tick_step

    # Bars + labels.
    for i, (vendor, val) in enumerate(pairs):
        cy = plot_y0 + i * row_h
        bar_y = cy + (row_h - bar_h) / 2
        bar_w = val * px_per_unit
        color = BAR_TOP if val == hi else BAR
        # Vendor name (right-aligned in the gutter).
        parts.append(
            f'<text x="{plot_x0 - 12}" y="{bar_y + bar_h * 0.72:.1f}" fill="{TEXT}" '
            f'font-size="12.5" text-anchor="end">{escape(vendor)}</text>'
        )
        # Bar.
        parts.append(
            f'<rect x="{plot_x0}" y="{bar_y:.1f}" width="{bar_w:.1f}" height="{bar_h}" '
            f'rx="2" fill="{color}"/>'
        )
        # Count label just past the bar end.
        parts.append(
            f'<text x="{plot_x0 + bar_w + 8:.1f}" y="{bar_y + bar_h * 0.74:.1f}" '
            f'fill="{TEXT}" font-size="12" font-weight="600">{val}</text>'
        )

    # X-axis label / caption.
    parts.append(
        f'<text x="{plot_x0 + plot_w / 2:.1f}" y="{plot_y1 + 44}" fill="{TEXT_DIM}" '
        f'font-size="12" text-anchor="middle">'
        f'Exploited edge CVEs (CISA KEV) — {total} total. A sort, not a verdict.'
        f'</text>'
    )

    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--counts", "-c", default=DEFAULT_COUNTS,
                    help=f"Input counts JSON (default: {DEFAULT_COUNTS})")
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                    help=f"Output SVG path (default: {DEFAULT_OUTPUT})")
    args = ap.parse_args()

    pairs, meta = load_counts(args.counts)
    svg = build_svg(pairs, meta)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(svg)
    print(f"# wrote {args.output}  |  {len(pairs)} vendors, "
          f"spread {min(v for _, v in pairs)}–{max(v for _, v in pairs)}, "
          f"{sum(v for _, v in pairs)} CVEs", file=sys.stderr)


if __name__ == "__main__":
    main()
