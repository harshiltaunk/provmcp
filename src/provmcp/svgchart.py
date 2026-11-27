"""Dependency-free SVG charts for the evaluation report.

One form is needed: horizontal grouped bars of rates (0-100%) with 95%
interval whiskers, one group per detection strategy. The output is a static
SVG image that renders on GitHub and in a paper, on an explicit light
surface so it reads the same under either site theme. Each bar carries an
SVG `<title>`, which browsers show as a tooltip; the report's tables are the
accessible text view.

Mark specs follow the project's chart guidance: bars at most 24px thick
(12px here) with a 2px surface gap between neighbours, a 4px rounded data
end and a square baseline, hairline grid, text in text colours (never the
series colour), a legend for two or more series, and the value at each bar
tip.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from provmcp.evaluation import Rate

SURFACE = "#ffffff"
TEXT = "#191919"
TEXT_2 = "#666666"
GRID = "#e6e6e6"
SERIES = ("#257de0", "#f47230", "#00b894")  # categorical slots 1-3, validated as a set
FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"


def _bar_path(x0: float, y: float, width: float, height: float, radius: float = 4.0) -> str:
    """A bar that is square at the baseline and rounded at the data end."""
    if width <= 0:
        return ""
    r = min(radius, width, height / 2)
    return (
        f"M{x0:.1f},{y:.1f} h{width - r:.1f} a{r:.1f},{r:.1f} 0 0 1 {r:.1f},{r:.1f} "
        f"v{height - 2 * r:.1f} a{r:.1f},{r:.1f} 0 0 1 {-r:.1f},{r:.1f} h{-(width - r):.1f} Z"
    )


def grouped_rate_bars(
    title: str,
    subtitle: str,
    categories: Sequence[str],
    series: Sequence[tuple[str, Sequence[Rate]]],
    *,
    width: int = 760,
) -> str:
    """Grouped horizontal bars: one group per category, one bar per series."""
    if len(series) > len(SERIES):
        raise ValueError(f"at most {len(SERIES)} series")
    for _, rates in series:
        if len(rates) != len(categories):
            raise ValueError("every series needs one rate per category")
    label_w, right_pad, top = 250, 70, 92
    bar_h, bar_gap, group_gap = 12, 2, 16
    x0, x1 = label_w, width - right_pad
    span = x1 - x0
    group_h = len(series) * bar_h + (len(series) - 1) * bar_gap
    height = top + len(categories) * (group_h + group_gap) + 34

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="chart-title chart-desc" '
        f'font-family="{FONT}">',
        f'<title id="chart-title">{escape(title)}</title>',
        f'<desc id="chart-desc">{escape(subtitle)}</desc>',
        f'<rect width="{width}" height="{height}" fill="{SURFACE}"/>',
        f'<text x="16" y="28" font-size="15" font-weight="600" fill="{TEXT}">'
        f"{escape(title)}</text>",
        f'<text x="16" y="48" font-size="12" fill="{TEXT_2}">{escape(subtitle)}</text>',
    ]
    lx = x0
    for i, (name, _) in enumerate(series):
        out.append(f'<rect x="{lx}" y="62" width="10" height="10" rx="2" fill="{SERIES[i]}"/>')
        out.append(f'<text x="{lx + 16}" y="71" font-size="12" fill="{TEXT}">{escape(name)}</text>')
        lx += 24 + 7 * len(name)
    out.append(
        f'<text x="{x1}" y="71" font-size="11" fill="{TEXT_2}" text-anchor="end">'
        "whiskers: 95% Wilson interval</text>"
    )
    plot_bottom = height - 30
    for tick in (0, 25, 50, 75, 100):
        x = x0 + span * tick / 100
        out.append(
            f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{plot_bottom}" '
            f'stroke="{GRID}" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{plot_bottom + 16}" font-size="11" fill="{TEXT_2}" '
            f'text-anchor="middle">{tick}%</text>'
        )
    for c, category in enumerate(categories):
        gy = top + c * (group_h + group_gap)
        out.append(
            f'<text x="{x0 - 10}" y="{gy + group_h / 2 + 4:.1f}" font-size="12" fill="{TEXT}" '
            f'text-anchor="end">{escape(category)}</text>'
        )
        for s, (name, rates) in enumerate(series):
            rate = rates[c]
            y = gy + s * (bar_h + bar_gap)
            if rate.n == 0:
                out.append(
                    f'<text x="{x0 + 4}" y="{y + bar_h - 2}" font-size="11" fill="{TEXT_2}">'
                    "no data</text>"
                )
                continue
            w = span * rate.value
            lo, hi = rate.interval
            tip = f"{category}, {name}: {rate}"
            path = _bar_path(x0, y, w, bar_h)
            out.append("<g>")
            out.append(f"<title>{escape(tip)}</title>")
            if path:
                out.append(f'<path d="{path}" fill="{SERIES[s]}"/>')
            cy = y + bar_h / 2
            xl, xh = x0 + span * lo, x0 + span * hi
            out.append(
                f'<line x1="{xl:.1f}" y1="{cy:.1f}" x2="{xh:.1f}" y2="{cy:.1f}" '
                f'stroke="{TEXT_2}" stroke-width="1.5"/>'
            )
            for xe in (xl, xh):
                out.append(
                    f'<line x1="{xe:.1f}" y1="{cy - 4:.1f}" x2="{xe:.1f}" y2="{cy + 4:.1f}" '
                    f'stroke="{TEXT_2}" stroke-width="1.5"/>'
                )
            out.append(
                f'<text x="{max(x0 + w, xh) + 6:.1f}" y="{y + bar_h - 2}" font-size="11" '
                f'fill="{TEXT_2}">{100 * rate.value:.0f}%</text>'
            )
            out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"
