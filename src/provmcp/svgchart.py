"""Dependency-free SVG charts for the evaluation report.

Two forms: horizontal grouped bars of rates (0-100%) with 95% interval
whiskers (Week 10), and grouped bars of measured values such as latency or
memory, optionally on a log axis with a target line (Week 11). The output is a static
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

import math
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


def _fmt(value: float) -> str:
    if value == 0:
        return "0"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    if value >= 0.1:
        return f"{value:.2f}"
    return f"{value:.3f}"


def grouped_value_bars(
    title: str,
    subtitle: str,
    categories: Sequence[str],
    series: Sequence[tuple[str, Sequence[tuple[float, float] | None]]],
    *,
    unit: str,
    target: float | None = None,
    target_label: str = "target",
    log: bool = False,
    width: int = 760,
) -> str:
    """Grouped horizontal bars of measured values: bar = typical, whisker = upper value.

    Each value is `(typical, upper)` (for latency, p50 and p95) or None for
    "not measured". `log=True` uses a base-10 axis, for values that span
    orders of magnitude. `target` draws a labelled vertical line.
    """
    if len(series) > len(SERIES):
        raise ValueError(f"at most {len(SERIES)} series")
    for _, values in series:
        if len(values) != len(categories):
            raise ValueError("every series needs one value per category")
    measured = [v for _, values in series for v in values if v is not None]
    top_value = max([u for _, u in measured] + ([target] if target else []) + [1e-9])
    if log:
        floor = min([t for t, _ in measured if t > 0] + [top_value]) / 2
        lo_exp = math.floor(math.log10(max(floor, 1e-3)))
        hi_exp = math.ceil(math.log10(top_value * 1.05))
        if hi_exp <= lo_exp:
            hi_exp = lo_exp + 1
        ticks = [10.0**e for e in range(lo_exp, hi_exp + 1)]
    else:
        step = 10 ** math.floor(math.log10(top_value)) if top_value > 0 else 1
        hi = math.ceil(top_value * 1.1 / step) * step
        ticks = [hi * i / 4 for i in range(5)]
    label_w, right_pad, top = 250, 80, 92
    bar_h, bar_gap, group_gap = 12, 2, 16
    x0, x1 = label_w, width - right_pad
    span = x1 - x0

    def xpos(value: float) -> float:
        if log:
            v = min(max(value, ticks[0]), ticks[-1])
            frac = (math.log10(v) - math.log10(ticks[0])) / (
                math.log10(ticks[-1]) - math.log10(ticks[0])
            )
            return x0 + span * frac
        return x0 + span * min(value, ticks[-1]) / ticks[-1]

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
    plot_bottom = height - 30
    for tick in ticks:
        x = xpos(tick)
        out.append(
            f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{plot_bottom}" '
            f'stroke="{GRID}" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{plot_bottom + 16}" font-size="11" fill="{TEXT_2}" '
            f'text-anchor="middle">{_fmt(tick)} {escape(unit)}</text>'
        )
    if target is not None:
        xt = xpos(target)
        out.append(
            f'<line x1="{xt:.1f}" y1="{top - 2}" x2="{xt:.1f}" y2="{plot_bottom}" '
            f'stroke="{TEXT}" stroke-width="1.5"/>'
        )
        out.append(
            f'<text x="{xt + 4:.1f}" y="{plot_bottom - 4}" font-size="11" fill="{TEXT}">'
            f"{escape(target_label)} {_fmt(target)} {escape(unit)}</text>"
        )
    for c, category in enumerate(categories):
        gy = top + c * (group_h + group_gap)
        out.append(
            f'<text x="{x0 - 10}" y="{gy + group_h / 2 + 4:.1f}" font-size="12" fill="{TEXT}" '
            f'text-anchor="end">{escape(category)}</text>'
        )
        for s, (name, values) in enumerate(series):
            y = gy + s * (bar_h + bar_gap)
            value = values[c]
            if value is None:
                out.append(
                    f'<text x="{x0 + 4}" y="{y + bar_h - 2}" font-size="11" fill="{TEXT_2}">'
                    "not measured</text>"
                )
                continue
            typical, upper = value
            w = xpos(typical) - x0
            out.append("<g>")
            out.append(
                f"<title>{escape(category)}, {escape(name)}: {_fmt(typical)} {escape(unit)} "
                f"(upper {_fmt(upper)} {escape(unit)})</title>"
            )
            path = _bar_path(x0, y, w, bar_h)
            if path:
                out.append(f'<path d="{path}" fill="{SERIES[s]}"/>')
            cy = y + bar_h / 2
            xu = xpos(upper)
            if xu > x0 + w + 1:
                out.append(
                    f'<line x1="{x0 + w:.1f}" y1="{cy:.1f}" x2="{xu:.1f}" y2="{cy:.1f}" '
                    f'stroke="{TEXT_2}" stroke-width="1.5"/>'
                )
                out.append(
                    f'<line x1="{xu:.1f}" y1="{cy - 4:.1f}" x2="{xu:.1f}" y2="{cy + 4:.1f}" '
                    f'stroke="{TEXT_2}" stroke-width="1.5"/>'
                )
            out.append(
                f'<text x="{max(x0 + w, xu) + 6:.1f}" y="{y + bar_h - 2}" font-size="11" '
                f'fill="{TEXT_2}">{_fmt(typical)}</text>'
            )
            out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"
