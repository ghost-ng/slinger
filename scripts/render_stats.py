#!/usr/bin/env python3
"""Render traffic stats PNGs from JSON snapshots on the stats branch.

Walks data/**/*_{views,clones}.json, deduplicates the 14-day rolling
windows into a single per-date timeline, and writes PNGs to charts/.

Run from the root of the stats-branch checkout.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patheffects import withStroke

NEON_CYAN = "#00f0ff"
NEON_MAGENTA = "#ff3cf5"
NEON_YELLOW = "#f8ff5c"
BG = "#05060a"
GRID = "#1a1f2e"


def load_timeline(kind: str) -> tuple[list[datetime], list[int], list[int]]:
    """Return (dates, counts, uniques) for 'views' or 'clones'."""
    per_date: dict[str, tuple[int, int]] = {}
    for path in sorted(Path("data").glob(f"**/*_{kind}.json")):
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        for row in payload.get(kind, []):
            ts = row["timestamp"][:10]
            count = row.get("count", 0)
            uniques = row.get("uniques", 0)
            prev = per_date.get(ts, (0, 0))
            per_date[ts] = (max(prev[0], count), max(prev[1], uniques))

    if not per_date:
        return [], [], []
    ordered = sorted(per_date.items())
    dates = [datetime.strptime(d, "%Y-%m-%d") for d, _ in ordered]
    counts = [v[0] for _, v in ordered]
    uniques = [v[1] for _, v in ordered]
    return dates, counts, uniques


def glow_plot(ax, x, y, color, label):
    """Draw a line with a soft neon glow underneath."""
    for lw, alpha in [(9, 0.05), (6, 0.08), (3.5, 0.15)]:
        ax.plot(x, y, color=color, linewidth=lw, alpha=alpha, solid_capstyle="round")
    ax.plot(
        x,
        y,
        color=color,
        linewidth=1.6,
        label=label,
        marker="o",
        markersize=4,
        markerfacecolor=color,
        markeredgecolor=BG,
        markeredgewidth=0.8,
    )


def style_axes(ax, title: str):
    ax.set_facecolor(BG)
    ax.grid(True, color=GRID, linewidth=0.6, linestyle="-")
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color("#2a3142")
        spine.set_linewidth(0.8)
    ax.tick_params(colors="#7a8196", labelsize=8)
    ax.set_title(
        title,
        color="#e6e9f2",
        fontsize=13,
        fontweight="bold",
        loc="left",
        pad=14,
        path_effects=[withStroke(linewidth=3, foreground=BG)],
    )


def render(kind: str, primary_color: str) -> bool:
    dates, counts, uniques = load_timeline(kind)
    if not dates:
        print(f"no data for {kind}, skipping")
        return False

    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=140)
    fig.patch.set_facecolor(BG)

    glow_plot(ax, dates, counts, primary_color, f"Total {kind}")
    glow_plot(ax, dates, uniques, NEON_YELLOW, f"Unique {kind}")

    total = sum(counts)
    uniq_total = sum(uniques)
    style_axes(ax, f"{kind.upper()}   //   total {total}   ·   unique {uniq_total}")

    legend = ax.legend(
        loc="upper left",
        frameon=False,
        fontsize=8,
        labelcolor="#c8ccd8",
        handlelength=2,
    )
    for text in legend.get_texts():
        text.set_path_effects([withStroke(linewidth=2, foreground=BG)])

    fig.autofmt_xdate()
    fig.tight_layout()

    Path("charts").mkdir(exist_ok=True)
    out = Path("charts") / f"{kind}.png"
    fig.savefig(out, facecolor=BG, edgecolor="none")
    plt.close(fig)
    print(f"wrote {out}")
    return True


def render_summary():
    v_dates, v_counts, v_uniques = load_timeline("views")
    c_dates, c_counts, c_uniques = load_timeline("clones")
    if not v_dates and not c_dates:
        return

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), dpi=140, sharex=True)
    fig.patch.set_facecolor(BG)

    if v_dates:
        glow_plot(ax1, v_dates, v_counts, NEON_CYAN, "views")
        glow_plot(ax1, v_dates, v_uniques, NEON_YELLOW, "unique")
    style_axes(ax1, f"VIEWS   //   {sum(v_counts)} total")
    ax1.legend(loc="upper left", frameon=False, fontsize=8, labelcolor="#c8ccd8")

    if c_dates:
        glow_plot(ax2, c_dates, c_counts, NEON_MAGENTA, "clones")
        glow_plot(ax2, c_dates, c_uniques, NEON_YELLOW, "unique")
    style_axes(ax2, f"CLONES   //   {sum(c_counts)} total")
    ax2.legend(loc="upper left", frameon=False, fontsize=8, labelcolor="#c8ccd8")

    fig.autofmt_xdate()
    fig.tight_layout()

    Path("charts").mkdir(exist_ok=True)
    out = Path("charts") / "summary.png"
    fig.savefig(out, facecolor=BG, edgecolor="none")
    plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    render("views", NEON_CYAN)
    render("clones", NEON_MAGENTA)
    render_summary()
