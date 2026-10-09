"""Draw the per-tactic coverage chart used in the README.

Reads results.json (written by `python matrix.py samples`) and the rule files,
and writes docs/coverage.png.

Each bar is one ATT&CK tactic, as a share of its sample files:
  blue    caught by at least one normal-confidence rule  (substantive)
  orange  caught ONLY by low-confidence rules            (hollow)
  grey    not caught at all

Blue + orange is the headline figure; blue alone is the substantive figure.

Usage: python chart.py [results.json] [output.png]
"""
import json
import os
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from engine import load_rules  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_MUTED = "#52514e"
BLUE = "#2a78d6"     # substantive
ORANGE = "#eb6834"   # hollow (low-confidence only)
TRACK = "#e6e5e0"    # not caught


def tally(results, low_conf):
    """Return {tactic: {"total", "substantive", "hollow"}} and the overall row."""
    by_tactic = defaultdict(lambda: {"total": 0, "substantive": 0, "hollow": 0})
    for r in results:
        row = by_tactic[r["tactic"]]
        row["total"] += 1
        if r["fired"]:
            if set(r["fired"]) <= low_conf:
                row["hollow"] += 1
            else:
                row["substantive"] += 1
    overall = {k: sum(v[k] for v in by_tactic.values())
               for k in ("total", "substantive", "hollow")}
    return by_tactic, overall


def draw(results, rules, out_path):
    low_conf = {r["id"] for r in rules if r.get("confidence") == "low"}
    by_tactic, overall = tally(results, low_conf)

    # Sort by headline coverage, best at the top.
    def headline(item):
        s = item[1]
        return (s["substantive"] + s["hollow"]) / s["total"]

    rows = sorted(by_tactic.items(), key=headline)
    names = [f"{t}  (n={s['total']})" for t, s in rows]

    fig, ax = plt.subplots(figsize=(9.2, 5.6), dpi=160)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    for i, (_, s) in enumerate(rows):
        total = s["total"]
        sub = 100 * s["substantive"] / total
        hol = 100 * s["hollow"] / total
        ax.barh(i, 100, color=TRACK, height=0.62, edgecolor=SURFACE, linewidth=1.5)
        ax.barh(i, sub, color=BLUE, height=0.62, edgecolor=SURFACE, linewidth=1.5)
        ax.barh(i, hol, left=sub, color=ORANGE, height=0.62, edgecolor=SURFACE,
                linewidth=1.5, hatch="////")
        ax.text(101.5, i, f"{sub + hol:.0f}%", va="center", ha="left",
                fontsize=10, color=INK)

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(names, fontsize=10, color=INK)
    ax.set_xlim(0, 112)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"], fontsize=9, color=INK_MUTED)
    ax.set_xlabel("Share of sample files caught (label = headline coverage)",
                  fontsize=9, color=INK_MUTED)
    ax.tick_params(length=0)
    ax.xaxis.grid(True, color="#d9d8d2", linewidth=0.6)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)

    head = 100 * (overall["substantive"] + overall["hollow"]) / overall["total"]
    subst = 100 * overall["substantive"] / overall["total"]
    fig.suptitle("Detection coverage by ATT&CK tactic", x=0.012, y=0.988,
                 ha="left", fontsize=14, color=INK, fontweight="bold")
    fig.text(0.012, 0.905,
             f"{overall['total']} attack samples, 27 rules.  Headline {head:.0f}%, "
             f"substantive {subst:.0f}%: the orange share is hollow coverage.",
             ha="left", fontsize=10, color=INK_MUTED)

    fig.legend(
        handles=[
            Patch(facecolor=BLUE, edgecolor=SURFACE, label="Caught by a normal-confidence rule"),
            Patch(facecolor=ORANGE, edgecolor=SURFACE, hatch="////",
                  label="Caught only by low-confidence rules"),
            Patch(facecolor=TRACK, edgecolor=SURFACE, label="Not caught"),
        ],
        loc="lower center", ncol=3, frameon=False, fontsize=9, labelcolor=INK_MUTED,
        bbox_to_anchor=(0.5, 0.005),
    )

    fig.tight_layout(rect=(0, 0.07, 1, 0.895))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    fig.savefig(out_path, facecolor=SURFACE)
    plt.close(fig)
    return overall


if __name__ == "__main__":
    results_path = sys.argv[1] if len(sys.argv) > 1 else "results.json"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "docs/coverage.png"
    with open(results_path) as f:
        results = json.load(f)
    overall = draw(results, load_rules(), out_path)
    print(f"wrote {out_path}  ({overall['substantive']} substantive + "
          f"{overall['hollow']} hollow of {overall['total']} files)")
