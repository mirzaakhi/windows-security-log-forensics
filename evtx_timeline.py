"""
evtx_timeline.py
----------------
Temporal visualisation of Windows Security Event Log data
parsed by EvtxECmd.

Usage:
    python evtx_timeline.py --csv ./output/evtxecmd_output.csv

Outputs:
    fig_event_timeline.pdf   (for LaTeX \includegraphics)
    fig_event_timeline.png   (quick preview)
"""

import argparse
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as mticker

matplotlib.rcParams.update({
    "font.family":       "serif",
    "font.size":         9,
    "axes.linewidth":    0.8,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
})

DEFAULT_CSV = "./output/evtxecmd_output.csv"

EVENT_CONFIG = {
    4625: {"label": "4625 - Failed logon (EventID 4625)",
           "color": "#D62728", "marker": "o", "ms": 3.5, "zorder": 4},
    4624: {"label": "4624 - Successful logon (EventID 4624)",
           "color": "#2CA02C", "marker": "^", "ms": 4.0, "zorder": 3},
}


def load_and_filter(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, low_memory=False)
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"],
                                       infer_datetime_format=True,
                                       errors="coerce")
    df.dropna(subset=["TimeCreated"], inplace=True)
    df = df[df["EventId"].isin(EVENT_CONFIG.keys())].copy()
    df.sort_values("TimeCreated", inplace=True)
    return df


def resample_series(df, eid, freq="1min"):
    sub = df[df["EventId"] == eid].copy()
    sub.set_index("TimeCreated", inplace=True)
    return sub.resample(freq).size()


def draw_timeline(df: pd.DataFrame,
                  freq: str = "1min",
                  threshold: int = 10):

    # ── Identify attack time and experiment day ───────────────
    fails_raw = df[df["EventId"] == 4625]["TimeCreated"]
    t_attack   = fails_raw.max() if not fails_raw.empty \
                 else df["TimeCreated"].max()
    experiment_day = t_attack.normalize()
    day_end        = experiment_day + pd.Timedelta(hours=24)

    fig, ax = plt.subplots(figsize=(10, 3.8))

    # ── Plot each EventID as vertical stems (today only) ──────
    all_series = {}
    for eid, cfg in EVENT_CONFIG.items():
        s_full = resample_series(df, eid, freq)
        s = s_full[(s_full.index >= experiment_day) &
                   (s_full.index < day_end)]
        s = s[s > 0]
        all_series[eid] = s
        if s.empty:
            continue
        for t, v in s.items():
            ax.vlines(t, 0, v,
                      color=cfg["color"],
                      linewidth=1.0,
                      zorder=cfg["zorder"])
            ax.plot(t, v,
                    marker=cfg["marker"],
                    color=cfg["color"],
                    markersize=cfg["ms"],
                    linestyle="none",
                    zorder=cfg["zorder"])
        ax.plot([], [],
                color=cfg["color"],
                marker=cfg["marker"],
                markersize=cfg["ms"],
                label=cfg["label"],
                linewidth=1.2)

    # ── Threshold line with baseline rationale ────────────────
    ax.axhline(y=threshold,
               color="#D62728", linestyle="--",
               linewidth=0.8, alpha=0.5,
               label=f"Detection threshold: {threshold} failures/min\n"
                     f"(normal failed-logon baseline: <3/min)")

    # ── Shade flagged window ──────────────────────────────────
    if 4625 in all_series and not all_series[4625].empty:
        flagged = all_series[4625][all_series[4625] >= threshold]
        for t in flagged.index:
            ax.axvspan(t, t + pd.Timedelta(minutes=1),
                       color="#D62728", alpha=0.10, zorder=1)

    # ── Vertical dotted line at exact attack timestamp ────────
    ax.axvline(x=t_attack, color="#D62728",
               linewidth=0.9, linestyle=":", alpha=0.85)

    # ── Attack annotations ────────────────────────────────────
    ymax = max((s.max() for s in all_series.values()
                if not s.empty), default=threshold + 5)

    # Arrow label — closer to spike
    ax.annotate("Suspected brute-force\nattack (rapid burst)",
                xy=(t_attack, ymax),
                xytext=(t_attack - pd.Timedelta(hours=1.8),
                        ymax * 0.88),
                fontsize=7.5,
                color="#D62728",
                ha="center",
                arrowprops=dict(arrowstyle="->",
                                color="#D62728",
                                lw=0.8))

    # Detail text just to the right of spike
    ax.text(t_attack + pd.Timedelta(minutes=20),
            ymax * 0.85,
            "20 failed attempts\nin 6s",
            fontsize=7,
            color="#D62728",
            va="top",
            ha="left")

    # ── X-axis: hourly ticks ──────────────────────────────────
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_xlabel("Time on 20 May 2026  (HH:MM, 1-minute aggregation)",
                  fontsize=8)
    ax.set_xlim(left=experiment_day,
                right=experiment_day + pd.Timedelta(hours=23))

    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.set_ylabel("Events per minute", fontsize=8)
    ax.set_ylim(bottom=0)

    plt.xticks(rotation=45, ha="right", fontsize=6.5)

    # ── Highlight nearest tick to attack timestamp ─────────────
    fig.canvas.draw()
    labels = ax.get_xticklabels()
    locs   = ax.xaxis.get_majorticklocs()

    nearest_idx = None
    min_diff = None

    for idx, loc in enumerate(locs):
        dt = pd.Timestamp(mdates.num2date(loc)).replace(tzinfo=None)
        diff = abs((dt - t_attack).total_seconds())

        if min_diff is None or diff < min_diff:
            min_diff = diff
            nearest_idx = idx

    if nearest_idx is not None:
        labels[nearest_idx].set_color("#D62728")
        labels[nearest_idx].set_fontweight("bold")

    ax.set_xticklabels(labels)

    # ── Spines ───────────────────────────────────────────────
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # ── Legend ───────────────────────────────────────────────
    ax.legend(fontsize=6, framealpha=0.6,
              loc="upper left", handlelength=1.8)

    plt.tight_layout(pad=0.5)
    return fig


def main():
    parser = argparse.ArgumentParser(
        description="Plot EventID frequency timeline from EvtxECmd CSV.")
    parser.add_argument("--csv",       default=DEFAULT_CSV)
    parser.add_argument("--freq",      default="1min")
    parser.add_argument("--threshold", type=int, default=10)
    args = parser.parse_args()

    print(f"[+] Loading: {args.csv}")
    df = load_and_filter(args.csv)
    print(f"[+] Rows after filter: {len(df)}")

    fig = draw_timeline(df, freq=args.freq, threshold=args.threshold)

    for ext in ("pdf", "png"):
        path = f"fig_event_timeline.{ext}"
        fig.savefig(path, dpi=300, bbox_inches="tight")
        print(f"[+] Saved: {path}")

    plt.show()


if __name__ == "__main__":
    main()
