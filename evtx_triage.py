"""
evtx_triage.py
--------------
Automated triage of EvtxECmd CSV output.

Usage:
    python evtx_triage.py --csv ./output/evtxecmd_output.csv

Outputs:
    - Console table of flagged one-minute windows
    - flagged_windows.csv  (save alongside the .evtx export)

EventIDs analysed:
    4625  Failed logon attempt
    4624  Successful logon
    4688  New process created
"""

import argparse
import pandas as pd

# ── Configuration ─────────────────────────────────────────────
DEFAULT_CSV  = "./output/evtxecmd_output.csv"
THRESHOLD    = 10          # failures per 1-min window to flag
TARGET_IDS   = [4624, 4625, 4688]
LABELS       = {4625: "Failed logon",
                4624: "Successful logon",
                4688: "Process created"}


def load_and_filter(csv_path: str) -> pd.DataFrame:
    """Load CSV, parse timestamps, keep only target EventIDs."""
    df = pd.read_csv(csv_path, low_memory=False)

    # EvtxECmd field names (adjust if your export differs)
    if "TimeCreated" not in df.columns:
        raise ValueError("Expected 'TimeCreated' column not found. "
                         "Check your EvtxECmd CSV header names.")
    if "EventId" not in df.columns:
        raise ValueError("Expected 'EventId' column not found.")

    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"],
                                       infer_datetime_format=True,
                                       errors="coerce")
    df.dropna(subset=["TimeCreated"], inplace=True)
    df = df[df["EventId"].isin(TARGET_IDS)].copy()
    df.sort_values("TimeCreated", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def compute_failure_rate(df: pd.DataFrame) -> pd.Series:
    """Count EventID 4625 occurrences per one-minute bin."""
    failures = df[df["EventId"] == 4625].copy()
    failures.set_index("TimeCreated", inplace=True)
    rate = failures.resample("1min").size().rename("FailureCount")
    return rate


def cross_reference(df: pd.DataFrame,
                    flagged: pd.Series) -> pd.DataFrame:
    """
    For each flagged window, check whether a 4624 or 4688 follows
    within the next 5 minutes.  Returns an enriched summary table.
    """
    rows = []
    for window_start, count in flagged.items():
        window_end   = window_start + pd.Timedelta(minutes=1)
        followup_end = window_start + pd.Timedelta(minutes=5)

        # Events in the 5-minute follow-up window
        after = df[(df["TimeCreated"] >= window_end) &
                   (df["TimeCreated"] <= followup_end)]

        has_4624 = (after["EventId"] == 4624).any()
        has_4688 = (after["EventId"] == 4688).any()

        severity = "LOW"
        if has_4624 and has_4688:
            severity = "HIGH"
        elif has_4624:
            severity = "MEDIUM"

        rows.append({
            "WindowStart":      window_start,
            "FailureCount":     count,
            "SuccessFollowed":  has_4624,
            "ProcessFollowed":  has_4688,
            "Severity":         severity,
        })

    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Triage EvtxECmd CSV output for anomalous "
                    "authentication patterns.")
    parser.add_argument("--csv", default=DEFAULT_CSV,
                        help="Path to EvtxECmd CSV output file.")
    parser.add_argument("--threshold", type=int, default=THRESHOLD,
                        help="Failure count per minute to flag "
                             f"(default: {THRESHOLD}).")
    args = parser.parse_args()

    print(f"[+] Loading: {args.csv}")
    df = load_and_filter(args.csv)
    print(f"[+] Filtered rows (target EventIDs): {len(df)}")

    # ── Per-EventID summary ───────────────────────────────────
    print("\n=== Event Count by Type ===")
    for eid in TARGET_IDS:
        n = (df["EventId"] == eid).sum()
        print(f"  EventID {eid} ({LABELS[eid]}): {n}")

    # ── Failure rate & flagging ───────────────────────────────
    fail_rate = compute_failure_rate(df)
    flagged   = fail_rate[fail_rate >= args.threshold]

    print(f"\n=== Flagged Windows "
          f"(threshold ≥ {args.threshold} failures/min) ===")
    if flagged.empty:
        print("  No windows exceeded the threshold.")
    else:
        print(flagged.to_string())

    # ── Cross-reference ───────────────────────────────────────
    if not flagged.empty:
        summary = cross_reference(df, flagged)
        print("\n=== Enriched Triage Summary ===")
        print(summary.to_string(index=False))

        out_path = "flagged_windows.csv"
        summary.to_csv(out_path, index=False)
        print(f"\n[+] Saved enriched summary to: {out_path}")
        print(f"[+] Total HIGH windows:     "
              f"{(summary['Severity'] == 'HIGH').sum()}")
        print(f"[+] Total MEDIUM windows:   "
              f"{(summary['Severity'] == 'MEDIUM').sum()}")


if __name__ == "__main__":
    main()
