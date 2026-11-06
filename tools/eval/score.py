#!/usr/bin/env python3
"""Score detect.py alerts against a label file.

    python3 tools/eval/score.py ALERTS.jsonl LABELS.csv WINDOWS.csv [WINDOWS.csv ...] [--window-after 600]

Labels: label,start,end[,ips][,kinds] (epoch seconds; ips and kinds space-separated). An alert
matches a label when its host is one of the label's ips (any host when the label has none), its
kind is one of the label's kinds (any kind when the label has none; a kind ending in * is a
prefix) and its window starts between 10 s before the label and --window-after seconds after it
ends. Give kinds when labels overlap in time on the same host (an injected beacon during a scan),
or an alert for one attack is credited to the other. Time to detect is measured from the label
start.

False-alarm windows: windows with at least one alert that matches no label, as a share of all
windows in the WINDOWS files. The unmatched alerts are listed by kind and host so each can be
explained or fixed.
"""

import argparse
import csv
import json
from collections import Counter


def load_labels(path):
    labels = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            labels.append(
                {
                    "name": row["label"],
                    "start": float(row["start"]) * 1000,
                    "end": float(row["end"]) * 1000,
                    "ips": set((row.get("ips") or "").split()),
                    "kinds": (row.get("kinds") or "").split(),
                }
            )
    return labels


def load_alerts(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def count_windows(paths):
    n = 0
    for path in paths:
        with open(path, newline="") as f:
            n += sum(1 for _ in csv.DictReader(f))
    return n


def kind_matches(kind, kinds):
    return not kinds or any(
        kind == k or (k.endswith("*") and kind.startswith(k[:-1])) for k in kinds
    )


def matches(alert, label, window_after_msec):
    t = alert["window_start_time"]
    in_time = label["start"] - 10_000 <= t <= label["end"] + window_after_msec
    # an alert naming a peer (beacons) must name one of the label's addresses there too, or a
    # benign beacon from the infected host would be credited with finding the C2
    peer = alert.get("peer", "").rsplit(":", 1)[0]
    return (
        in_time
        and (not label["ips"] or alert["host"] in label["ips"])
        and (not peer or not label["ips"] or peer in label["ips"])
        and kind_matches(alert["kind"], label["kinds"])
    )


def score(alerts_path, labels_path, windows_paths, window_after=600):
    """Return the report as text and the summary numbers as a dict."""
    alerts = load_alerts(alerts_path)
    labels = load_labels(labels_path)
    n_windows = count_windows(windows_paths)
    after = window_after * 1000
    lines = [f"{'label':24s} detected  first alert after  kinds"]
    detected = 0
    for label in labels:
        hits = [a for a in alerts if matches(a, label, after)]
        if hits:
            detected += 1
            first = min(a["window_start_time"] for a in hits)
            kinds = Counter(a["kind"] for a in hits)
            lines.append(
                f"{label['name']:24s} yes       {max(0, (first - label['start']) / 1000):6.0f} s"
                f"           {dict(kinds.most_common(3))}"
            )
        else:
            lines.append(f"{label['name']:24s} NO")
    unmatched = [a for a in alerts if not any(matches(a, l, after) for l in labels)]
    # beacon alerts (they name a peer) are one per pair over the whole capture, not per window, so
    # they are counted as pairs and kept out of the window rate
    fa_windows = {a["window_start_time"] for a in unmatched if "peer" not in a}
    fa_peers = sorted(
        (-a.get("evidence", 0), a["host"], a["peer"]) for a in unmatched if "peer" in a
    )
    rate = len(fa_windows) / n_windows if n_windows else 0.0
    lines.append("")
    lines.append(
        f"labels detected={detected}/{len(labels)} alerts={len(alerts)} unmatched={len(unmatched)} "
        f"false-alarm windows={len(fa_windows)}/{n_windows} = {rate:.2%} "
        f"false-alarm beacon pairs={len(fa_peers)} "
        f"(with evidence: {sum(1 for e, _, _ in fa_peers if e < 0)})"
    )
    for (kind, host), n in Counter(
        (a["kind"], a["host"] + (" -> " + a["peer"] if "peer" in a else ""))
        for a in unmatched
    ).most_common(12):
        lines.append(f"  {n:5d}  {kind:22s} {host}")
    summary = {
        "labels": len(labels),
        "detected": detected,
        "alerts": len(alerts),
        "unmatched": len(unmatched),
        "false_alarm_windows": len(fa_windows),
        "windows": n_windows,
        "false_alarm_rate": rate,
        "false_alarm_beacon_pairs": len(fa_peers),
        "false_alarm_beacon_pairs_with_evidence": sum(
            1 for e, _, _ in fa_peers if e < 0
        ),
    }
    return "\n".join(lines), summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("alerts")
    parser.add_argument("labels")
    parser.add_argument("windows", nargs="+")
    parser.add_argument("--window-after", type=float, default=600)
    args = parser.parse_args(argv)
    text, _ = score(args.alerts, args.labels, args.windows, args.window_after)
    print(text)


if __name__ == "__main__":
    main()
