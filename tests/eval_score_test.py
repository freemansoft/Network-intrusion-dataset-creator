# unit tests for tools/eval/score.py: label matching and the false-alarm rate

import csv
import json
import os
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "eval"
    ),
)
import score  # noqa: E402

T0 = 1_600_000_000


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def test_matches_by_host_and_time_and_counts_false_alarm_windows(tmp_path):
    windows = tmp_path / "w.csv"
    with open(windows, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["window_start_time", "window_end_time", "num_packets"])
        for i in range(100):
            w.writerow([(T0 + 5 * i) * 1000, (T0 + 5 * i + 4) * 1000, 10])
    labels = write(
        tmp_path,
        "labels.csv",
        f"label,start,end,ips\nscan,{T0 + 100},{T0 + 110},10.0.0.66 10.0.0.50\nflood,{T0 + 300},{T0 + 310},\n",
    )
    alerts = [
        {
            "kind": "port_scan",
            "host": "10.0.0.66",
            "window_start_time": (T0 + 105) * 1000,
        },  # scan
        {
            "kind": "port_scan",
            "host": "10.0.0.9",
            "window_start_time": (T0 + 105) * 1000,
        },  # wrong host
        {
            "kind": "syn_flood",
            "host": "anyone",
            "window_start_time": (T0 + 305) * 1000,
        },  # flood, no ips
        {
            "kind": "syn_flood",
            "host": "anyone",
            "window_start_time": (T0 + 305) * 1000,
        },  # same window
        {
            "kind": "large_upload",
            "host": "10.0.0.66",
            "window_start_time": (T0 + 400) * 1000,
        },  # late
    ]
    alerts_path = write(
        tmp_path, "a.jsonl", "".join(json.dumps(a) + "\n" for a in alerts)
    )
    text, summary = score.score(alerts_path, labels, [str(windows)], window_after=60)
    assert summary["detected"] == 2
    assert summary["unmatched"] == 2
    assert (
        summary["false_alarm_windows"] == 2
    )  # the wrong-host and the late alert, distinct windows
    assert summary["windows"] == 100
    assert "scan                     yes" in text
    assert "port_scan              10.0.0.9" in text


def test_kinds_column_keeps_overlapping_labels_apart(tmp_path):
    windows = tmp_path / "w.csv"
    with open(windows, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["window_start_time", "window_end_time", "num_packets"])
        w.writerow([T0 * 1000, (T0 + 4) * 1000, 10])
    # a beacon and a scan by the same host at the same time: only a beacon alert may credit the beacon
    labels = write(
        tmp_path,
        "labels.csv",
        f"label,start,end,ips,kinds\nscan,{T0},{T0 + 100},10.0.0.66,port_scan slow_*\n"
        f"beacon,{T0},{T0 + 100},10.0.0.66,beacon\n",
    )
    alerts = [
        {"kind": "slow_port_scan", "host": "10.0.0.66", "window_start_time": T0 * 1000}
    ]
    alerts_path = write(
        tmp_path, "a.jsonl", "".join(json.dumps(a) + "\n" for a in alerts)
    )
    text, summary = score.score(alerts_path, labels, [str(windows)])
    assert summary["detected"] == 1
    assert summary["unmatched"] == 0
    assert "beacon                   NO" in text
