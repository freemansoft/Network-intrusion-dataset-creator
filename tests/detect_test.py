# unit tests for detect.py rules, volume baseline and incident merging

import csv
import json

import pytest

import detect
from counts import TimesAndCounts
from connections import CONN_FIELDNAMES
from hoststats import HOST_FIELDNAMES

T0 = 1_600_000_000_000
STEP = 5000


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, restval="0")
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


def windows(n, overrides_by_index=None):
    rows = []
    for i in range(n):
        row = {
            "window_start_time": T0 + i * STEP,
            "window_end_time": T0 + i * STEP + 4000,
            "num_packets": 1000,
            "num_tcp": 900,
            "tcp_frame_length": 600000,
        }
        row.update((overrides_by_index or {}).get(i, {}))
        rows.append(row)
    return rows


def host(i, name, **values):
    return {
        "window_start_time": T0 + i * STEP,
        "window_end_time": T0 + i * STEP + 4000,
        "host": name,
        "is_home": 1,
        **values,
    }


def run(tmp_path, window_rows, host_rows=(), **overrides):
    w = write_csv(tmp_path / "w.csv", TimesAndCounts.fieldnames, window_rows)
    h = (
        write_csv(tmp_path / "h.csv", HOST_FIELDNAMES, list(host_rows))
        if host_rows
        else None
    )
    t = dict(detect.THRESHOLDS, **overrides)
    return detect.detect(w, h, t)


def kinds(alerts):
    return {(a["kind"], a["host"]) for a in alerts}


def test_quiet_capture_raises_nothing(tmp_path):
    assert run(tmp_path, windows(200)) == []


def test_syn_flood_names_the_victim(tmp_path):
    flood = {
        "num_syn": 7000,
        "num_synack": 3,
        "max_contacting_ips_per_dst": 6900,
        "top_dst_by_contacting_ips": "10.0.0.80",
    }
    assert ("syn_flood", "10.0.0.80") in kinds(run(tmp_path, windows(10, {5: flood})))


def test_fast_port_scan(tmp_path):
    rows = [host(3, "10.0.0.66", contacted_ports=625)]
    assert ("port_scan", "10.0.0.66") in kinds(run(tmp_path, windows(10), rows))


def test_slow_scan_accumulates_new_ports_across_windows(tmp_path):
    # 3 new ports per window: never a fast scan, but 42 within 70 s
    rows = [
        host(i, "10.0.0.66", new_contacted_ports=3, contacted_ports=3)
        for i in range(14)
    ]
    found = run(tmp_path, windows(20), rows)
    assert ("slow_port_scan", "10.0.0.66") in kinds(found)
    assert ("port_scan", "10.0.0.66") not in kinds(found)


def test_slow_scan_forgets_contacts_outside_the_span(tmp_path):
    rows = [
        host(i * 30, "10.0.0.5", new_contacted_ports=3) for i in range(20)
    ]  # 3 every 150 s
    assert run(tmp_path, windows(600), rows, slow_scan_span_sec=600) == []


def test_login_bruteforce(tmp_path):
    rows = [
        host(i, "203.0.113.7", auth_syn_out=2, syn_out=2, synack_in=2)
        for i in range(12)
    ]
    assert ("login_bruteforce", "203.0.113.7") in kinds(
        run(tmp_path, windows(20), rows)
    )


def test_large_upload_needs_size_and_ratio(tmp_path):
    upload = [
        host(i, "10.0.0.50", upload_bytes_ext=7_000_000, download_bytes_ext=100_000)
        for i in range(6)
    ]
    assert ("large_upload", "10.0.0.50") in kinds(run(tmp_path, windows(10), upload))
    balanced = [
        host(i, "10.0.0.51", upload_bytes_ext=7_000_000, download_bytes_ext=7_000_000)
        for i in range(6)
    ]
    assert run(tmp_path, windows(10), balanced) == []


def test_failed_connections(tmp_path):
    rows = [host(i, "10.0.0.66", syn_out=30, synack_in=0) for i in range(5)]
    assert ("failed_connections", "10.0.0.66") in kinds(
        run(tmp_path, windows(10), rows)
    )


def test_volume_needs_two_consecutive_material_windows(tmp_path):
    spike = {"num_packets": 50000, "num_tcp": 49000}
    one = run(tmp_path, windows(100, {80: spike}))
    assert not [a for a in one if a["kind"].startswith("volume_")]
    two = run(tmp_path, windows(100, {80: spike, 81: spike}))
    assert "volume_num_packets" in {a["kind"] for a in two}


def test_volume_ignores_large_ratios_on_near_silent_traffic(tmp_path):
    quiet = [
        {"num_packets": 2, "num_tcp": 2, "tcp_frame_length": 120} for _ in range(100)
    ]
    rows = windows(100, {i: quiet[i] for i in range(100)})
    rows[80].update(num_packets=60, num_tcp=60, tcp_frame_length=6000)
    rows[81].update(num_packets=60, num_tcp=60, tcp_frame_length=6000)
    assert run(tmp_path, rows) == []


def test_incidents_merge_same_kind_and_host():
    alerts = [
        {
            "kind": "port_scan",
            "host": "a",
            "window_start_time": T0,
            "ts_start": "x",
            "detail": "",
        },
        {
            "kind": "port_scan",
            "host": "a",
            "window_start_time": T0 + 60_000,
            "ts_start": "y",
            "detail": "",
        },
        {
            "kind": "port_scan",
            "host": "a",
            "window_start_time": T0 + 600_000,
            "ts_start": "z",
            "detail": "",
        },
        {
            "kind": "port_scan",
            "host": "b",
            "window_start_time": T0,
            "ts_start": "x",
            "detail": "",
        },
    ]
    merged = detect.incidents(alerts, gap_sec=120)
    assert [(i["host"], i["alerts"]) for i in merged] == [("a", 2), ("b", 1), ("a", 1)]


def test_cli_writes_jsonl_and_rejects_unknown_thresholds(tmp_path, capsys):
    flood = {
        "num_syn": 7000,
        "num_synack": 3,
        "max_contacting_ips_per_dst": 6900,
        "top_dst_by_contacting_ips": "10.0.0.80",
    }
    w = write_csv(
        tmp_path / "w.csv", TimesAndCounts.fieldnames, windows(10, {5: flood})
    )
    out = tmp_path / "alerts.jsonl"
    detect.main([w, "-o", str(out), "--incidents", str(tmp_path / "inc.jsonl")])
    assert json.loads(out.read_text().splitlines()[0])["kind"] == "syn_flood"
    detect.main([w, "-o", str(out), "--set", "syn_flood_half_open=10000"])
    assert out.read_text() == ""
    with pytest.raises(SystemExit):
        detect.main([w, "--set", "no_such_threshold=1"])


def test_one_extreme_window_alerts_and_names_top_destination(tmp_path):
    flood = {
        "num_packets": 5_000_000,
        "num_tcp": 5_000_000,
        "top_dst_by_packets": "131.84.1.31",
    }
    found = run(tmp_path, windows(100, {80: flood}))
    assert ("volume_num_packets", "131.84.1.31") in kinds(found)


def alert_at(kind, host, observed, i=0):
    return {
        "kind": kind,
        "host": host,
        "observed": observed,
        "window_start_time": T0 + i * STEP,
    }


def test_learned_suppression_drops_known_noisy_host_unless_it_escalates():
    baseline = [
        alert_at("failed_connections", "10.0.0.118", v) for v in (150, 600, 400)
    ]
    peaks = detect.learn_suppressions(baseline)
    assert peaks == {("failed_connections", "10.0.0.118", ""): 600}
    later = [
        alert_at("failed_connections", "10.0.0.118", 550),  # usual for this host
        alert_at(
            "failed_connections", "10.0.0.118", 2000
        ),  # escalated past 3x its peak
        alert_at(
            "failed_connections", "10.0.0.165", 360
        ),  # a host never seen doing this
    ]
    kept = detect.apply_suppressions(later, peaks, escalation=3.0)
    assert [(a["host"], a["observed"]) for a in kept] == [
        ("10.0.0.118", 2000),
        ("10.0.0.165", 360),
    ]


def test_learning_skips_known_incident_hosts_and_later_windows():
    alerts = [
        alert_at("login_bruteforce", "10.0.0.7", 40, i=0),
        alert_at("failed_connections", "10.0.0.66", 500, i=1),
        alert_at("slow_sweep", "10.0.0.59", 300, i=100),
    ]
    peaks = detect.learn_suppressions(
        alerts, until_msec=T0 + 50 * STEP, exclude_hosts={"10.0.0.66"}
    )
    assert set(peaks) == {("login_bruteforce", "10.0.0.7", "")}


def test_dict_observed_values_use_their_first_number():
    assert detect.scalar({"upload": 30e6, "download": 1e6}) == 30e6
    assert detect.scalar(7) == 7.0


def test_several_days_read_as_one_run_in_time_order(tmp_path):
    # a failed-connection host rule needs 5 windows; split them across two daily files, hosts
    # written as window 3-4 on day 1 and 0-2 on day 2 (day 2 = T0 + 1 day), given out of order
    day = 86_400_000
    rows1 = [host(i, "10.0.0.66", syn_out=30, synack_in=0) for i in range(3)]
    rows2 = [host(i, "10.0.0.66", syn_out=30, synack_in=0) for i in range(2)]
    for r in rows2:
        r["window_start_time"] += day
        r["window_end_time"] += day
    w1 = write_csv(tmp_path / "w1.csv", TimesAndCounts.fieldnames, windows(3))
    w2_rows = windows(2)
    for r in w2_rows:
        r["window_start_time"] += day
        r["window_end_time"] += day
    w2 = write_csv(tmp_path / "w2.csv", TimesAndCounts.fieldnames, w2_rows)
    h1 = write_csv(tmp_path / "h1.csv", HOST_FIELDNAMES, rows1)
    h2 = write_csv(tmp_path / "h2.csv", HOST_FIELDNAMES, rows2)

    c1 = write_csv(
        tmp_path / "c1.csv", CONN_FIELDNAMES, [{"start_msec": T0, "state": "SF"}]
    )
    assert detect.classify_inputs([h2, c1, w2, h1, w1]) == (
        [w1, w2],
        [h1, h2],
        [c1],
    )
    # a day apart, the 600 s failed-connection span never holds 5 windows: no alert either way
    assert detect.detect([w1, w2], [h1, h2], detect.THRESHOLDS) == []
    # moved to the same day, the rows across the two files add up
    for r in rows2:
        r["window_start_time"] -= day - 3 * STEP
        r["window_end_time"] -= day - 3 * STEP
    h2 = write_csv(tmp_path / "h2.csv", HOST_FIELDNAMES, rows2)
    found = detect.detect([w1, w2], [h1, h2], detect.THRESHOLDS)
    assert ("failed_connections", "10.0.0.66") in kinds(found)
    out = tmp_path / "a.jsonl"
    detect.main([h2, w2, h1, w1, "-o", str(out)])
    assert json.loads(out.read_text().splitlines()[0])["kind"] == "failed_connections"
    with pytest.raises(SystemExit):
        detect.main([h1, "-o", str(out)])


def test_cli_learn_then_suppress(tmp_path):
    rows = [host(i, "10.0.0.118", syn_out=30, synack_in=0) for i in range(5)]
    w = write_csv(tmp_path / "w.csv", TimesAndCounts.fieldnames, windows(10))
    h = write_csv(tmp_path / "h.csv", HOST_FIELDNAMES, rows)
    supp = tmp_path / "supp.csv"
    detect.main(
        [w, h, "-o", str(tmp_path / "a.jsonl"), "--learn-suppressions", str(supp)]
    )
    assert "failed_connections,10.0.0.118" in supp.read_text()
    detect.main([w, h, "-o", str(tmp_path / "b.jsonl"), "--suppress", str(supp)])
    assert (tmp_path / "b.jsonl").read_text() == ""
