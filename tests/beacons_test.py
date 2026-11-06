# unit tests for beacons.py, the beacon scorer over the connection log

import json
import os
import sys

import beacons
import detect
from connections import CONN_FIELDNAMES
from counts import TimesAndCounts

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "eval"
    ),
)
import score  # noqa: E402

T = 1_600_000_000  # seconds
HOST, C2 = "10.0.0.5", "203.0.113.77"
NO_ALLOW = (set(), [])


def conn(start, dst=C2, dport="443", src=HOST, state="SF", sent=500, **extra):
    row = {name: "" for name in CONN_FIELDNAMES}
    row.update(
        start_msec=str(int(start * 1000)),
        end_msec=str(int(start * 1000) + 200),
        src=src,
        sport="50000",
        dst=dst,
        dport=dport,
        proto="udp" if dport == "123" else "tcp",
        initiated="1",
        src_home="1",
        dst_home="0",
        bytes_out=str(sent),
        state=state,
    )
    row.update(extra)
    return row


def periodic(n=40, period=60.0, **kwargs):
    return [conn(T + i * period, **kwargs) for i in range(n)]


def alerts_for(rows, allowlist=NO_ALLOW, **t):
    return beacons.beacon_alerts(rows, {**beacons.DEFAULTS, **t}, allowlist)


def test_a_steady_beacon_alerts_with_its_peer_period_and_scores():
    [a] = alerts_for(periodic())
    assert (a["kind"], a["host"], a["peer"]) == ("beacon", HOST, f"{C2}:443")
    assert a["observed"]["period_sec"] == 60.0
    assert a["observed"]["attempts"] == 40
    assert a["observed"]["coverage"] == 1.0 and a["observed"]["score"] == 1.0
    assert a["window_start_time"] == T * 1000
    assert a["evidence"] == 0 and a["facts"] == []


def test_retries_after_unanswered_contacts_merge_but_answered_bursts_do_not():
    attempts = [(0, 60, False), (1, 60, False), (2.5, 60, True), (100, 60, True)]
    assert beacons.collapse_retries(attempts, 3) == [(0, 180), (100, 60)]
    burst = [(0, 60, True), (2, 60, True), (4, 60, True)]
    assert beacons.collapse_retries(burst, 3) == [(0, 60), (2, 60), (4, 60)]


def test_a_beacon_with_syn_retries_still_scores_as_one_attempt_per_period():
    rows = []
    for i in range(30):
        rows += [
            conn(T + i * 60, state="S0"),
            conn(T + i * 60 + 1, state="S0"),
            conn(T + i * 60 + 2),
        ]
    [a] = alerts_for(rows)
    assert a["observed"]["attempts"] == 30 and a["observed"]["period_sec"] == 60.0


def test_bursts_are_not_beacons():
    # bursts of answered connections 2 s apart every 45 minutes: median gap below the minimum
    rows = []
    for burst in range(24):
        rows += [conn(T + burst * 2700 + k * 2) for k in range(5)]
    assert alerts_for(rows) == []


def test_coverage_is_low_when_a_period_holds_for_part_of_the_span():
    times = [i * 10.0 for i in range(100)] + [86_000.0]
    assert beacons.coverage(times, 10.0) < 0.02
    assert beacons.coverage([i * 10.0 for i in range(100)], 10.0) == 1.0


def test_qualification_needs_contacts_span_and_gap():
    t = beacons.DEFAULTS
    assert beacons.score_pair([(T + i * 60, 1) for i in range(9)], t) is None
    assert (
        beacons.score_pair([(T + i * 20, 1) for i in range(12)], t) is None
    )  # 220 s span
    assert (
        beacons.score_pair([(T + i * 4, 1) for i in range(100)], t) is None
    )  # 4 s gaps
    assert beacons.score_pair([(T + i * 60, 1) for i in range(10)], t) is not None


def test_irregular_contacts_do_not_alert():
    gaps = [5, 400, 30, 2000, 90, 15, 700, 60, 1200, 10, 300, 45, 3000, 20]
    rows, now = [], T
    for gap in gaps:
        now += gap
        rows.append(conn(now))
    assert alerts_for(rows) == []


def test_multicast_broadcast_and_home_destinations_are_ignored():
    rows = (
        periodic(dst="239.255.255.250", dport="1900")
        + periodic(dst="10.0.0.255", dport="137")
        + periodic(dst="10.0.0.9", dst_home="1")
    )
    assert alerts_for(rows) == []


def test_allowlist_by_port_and_network():
    ntp = periodic(dst="198.51.100.1", dport="123")
    assert alerts_for(ntp, beacons.load_allowlist()) == []
    assert len(alerts_for(ntp)) == 1
    allow = (set(), [beacons.ipaddress.ip_network("203.0.113.0/24")])
    assert alerts_for(periodic(), allow) == []


def test_popular_destinations_are_shared_services():
    rows = []
    for k in range(5):
        rows += periodic(src=f"10.0.0.{10 + k}", dst="198.51.100.25", dport="25")
    assert alerts_for(rows) == []
    assert len(alerts_for(rows, beacon_popular_hosts=6)) == 5


def test_evidence_counts_odd_tls_and_http_facts():
    tls = periodic(tls_ja3="abc", cert_self_signed="1")
    other = [conn(T, dst="198.51.100.2", tls_ja3="browser", tls_sni="example.com")]
    [a] = alerts_for(tls + other)
    assert a["facts"] == ["tls_no_sni", "ja3_single_destination", "cert_self_signed"]
    assert a["evidence"] == 3
    # the same JA3 toward another destination is not single-destination
    shared = [conn(T, dst="198.51.100.2", tls_ja3="abc", tls_sni="x.example")]
    [a] = alerts_for(tls + shared)
    assert "ja3_single_destination" not in a["facts"]
    http = periodic(dport="80", http_host=f"{C2}:80", http_user_agent="implant/1.0")
    [a] = alerts_for(http)
    assert a["facts"] == ["http_host_is_ip", "user_agent_single_destination"]


def test_detect_cli_reads_connections_and_suppresses_by_peer(tmp_path):
    def write(path, fieldnames, rows):
        import csv

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, restval="0")
            writer.writeheader()
            writer.writerows(rows)
        return str(path)

    windows = write(
        tmp_path / "w.csv",
        TimesAndCounts.fieldnames,
        [{"window_start_time": T * 1000, "window_end_time": T * 1000 + 4999}],
    )
    two = periodic() + periodic(dst="198.51.100.7")
    connections = write(tmp_path / "c.csv", CONN_FIELDNAMES, two)
    out, supp = tmp_path / "a.jsonl", tmp_path / "supp.csv"
    detect.main([windows, connections, "-o", str(out), "--beacon-allow", os.devnull])
    found = [json.loads(line) for line in out.read_text().splitlines()]
    assert sorted(a["peer"] for a in found) == ["198.51.100.7:443", f"{C2}:443"]
    # learn on the benign peer only; the other one still alerts
    benign = write(tmp_path / "b.csv", CONN_FIELDNAMES, periodic(dst="198.51.100.7"))
    detect.main([windows, benign, "-o", os.devnull, "--learn-suppressions", str(supp)])
    detect.main([windows, connections, "-o", str(out), "--suppress", str(supp)])
    found = [json.loads(line) for line in out.read_text().splitlines()]
    assert [a["peer"] for a in found] == [f"{C2}:443"]
    # incidents keep two peers of one host apart
    merged = detect.incidents(alerts_for(two), 120)
    assert len(merged) == 2 and {i["peer"] for i in merged} == {
        f"{C2}:443",
        "198.51.100.7:443",
    }


def test_scorer_needs_the_beacon_peer_in_the_label():
    label = {
        "name": "c2",
        "start": T * 1000,
        "end": (T + 3600) * 1000,
        "ips": {HOST, C2},
        "kinds": [],
    }
    [c2] = alerts_for(periodic())
    [benign] = alerts_for(periodic(dst="198.51.100.7"))
    assert score.matches(c2, label, 600_000)
    assert not score.matches(benign, label, 600_000)
