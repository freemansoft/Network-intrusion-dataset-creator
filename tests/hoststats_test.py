# unit tests for hoststats.py per-host window statistics

from hoststats import HomeNet, Novelty, WindowHosts, labels_for, entropy
from collections import Counter

HOME = HomeNet(["10.0.0.0/8", "fc00::/7"])
T = 1_600_000_000_000  # msec


def tcp(src, dst, sport, dport, syn=False, ack=False, rst=False, length=60):
    return {
        "ip.src": src,
        "ip.dst": dst,
        "tcp.srcport": str(sport),
        "tcp.dstport": str(dport),
        "tcp.flags.syn": syn,
        "tcp.flags.ack": ack,
        "tcp.flags.reset": rst,
        "frame.len": str(length),
    }


def udp(src, dst, sport, dport, length=80):
    return {
        "ip.src": src,
        "ip.dst": dst,
        "udp.srcport": str(sport),
        "udp.dstport": str(dport),
        "frame.len": str(length),
    }


def feed(packets, novelty=None, start=T):
    window = WindowHosts()
    novelty = novelty or Novelty()
    for i, (protocol, packet) in enumerate(packets):
        window.update(packet, protocol, start + i, HOME, novelty)
    return window


def rows_by_host(window):
    return {row["host"]: row for row in window.host_rows(HOME, topk=20)}


def test_scan_counts_the_scanner_not_the_victim_replying_with_rst():
    packets = []
    for port in range(1, 101):
        packets.append(
            ("tcp", tcp("10.0.0.66", "10.0.0.50", 40000 + port, port, syn=True))
        )
        packets.append(
            (
                "tcp",
                tcp("10.0.0.50", "10.0.0.66", port, 40000 + port, rst=True, ack=True),
            )
        )
    rows = rows_by_host(feed(packets))
    assert rows["10.0.0.66"]["contacted_ports"] == 100
    assert rows["10.0.0.66"]["syn_out"] == 100
    assert rows["10.0.0.66"]["rst_in"] == 100
    assert rows["10.0.0.50"]["contacted_ports"] == 0
    assert rows["10.0.0.50"]["contacting_ips"] == 1


def test_window_columns_name_the_scanner_and_the_flood_victim():
    packets = [
        ("tcp", tcp("10.0.0.66", "10.0.0.50", 40000, p, syn=True)) for p in range(1, 51)
    ]
    packets += [
        ("tcp", tcp(f"203.0.113.{i}", "10.0.0.80", 1024 + i, 80, syn=True))
        for i in range(1, 201)
    ]
    columns = feed(packets).window_columns()
    assert columns["max_contacted_ports_per_src"] == 50
    assert columns["top_src_by_contacted_ports"] == "10.0.0.66"
    assert columns["max_contacting_ips_per_dst"] == 200
    assert columns["top_dst_by_contacting_ips"] == "10.0.0.80"


def test_udp_client_query_counts_service_port_but_reply_does_not():
    rows = rows_by_host(
        feed(
            [
                ("udp", udp("10.0.0.5", "10.0.0.53", 53211, 53)),
                ("udp", udp("10.0.0.53", "10.0.0.5", 53, 53211)),
            ]
        )
    )
    assert rows["10.0.0.5"]["contacted_ports"] == 1
    assert rows["10.0.0.53"]["contacted_ports"] == 0


def test_upload_counts_client_role_only():
    upload = ("tcp", tcp("10.0.0.5", "198.51.100.9", 51000, 443, ack=True, length=1400))
    server_reply = (
        "tcp",
        tcp("10.0.0.80", "198.51.100.9", 443, 51001, ack=True, length=1400),
    )
    rows = rows_by_host(feed([upload, server_reply]))
    assert rows["10.0.0.5"]["upload_bytes_ext"] == 1400
    assert rows["10.0.0.80"]["upload_bytes_ext"] == 0
    assert rows["10.0.0.80"]["bytes_out"] == 1400


def test_auth_port_syns():
    packets = [
        ("tcp", tcp("203.0.113.7", "10.0.0.22", 33000 + i, 22, syn=True))
        for i in range(5)
    ]
    rows = rows_by_host(feed(packets))
    assert rows["203.0.113.7"]["auth_syn_out"] == 5
    assert rows["10.0.0.22"]["auth_syn_in"] == 5


def test_novelty_within_and_after_horizon():
    novelty = Novelty(horizon_msec=1000)
    assert novelty.is_new(("port", "a", "22"), T)
    assert not novelty.is_new(("port", "a", "22"), T + 500)
    assert novelty.is_new(("port", "a", "22"), T + 2000)
    novelty.prune(T + 5000)
    assert novelty.last_seen == {}


def test_new_contacted_ports_carry_across_windows():
    novelty = Novelty(horizon_msec=600_000)
    first = rows_by_host(
        feed([("tcp", tcp("10.0.0.5", "10.0.0.6", 50000, 443, syn=True))], novelty)
    )
    second = rows_by_host(
        feed(
            [("tcp", tcp("10.0.0.5", "10.0.0.6", 50001, 443, syn=True))],
            novelty,
            start=T + 5000,
        )
    )
    assert first["10.0.0.5"]["new_contacted_ports"] == 1
    assert second["10.0.0.5"]["new_contacted_ports"] == 0
    assert second["10.0.0.5"]["contacted_ports"] == 1


def test_host_rows_keep_home_hosts_and_top_external():
    packets = [
        ("tcp", tcp(f"203.0.113.{i}", "10.0.0.80", 1024, 80, syn=True))
        for i in range(1, 31)
    ]
    rows = WindowHosts()
    for i, (protocol, packet) in enumerate(packets):
        rows.update(packet, protocol, T + i, HOME, Novelty())
    hosts = [row["host"] for row in rows.host_rows(HOME, topk=5)]
    assert "10.0.0.80" in hosts
    assert len(hosts) == 1 + 5


def test_home_net_handles_ipv6_and_garbage():
    assert HOME.contains("fd00::1")
    assert not HOME.contains("2001:db8::1")
    assert not HOME.contains("not-an-ip")


def test_labels_for_window_and_host():
    labels = [
        {"name": "scan", "start_msec": 1000, "end_msec": 2000, "ips": {"10.0.0.66"}},
        {"name": "noise", "start_msec": 0, "end_msec": 500, "ips": set()},
    ]
    assert labels_for(labels, 1500, 6500) == "scan"
    assert labels_for(labels, 1500, 6500, "10.0.0.66") == "scan"
    assert labels_for(labels, 1500, 6500, "10.0.0.50") == ""
    assert labels_for(labels, 0, 5000) == "scan+noise"


def test_entropy():
    assert entropy(Counter()) == 0.0
    assert entropy(Counter({"a": 5})) == 0.0
    assert entropy(Counter({"a": 1, "b": 1})) == 1.0


def test_udp_between_high_ports_is_not_an_initiated_contact():
    rows = rows_by_host(feed([("udp", udp("10.0.0.5", "10.0.0.6", 40000, 25326))]))
    assert rows["10.0.0.5"]["contacted_ports"] == 0
    assert rows["10.0.0.5"]["contacted_ips"] == 0


def test_window_columns_name_top_talkers_by_packets():
    packets = [
        ("tcp", tcp(f"198.51.100.{i}", "10.0.0.80", 1024, 80, ack=True))
        for i in range(1, 6)
    ]
    columns = feed(packets).window_columns()
    assert columns["top_dst_by_packets"] == "10.0.0.80"
