# unit tests for connections.py, the connection log

import json

from capture import PacketCapture, keep_duplicate_times
from connections import (
    ConnectionTable,
    certificate_validity,
    connection_labels,
    self_signed,
    x509_epoch,
)
from hoststats import HomeNet
from loggingconfig import load_logging

load_logging()

HOME = HomeNet(["10.0.0.0/8"])
T = 1_600_000_000_000  # msec
CLIENT, SERVER = "10.0.0.5", "203.0.113.9"


def tcp(src, dst, sport, dport, flags="", length=60, **extra):
    return {
        "ip.src": src,
        "ip.dst": dst,
        "tcp.srcport": str(sport),
        "tcp.dstport": str(dport),
        "tcp.flags.syn": "S" in flags,
        "tcp.flags.ack": "A" in flags,
        "tcp.flags.fin": "F" in flags,
        "tcp.flags.reset": "R" in flags,
        "frame.len": str(length),
        **extra,
    }


def udp(src, dst, sport, dport, length=80, **extra):
    return {
        "ip.src": src,
        "ip.dst": dst,
        "udp.srcport": str(sport),
        "udp.dstport": str(dport),
        "frame.len": str(length),
        **extra,
    }


def icmp(src, dst, icmp_type, code="0", length=98):
    return {
        "ip.src": src,
        "ip.dst": dst,
        "icmp.type": icmp_type,
        "icmp.code": code,
        "frame.len": str(length),
    }


def out(flags="", length=60, sport=50000, **extra):
    return ("tcp", tcp(CLIENT, SERVER, sport, 443, flags, length, **extra))


def back(flags="", length=60, sport=50000, **extra):
    return ("tcp", tcp(SERVER, CLIENT, 443, sport, flags, length, **extra))


def run(packets, table=None, sweep_every=None):
    """packets: (protocol, packet) or (protocol, packet, msec offset); returns rows by start."""
    table = table or ConnectionTable(HOME)
    for i, item in enumerate(packets):
        protocol, packet = item[0], item[1]
        now = T + (item[2] if len(item) > 2 else i)
        table.update(packet, protocol, {"no service"}, now)
        if sweep_every and i % sweep_every == 0:
            table.sweep(now)
    return [table.row(c) for c in table.drain(everything=True)]


HANDSHAKE_AND_CLOSE = [
    out("S"),
    back("SA"),
    out("A"),
    out("PA", 200),
    back("PA", 1500),
    out("FA"),
    back("FA"),
    out("A"),
]


def test_tcp_handshake_and_close_is_one_sf_row_oriented_from_the_syn():
    [row] = run(HANDSHAKE_AND_CLOSE)
    assert (row["src"], row["sport"], row["dst"], row["dport"]) == (
        CLIENT,
        "50000",
        SERVER,
        "443",
    )
    assert row["initiated"] == 1 and row["state"] == "SF"
    assert (row["pkts_out"], row["pkts_in"]) == (5, 3)
    assert (row["bytes_out"], row["bytes_in"]) == (60 * 4 + 200, 60 * 2 + 1500)
    assert (row["src_home"], row["dst_home"]) == (1, 0)
    assert (row["start_msec"], row["end_msec"]) == (T, T + 7)


def test_unanswered_syns_are_one_s0_row_with_retries():
    [row] = run([out("S", sport=1), out("S", sport=1), out("S", sport=1)])
    assert row["state"] == "S0" and row["syn_retries"] == 2


def test_rst_to_the_syn_is_rej_and_resets_after_handshake_name_who_reset():
    [rej] = run([out("S"), back("RA")])
    assert rej["state"] == "REJ"
    [rsto] = run([out("S"), back("SA"), out("A"), out("RA")])
    assert rsto["state"] == "RSTO"
    [rstr] = run([out("S"), back("SA"), out("A"), back("R")])
    assert rstr["state"] == "RSTR"
    [s1] = run([out("S"), back("SA"), out("A"), out("PA", 100)])
    assert s1["state"] == "S1"


def test_no_syn_seen_is_oth_with_the_higher_port_as_originator():
    [row] = run([back("PA", 1500), out("A")])
    assert row["state"] == "OTH" and row["initiated"] == 0
    assert (row["src"], row["sport"]) == (CLIENT, "50000")
    assert (row["pkts_out"], row["pkts_in"]) == (1, 1)


def test_port_reuse_and_idle_split_connections():
    # a new SYN after the responder answered starts a new connection, even within the linger time
    rows = run(HANDSHAKE_AND_CLOSE + [out("S"), back("SA")])
    assert [r["state"] for r in rows] == ["SF", "S1"]
    # a packet after the linger time on a closed connection is a new (OTH) row
    late = [(p[0], p[1], i) for i, p in enumerate(HANDSHAKE_AND_CLOSE)] + [
        out("A") + (6000,)
    ]
    assert [r["state"] for r in run(late)] == ["SF", "OTH"]
    # an open connection idle for more than 300 s is split
    idle = [out("S") + (0,), back("SA") + (1,), out("PA") + (301_000,)]
    assert [r["state"] for r in run(idle)] == ["S1", "OTH"]


def test_sweeps_do_not_change_the_rows():
    packets = []
    for n in range(20):
        base = n * 40_000  # one short connection every 40 s, reusing the same ports
        for j, (protocol, packet) in enumerate(HANDSHAKE_AND_CLOSE):
            packets.append((protocol, packet, base + j))
    assert run(packets) == run(packets, sweep_every=3)
    assert len(run(packets)) == 20


def test_udp_orientation_and_idle():
    query = ("udp", udp(CLIENT, "10.0.0.53", 53000, 53))
    reply = ("udp", udp("10.0.0.53", CLIENT, 53, 53000))
    [row] = run([query, reply])
    assert (row["src"], row["dport"], row["initiated"], row["state"]) == (
        CLIENT,
        "53",
        1,
        "SF",
    )
    # the reply seen first: the client is still the originator, but not seen initiating
    [row] = run([reply])
    assert (row["src"], row["initiated"], row["pkts_in"], row["state"]) == (
        CLIENT,
        0,
        1,
        "SF",
    )
    # between two high ports the first sender is the originator
    [row] = run([("udp", udp(CLIENT, SERVER, 40000, 50000))])
    assert (row["src"], row["initiated"]) == (CLIENT, 0)
    # 60 s idle splits a UDP flow
    rows = run([query + (0,), query + (61_000,)])
    assert len(rows) == 2


def test_icmp_echo_shares_a_row_and_errors_are_separate():
    rows = run(
        [
            ("icmp", icmp(CLIENT, SERVER, "8")),
            ("icmp", icmp(SERVER, CLIENT, "0")),
            ("icmp", icmp(SERVER, CLIENT, "3", code="3")),
        ]
    )
    echo, unreach = rows
    assert (echo["src"], echo["sport"], echo["initiated"], echo["state"]) == (
        CLIENT,
        "8",
        1,
        "SF",
    )
    assert (echo["pkts_out"], echo["pkts_in"]) == (1, 1)
    assert (unreach["src"], unreach["sport"], unreach["dport"]) == (SERVER, "3", "3")
    assert unreach["initiated"] == 0


def test_scope_home_skips_connections_between_external_hosts():
    packets = [("tcp", tcp("198.51.100.1", SERVER, 50000, 80, "S"))]
    assert run(packets) == []
    assert len(run(packets, table=ConnectionTable(HOME, scope="all"))) == 1


def test_tls_facts_from_hello_server_hello_and_certificate():
    rows = run(
        [
            out("S"),
            back("SA"),
            out(
                "PA",
                **{
                    "tls.handshake_type": "1",
                    "tls.handshake_ja3": "abc",
                    "tls.handshake_extensions_server_name": "example.com",
                    "tls.handshake_version": "0x0303",
                },
            ),
            back(
                "PA",
                **{
                    "tls.handshake_type": ["2", "11", "14"],
                    "tls.handshake_version": "0x0303",
                    "tls.handshake_extensions_supported_version": "0x0304",
                    "tls.handshake_certificate_length": "851",
                    "x509if.oid": ["2.5.4.6", "2.5.4.3", "2.5.4.6", "2.5.4.3"],
                    "x509sat.uTF8String": ["evil", "evil"],
                    "x509af.utcTime_all": [
                        "2021-04-03 04:20:58 (UTC)",
                        "2031-04-01 04:20:58 (UTC)",
                    ],
                },
            ),
        ]
    )
    [row] = rows
    assert (row["tls_sni"], row["tls_ja3"], row["tls_version"]) == (
        "example.com",
        "abc",
        "TLS1.3",
    )
    assert row["cert_self_signed"] == 1
    assert row["cert_not_before"] == 1617423658
    assert row["cert_not_after"] == 1932783658


def test_self_signed_and_validity_rules():
    chain = {
        "tls.handshake_certificate_length": ["2190", "1374"],
        "x509if.oid": ["2.5.4.3", "2.5.4.3"],
        "x509af.utcTime_all": [
            ["2020-08-26 16:32:20 (UTC)", "2020-07-21 23:00:00 (UTC)"],
            ["2021-08-26 16:32:20 (UTC)", "2024-10-08 07:00:00 (UTC)"],
        ],
    }
    assert self_signed(chain) == 0  # more than one certificate
    # the leaf's dates are the first of each list
    assert certificate_validity(chain) == (
        x509_epoch("2020-08-26 16:32:20"),
        x509_epoch("2021-08-26 16:32:20"),
    )
    issued = {
        "tls.handshake_certificate_length": "900",
        "x509if.oid": ["2.5.4.3", "2.5.4.3"],
        "x509sat.printableString": ["Some CA", "www.example.com"],
    }
    assert self_signed(issued) == 0
    assert self_signed({"tls.handshake_certificate_length": "900"}) == 0
    # a leaf valid past 2049 has one utcTime and one generalizedTime
    assert certificate_validity(
        {
            "x509af.utcTime": "2021-01-01 00:00:00 (UTC)",
            "x509af.generalizedTime": "2051-01-01 00:00:00 (UTC)",
        }
    ) == (x509_epoch("2021-01-01 00:00:00"), x509_epoch("2051-01-01 00:00:00"))
    assert certificate_validity({}) == ("", "")
    assert x509_epoch("garbage") == ""


def test_http_facts_from_the_first_request_and_wire_strings_are_bounded():
    request = {
        "http.request.method": "GET",
        "http.host": "157.245.128.27",
        "http.user_agent": "x" * 2000,
        "http.request.uri": "/updates",
    }
    [row] = run(
        [
            out("S", sport=1),
            back("SA", sport=1),
            ("tcp", tcp(CLIENT, SERVER, 1, 443, "PA", **request)),
            (
                "tcp",
                tcp(
                    CLIENT,
                    SERVER,
                    1,
                    443,
                    "PA",
                    **{**request, "http.request.uri": "/other"},
                ),
            ),
        ]
    )
    assert row["http_requests"] == 2
    assert (row["http_host"], row["http_uri"]) == ("157.245.128.27", "/updates")
    assert len(row["http_user_agent"]) == 512


def test_service_names_are_collected_without_the_placeholder():
    table = ConnectionTable(HOME)
    table.update(out("S")[1], "tcp", {"no service"}, T)
    table.update(out("PA")[1], "tcp", {"tls"}, T + 1)
    table.update(out("PA")[1], "tcp", {"http", "tls"}, T + 2)
    [conn] = table.drain(everything=True)
    assert table.row(conn)["service"] == "http+tls"


def test_labels_name_either_address_and_overlap_in_time():
    table = ConnectionTable(HOME)
    table.update(out("S")[1], "tcp", set(), T)
    [conn] = table.drain(everything=True)
    labels = [
        {"name": "c2", "start_msec": T - 10, "end_msec": T + 10, "ips": {SERVER}},
        {"name": "any", "start_msec": T, "end_msec": T, "ips": set()},
        {"name": "other", "start_msec": T, "end_msec": T + 1, "ips": {"10.9.9.9"}},
        {"name": "later", "start_msec": T + 5, "end_msec": T + 9, "ips": set()},
    ]
    assert connection_labels(labels, conn) == "c2+any"


def test_capture_keeps_both_certificate_times():
    line = (
        '{"layers":{"x509af":{"x509af_x509af_utcTime":"2021-04-03 04:20:58 (UTC)",'
        '"x509af_x509af_utcTime":"2031-04-01 04:20:58 (UTC)"}}}'
    )
    layers = json.loads(line, object_pairs_hook=keep_duplicate_times)["layers"]
    packet = PacketCapture("test", "tshark", None, None, 1, None).unwrap(layers.items())
    assert packet["x509af.utcTime_all"] == [
        "2021-04-03 04:20:58 (UTC)",
        "2031-04-01 04:20:58 (UTC)",
    ]
    # the plain key keeps json's last-wins value, as before
    assert packet["x509af.utcTime"] == "2031-04-01 04:20:58 (UTC)"
