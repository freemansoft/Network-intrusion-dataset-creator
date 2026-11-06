# unit tests for capture.py EK flattening

from capture import PacketCapture
from loggingconfig import load_logging

load_logging()


def unwrap(layers):
    return PacketCapture("test", "tshark", None, None, 1, None).unwrap(layers.items())


def test_outer_ip_header_wins_over_header_quoted_inside_icmp():
    # shape of `tshark -T ek` for an ICMP port unreachable quoting a truncated UDP header
    layers = {
        "ip": {
            "ip_ip_proto": "1",
            "ip_ip_src": "147.32.84.59",
            "ip_ip_dst": "210.49.64.185",
        },
        "icmp": {
            "icmp_icmp_type": "3",
            "ip": {
                "ip_ip_proto": "17",
                "ip_ip_src": "210.49.64.185",
                "ip_ip_dst": "147.32.84.59",
            },
            "udp": {"udp_udp_srcport": "29365"},
        },
    }
    packet = unwrap(layers)
    assert packet["ip.proto"] == "1"
    assert packet["ip.src"] == "147.32.84.59"
    assert packet["ip.dst"] == "210.49.64.185"
    assert packet["icmp.type"] == "3"
    # fields that only exist in the quoted header are still kept
    assert packet["udp.srcport"] == "29365"


def test_key_renaming_for_fields_detectors_use():
    layers = {
        "ip": {"ip_ip_flags_mf": True, "ip_ip_frag_offset": "0"},
        "ipv6": {
            "ipv6_ipv6_nxt": "44",
            "ipv6_fraghdr": {"ipv6_fraghdr_ipv6_fraghdr_offset": "0"},
        },
        "icmpv6": {"icmpv6_icmpv6_type": "135"},
        "tcp": {"tcp_tcp_flags_syn": True},
    }
    packet = unwrap(layers)
    for key in (
        "ip.flags.mf",
        "ip.frag_offset",
        "ipv6.nxt",
        "ipv6_fraghdr.offset",
        "icmpv6.type",
        "tcp.flags.syn",
    ):
        assert key in packet, key
