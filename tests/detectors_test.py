# unit tests for detectors.py protocol classification
# Packets are dicts with the dotted field names capture.unwrap produces.

import pytest

import transitkeys
from detectors import PacketAnalyse, normalize_addressing
from dvar import datasetSummary
from loggingconfig import load_logging

load_logging()


class ListQueue:
    """Stand-in for multiprocessing.Queue: records what a stage puts."""

    def __init__(self, items=()):
        self.items = list(items)

    def put(self, item):
        self.items.append(item)

    def get(self):
        return self.items.pop(0)

    def empty(self):
        return not self.items


def classify(packet):
    out = ListQueue()
    analyse = PacketAnalyse("test", ListQueue(), out)
    dvar = datasetSummary()
    normalize_addressing(packet)
    if not analyse.find_ip(packet, dvar):
        analyse.find_non_ip(packet, dvar)
    protocol = out.items[0][transitkeys.key_protocol] if out.items else None
    return protocol, dvar


def ipv4(proto, src="10.0.0.1", dst="10.0.0.2", **fields):
    return {
        "ip.proto": proto,
        "ip.src": src,
        "ip.dst": dst,
        "frame.len": "60",
        **fields,
    }


def test_icmp_echo_is_icmp():
    protocol, dvar = classify(ipv4("1", **{"icmp.type": "8"}))
    assert protocol == "icmp"
    assert dvar.icmp_count == 1
    assert dvar.not_analyzed_ip_count == 0


def test_icmp_error_quoting_truncated_udp_is_icmp_not_udp():
    # outer ip.proto wins in capture.unwrap; the quoted UDP header has ports but no length
    packet = ipv4(
        "1",
        src="10.0.0.3",
        dst="10.0.0.2",
        **{"icmp.type": "3", "udp.srcport": "40000", "udp.dstport": "161"}
    )
    protocol, dvar = classify(packet)
    assert protocol == "icmp"
    assert dvar.udp_count == 0


def test_icmp_error_quoting_truncated_tcp_is_icmp_not_tcp():
    packet = ipv4(
        "1",
        **{
            "icmp.type": "3",
            "tcp.srcport": "40001",
            "tcp.dstport": "23",
            "tcp.flags.syn": False,
        }
    )
    protocol, dvar = classify(packet)
    assert protocol == "icmp"
    assert dvar.tcp_count == 0


def test_icmpv6_is_icmp_not_igmp():
    packet = {
        "ipv6.src": "2001:db8::1",
        "ipv6.dst": "ff02::1:ff00:2",
        "ipv6.nxt": "58",
        "icmpv6.type": "135",
    }
    protocol, dvar = classify(packet)
    assert protocol == "icmp"
    assert dvar.igmp_count == 0


def test_igmp_is_still_igmp():
    protocol, dvar = classify(ipv4("2", dst="224.0.0.251", **{"igmp.type": "0x16"}))
    assert protocol == "igmp"
    assert dvar.igmp_count == 1


def test_unknown_ipv6_next_header_is_unanalyzed_ip_not_igmp():
    packet = {"ipv6.src": "fe80::1", "ipv6.dst": "ff02::5", "ipv6.nxt": "89"}
    protocol, dvar = classify(packet)
    assert protocol is None
    assert dvar.igmp_count == 0
    assert dvar.not_analyzed_ip_count == 1
    assert dvar.not_analyzed_ip == {"89"}


@pytest.mark.parametrize(
    "fields",
    [
        {"ip.flags.mf": True, "ip.frag_offset": "0"},  # first fragment
        {"ip.flags.mf": True, "ip.frag_offset": "1200"},  # middle fragment
        {
            "ip.flags.mf": False,
            "ip.frag_offset": "2400",
        },  # last fragment, not reassembled
    ],
)
def test_ipv4_fragment_without_transport_header_is_ipfrag(fields):
    protocol, dvar = classify(ipv4("17", **fields))
    assert protocol == "ipfrag"
    assert dvar.ip_fragment_count == 1
    assert dvar.not_analyzed_ip_count == 0


def test_reassembled_final_fragment_is_counted_as_udp():
    packet = ipv4(
        "17",
        **{
            "ip.flags.mf": False,
            "ip.frag_offset": "2400",
            "udp.srcport": "5000",
            "udp.dstport": "6000",
            "udp.length": "3008",
        }
    )
    protocol, _ = classify(packet)
    assert protocol == "udp"


def test_ipv6_fragment_without_transport_header_is_ipfrag():
    packet = {
        "ipv6.src": "2001:db8::1",
        "ipv6.dst": "2001:db8::2",
        "ipv6.nxt": "44",
        "ipv6_fraghdr.offset": "0",
    }
    protocol, dvar = classify(packet)
    assert protocol == "ipfrag"
    assert dvar.ip_fragment_count == 1


def test_list_valued_addressing_fields_use_first_value():
    packet = ipv4(
        ["6", "6"],
        src=["10.0.0.1", "10.9.9.9"],
        dst=["10.0.0.2", "10.9.9.8"],
        **{"tcp.srcport": "1", "tcp.flags.syn": True}
    )
    protocol, _ = classify(packet)
    assert protocol == "tcp"
    assert packet["ip.src"] == "10.0.0.1"
