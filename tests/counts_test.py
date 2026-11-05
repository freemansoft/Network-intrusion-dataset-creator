# unit tests for counts.py window accumulation and stage failure handling

import pytest

import transitkeys
from counts import TimesAndCounts
from cvar import windowcounts
from services import ServiceIdentity
from loggingconfig import load_logging

load_logging()


class ListQueue:
    def __init__(self, items=()):
        self.items = list(items)

    def put(self, item):
        self.items.append(item)

    def get(self):
        return self.items.pop(0)

    def empty(self):
        return not self.items


def accumulate(protocol, packet, services=frozenset({"no service"})):
    counter = TimesAndCounts("test", 5000, None, "unused.csv", None)
    window = windowcounts(window_start_time=0, window_index=1)
    base = {"frame.time_epoch": "1600000000.0", "frame.len": "100"}
    counter.analyze_update_window(
        ID="10.0.0.1-10.0.0.2",
        packet_dict={**base, **packet},
        Prot1=protocol,
        services=set(services),
        target_window=window,
    )
    return window


def test_tcp_without_tcp_len_does_not_crash():
    window = accumulate("tcp", {"ip.len": "40", "tcp.srcport": "1", "tcp.dstport": "2"})
    assert window.num_tcp == 1
    assert window.tcp_length == 0
    assert window.tcp_frame_length == 100


def test_udp_without_udp_length_or_ports_does_not_crash():
    window = accumulate("udp", {"ip.len": "28"})
    assert window.num_udp == 1
    assert window.udp_length == 0
    assert window.ports == set()


def test_icmp_echo_and_unreachable_counts():
    echo = accumulate("icmp", {"icmp.type": "8"})
    assert (echo.num_icmp, echo.num_icmp_echo, echo.num_icmp_unreach) == (1, 1, 0)
    assert echo.icmp_frame_length == 100
    unreach = accumulate("icmp", {"icmp.type": "3"})
    assert (unreach.num_icmp, unreach.num_icmp_echo, unreach.num_icmp_unreach) == (
        1,
        0,
        1,
    )
    v6_unreach = accumulate("icmp", {"icmpv6.type": "1"})
    assert v6_unreach.num_icmp_unreach == 1
    v6_echo_reply = accumulate("icmp", {"icmpv6.type": "129"})
    assert v6_echo_reply.num_icmp_echo == 1


def test_ip_fragment_counts():
    window = accumulate("ipfrag", {})
    assert window.num_ip_fragments == 1
    assert window.ip_fragment_frame_length == 100
    assert window.num_packets == 1


def test_new_columns_are_in_csv_fieldnames_after_window_times():
    names = TimesAndCounts.fieldnames
    assert names.index("window_end_time") < names.index("num_icmp")
    for column in (
        "icmp_frame_length",
        "num_icmp",
        "num_icmp_echo",
        "num_icmp_unreach",
        "ip_fragment_frame_length",
        "num_ip_fragments",
    ):
        assert column in names
        assert hasattr(windowcounts(), column)


def test_failing_stage_still_forwards_end_of_stream_sentinel():
    # a message missing its id makes ServiceIdentity raise; the stage after it must still be told to stop
    out = ListQueue()
    stage = ServiceIdentity("test", ListQueue([{transitkeys.key_packet: {}}]), out)
    with pytest.raises(KeyError):
        stage.run()
    assert out.items == [{}]
