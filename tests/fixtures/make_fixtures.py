"""Regenerate the fixture captures used by tests/pipeline_test.py.

Needs scapy, which is not a runtime dependency: `pip install scapy`, then run
`python3 tests/fixtures/make_fixtures.py` from the repo root. The committed .pcap
files are what the tests use; rerun this only to change them.

icmp_mix.pcap (8 frames, all at the same second):
  2 ICMP echo request/reply, 1 ICMP port unreachable quoting a UDP header cut to
  its ports, 1 ICMP port unreachable quoting a TCP header cut to its ports,
  1 ICMPv6 echo request, 1 ICMPv6 neighbor solicitation, 1 IGMPv2 report,
  1 TCP SYN.  The truncated quoted headers are what crashed counts.py on real
  router captures (CTU-13), and the ICMPv6 frames used to be counted as IGMP.

fragments.pcap (5 frames):
  one 3000-byte UDP datagram over IPv4 in 3 fragments, and one 2000-byte UDP
  datagram over IPv6 in 2 fragments.  tshark reassembles each datagram onto its
  final fragment; the 3 earlier fragments have no UDP header of their own and
  used to be dropped.
"""

import os

from scapy.all import (
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoRequest,
    ICMPv6ND_NS,
    IPv6,
    IPv6ExtHdrFragment,
    Raw,
    fragment,
    fragment6,
    wrpcap,
)
from scapy.contrib.igmp import IGMP

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1600000000.0
A, B, C = "10.0.0.1", "10.0.0.2", "10.0.0.3"
A6, B6 = "2001:db8::1", "2001:db8::2"


def eth():
    # explicit MACs: a bare Ether() over IPv6 makes scapy try live neighbor discovery
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def stamp(packets):
    for i, p in enumerate(packets):
        p.time = T0 + i * 0.01
    return packets


def quoted(inner_ip, l4_bytes):
    """Original IP header plus the first 4 bytes of its transport header (the ports)."""
    raw = bytes(inner_ip)
    header_len = (raw[0] & 0x0F) * 4
    return raw[:header_len] + l4_bytes[:4]


udp_probe = IP(src=B, dst=C) / UDP(sport=40000, dport=161)
tcp_probe = IP(src=B, dst=C) / TCP(sport=40001, dport=23)

icmp_mix = stamp(
    [
        eth() / IP(src=A, dst=B) / ICMP(type=8, id=1, seq=1),
        eth() / IP(src=B, dst=A) / ICMP(type=0, id=1, seq=1),
        eth()
        / IP(src=C, dst=B)
        / ICMP(type=3, code=3)
        / Raw(quoted(udp_probe, bytes(udp_probe[UDP]))),
        eth()
        / IP(src=C, dst=B)
        / ICMP(type=3, code=3)
        / Raw(quoted(tcp_probe, bytes(tcp_probe[TCP]))),
        eth() / IPv6(src=A6, dst=B6) / ICMPv6EchoRequest(),
        eth() / IPv6(src=A6, dst="ff02::1:ff00:2") / ICMPv6ND_NS(tgt=B6),
        eth()
        / IP(src=A, dst="224.0.0.251", ttl=1)
        / IGMP(type=0x16, gaddr="224.0.0.251"),
        eth() / IP(src=A, dst=B) / TCP(sport=40002, dport=80, flags="S"),
    ]
)

v4 = fragment(
    IP(src=A, dst=B, id=7) / UDP(sport=5000, dport=6000) / Raw(b"x" * 3000),
    fragsize=1200,
)
v6 = fragment6(
    IPv6(src=A6, dst=B6)
    / IPv6ExtHdrFragment(id=9)
    / UDP(sport=5001, dport=6001)
    / Raw(b"y" * 2000),
    1280,
)
frags = stamp([eth() / p for p in v4] + [eth() / p for p in v6])
assert len(v4) == 3 and len(v6) == 2, (len(v4), len(v6))

wrpcap(os.path.join(HERE, "icmp_mix.pcap"), icmp_mix)
wrpcap(os.path.join(HERE, "fragments.pcap"), frags)
print("wrote icmp_mix.pcap (%d) and fragments.pcap (%d)" % (len(icmp_mix), len(frags)))
