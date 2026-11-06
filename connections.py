# One row per connection, written to the connection log (main.py -oc connections.csv).
# Used only by counts.py (the TimesAndCounts process), like hoststats.py: every packet that reaches
# the window counts also updates this table, and a row is written when its connection ends.
#
# Keying and orientation (the originator is the side that started the connection):
#   TCP   5-tuple. A SYN without ACK starts a connection and its sender is the originator
#         (initiated = 1). A packet with no SYN seen starts a row with initiated = 0 and the
#         higher port as the originator (capture started mid-connection, or the SYN was lost).
#   UDP   5-tuple. The client by the hosts.csv rule (destination port below 1024 and not above
#         the source port) is the originator; initiated = 1 when the first packet seen came from
#         it. Between two high ports, the first sender is the originator with initiated = 0.
#   ICMP  echo request and its replies share a row (initiated = 1 when the request was seen);
#         every other type (errors, neighbor discovery) is a row per (src, dst, type, code).
#         As in Zeek's conn.log, sport holds the ICMP type and dport the code.
# ARP, IGMP and IP fragments are not connections and appear only in windows.csv.
#
# A connection ends when, at its next packet or at a sweep:
#   TCP   both FINs or a RST were seen and linger_sec passed without packets, or idle_sec passed
#   UDP / ICMP  idle_udp_sec passed without packets
# A SYN from the originator after the responder has answered starts a new connection (port
# reuse); before that it is a retry. Rows still open at end of input are written then.
#
# state uses Zeek's conn_state names so anyone who knows conn.log can read it:
#   S0 no answer, REJ answered with RST, SF handshake and both FINs, S1 established and not
#   closed (Zeek's S2/S3 half-closes included), RSTO/RSTR reset by originator/responder after
#   the handshake, OTH no SYN seen. UDP and ICMP: SF when the responder sent anything, else S0.

import calendar
import re
import time

from hoststats import TRUE_VALUES, _first, addresses

CONN_FIELDNAMES = [
    "start_msec",
    "end_msec",
    "src",
    "sport",
    "dst",
    "dport",
    "proto",
    "initiated",
    "src_home",
    "dst_home",
    "service",
    "pkts_out",
    "pkts_in",
    "bytes_out",
    "bytes_in",
    "state",
    "syn_retries",
    "tls_sni",
    "tls_ja3",
    "tls_version",
    "cert_self_signed",
    "cert_not_before",
    "cert_not_after",
    "http_requests",
    "http_host",
    "http_user_agent",
    "http_uri",
    "label",
]

ICMP_ECHO = {"8": "0", "128": "129"}  # request -> reply, IPv4 and IPv6
ICMP_ECHO_REPLY = {reply: request for request, reply in ICMP_ECHO.items()}
TLS_VERSIONS = {
    "0x0300": "SSL3",
    "0x0301": "TLS1.0",
    "0x0302": "TLS1.1",
    "0x0303": "TLS1.2",
    "0x0304": "TLS1.3",
}
# strings from the wire (SNI, Host, user agent, URI) are attacker-controlled; bound their size
MAX_WIRE_STRING = 512


def wire_string(value):
    value = _first(value)
    if value is None:
        return ""
    return str(value)[:MAX_WIRE_STRING]


def has_value(value, wanted):
    return wanted in value if isinstance(value, list) else value == wanted


def x509_epoch(text):
    """'2021-04-03 04:20:58 (UTC)' (tshark's utcTime/generalizedTime) -> epoch seconds, or ''."""
    found = re.match(r"(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)", str(text or ""))
    if not found:
        return ""
    return calendar.timegm(
        time.struct_time(tuple(map(int, found.groups())) + (0, 0, 0))
    )


def certificate_validity(packet_dict):
    """(not_before, not_after) of the first certificate in the chain, epoch seconds or ''.

    tshark emits utcTime twice at one level (not before, then not after); capture.py keeps both
    under x509af.utcTime_all. In a chain each occurrence is a list with the leaf first.
    """
    both = packet_dict.get("x509af.utcTime_all")
    if isinstance(both, list) and len(both) == 2:
        return x509_epoch(_first(both[0])), x509_epoch(_first(both[1]))
    # a leaf valid past 2049 has one utcTime (not before) and one generalizedTime (not after)
    utc = packet_dict.get("x509af.utcTime")
    general = packet_dict.get("x509af.generalizedTime")
    if utc is not None and general is not None:
        return x509_epoch(_first(utc)), x509_epoch(_first(general))
    return "", ""


def self_signed(packet_dict):
    """1 when the chain is one certificate whose issuer and subject names are equal, else 0.

    tshark gives the issuer's and then the subject's name attributes as flat lists (x509if.oid
    and one list per string type), so equal names show up as every list being two equal halves.
    Chains of more than one certificate count as not self-signed.
    """
    if isinstance(packet_dict.get("tls.handshake_certificate_length"), list):
        return 0
    lists = [packet_dict.get("x509if.oid")] + [
        value
        for key, value in packet_dict.items()
        if key.startswith("x509sat.") and isinstance(value, list)
    ]
    if not isinstance(lists[0], list):
        return 0
    for values in lists:
        half = len(values) // 2
        if len(values) % 2 or values[:half] != values[half:]:
            return 0
    return 1


class Connection:
    __slots__ = (
        "proto",
        "src",
        "sport",
        "dst",
        "dport",
        "initiated",
        "start",
        "last",
        "pkts_out",
        "pkts_in",
        "bytes_out",
        "bytes_in",
        "services",
        "syn",
        "synack",
        "fin_out",
        "fin_in",
        "rst_by",
        "syn_retries",
        "tls_sni",
        "tls_ja3",
        "tls_version",
        "cert_self_signed",
        "cert_not_before",
        "cert_not_after",
        "http_requests",
        "http_host",
        "http_user_agent",
        "http_uri",
    )

    def __init__(self, proto, src, sport, dst, dport, initiated, now):
        self.proto, self.src, self.sport, self.dst, self.dport = (
            proto,
            src,
            sport,
            dst,
            dport,
        )
        self.initiated = initiated
        self.start = self.last = now
        self.pkts_out = self.pkts_in = self.bytes_out = self.bytes_in = 0
        self.services = set()
        self.syn = self.synack = self.fin_out = self.fin_in = False
        self.rst_by = ""
        self.syn_retries = 0
        self.tls_sni = self.tls_ja3 = self.tls_version = ""
        self.cert_self_signed = self.cert_not_before = self.cert_not_after = ""
        self.http_requests = 0
        self.http_host = self.http_user_agent = self.http_uri = ""

    def closed(self):
        return bool(self.rst_by) or (self.fin_out and self.fin_in)

    def state(self):
        if self.proto != "tcp":
            return "SF" if self.pkts_in else "S0"
        if not self.syn:
            return "OTH"
        if not self.synack:
            return "REJ" if self.rst_by == "in" else "S0"
        if self.rst_by:
            return "RSTO" if self.rst_by == "out" else "RSTR"
        return "SF" if self.fin_out and self.fin_in else "S1"


class ConnectionTable:
    def __init__(
        self,
        home_net,
        scope="home",
        linger_sec=5,
        idle_sec=300,
        idle_udp_sec=60,
    ):
        self.home_net = home_net
        self.scope = scope
        self.linger_msec = linger_sec * 1000
        self.idle_msec = idle_sec * 1000
        self.idle_udp_msec = idle_udp_sec * 1000
        self.active = {}
        self.finished = []

    def in_scope(self, src, dst):
        return self.scope == "all" or (
            self.home_net.contains(src) or self.home_net.contains(dst)
        )

    def ended(self, conn, now):
        idle = now - conn.last
        if conn.proto != "tcp":
            return idle > self.idle_udp_msec
        return idle > self.idle_msec or (conn.closed() and idle > self.linger_msec)

    def finish(self, key):
        self.finished.append(self.active.pop(key))

    def update(self, packet_dict, protocol, services, now):
        """Add one packet (frame time now, msec) to its connection."""
        if protocol not in ("tcp", "udp", "icmp"):
            return
        src, dst = addresses(packet_dict, protocol)
        if not src or not dst:
            return
        src, dst = str(_first(src)), str(_first(dst))

        syn = synack = False
        sport = None
        if protocol == "icmp":
            key, start = self.icmp_key(packet_dict, src, dst)
        else:
            sport = _first(packet_dict.get(protocol + ".srcport"))
            dport = _first(packet_dict.get(protocol + ".dstport"))
            if sport is None or dport is None:
                return
            sport, dport = str(sport), str(dport)
            key = (protocol,) + tuple(sorted(((src, sport), (dst, dport))))
            if protocol == "tcp":
                flag_syn = packet_dict.get("tcp.flags.syn") in TRUE_VALUES
                flag_ack = packet_dict.get("tcp.flags.ack") in TRUE_VALUES
                syn, synack = flag_syn and not flag_ack, flag_syn and flag_ack
                start = self.tcp_start(src, sport, dst, dport, syn)
            else:
                start = self.udp_start(src, sport, dst, dport)

        conn = self.active.get(key)
        if conn is not None:
            outbound = is_outbound(conn, src, sport)
            if self.ended(conn, now) or (
                syn and (not outbound or conn.synack or conn.pkts_in)
            ):
                # idle or closed too long, or a fresh SYN after the responder answered
                self.finish(key)
                conn = None
            elif syn:
                conn.syn_retries += 1
        if conn is None:
            if not self.in_scope(src, dst):
                return
            conn = self.active[key] = Connection(protocol, *start, now)

        outbound = is_outbound(conn, src, sport)
        frame_len = int(packet_dict.get("frame.len", 0))
        conn.last = now
        if outbound:
            conn.pkts_out += 1
            conn.bytes_out += frame_len
        else:
            conn.pkts_in += 1
            conn.bytes_in += frame_len
        conn.services.update(s for s in services if s != "no service")

        if protocol == "tcp":
            if syn and outbound:
                conn.syn = True
            if synack and not outbound:
                conn.synack = True
            if packet_dict.get("tcp.flags.fin") in TRUE_VALUES:
                if outbound:
                    conn.fin_out = True
                else:
                    conn.fin_in = True
            if packet_dict.get("tcp.flags.reset") in TRUE_VALUES and not conn.rst_by:
                conn.rst_by = "out" if outbound else "in"
            self.tls_facts(conn, packet_dict)
        if protocol in ("tcp", "udp"):
            self.http_facts(conn, packet_dict)

    def tcp_start(self, src, sport, dst, dport, syn):
        if syn:
            return src, sport, dst, dport, 1
        # no SYN seen: the higher port is the client
        if int(dport) > int(sport):
            return dst, dport, src, sport, 0
        return src, sport, dst, dport, 0

    def udp_start(self, src, sport, dst, dport):
        if int(dport) < 1024 and int(dport) <= int(sport):
            return src, sport, dst, dport, 1
        if int(sport) < 1024 and int(sport) <= int(dport):
            # a reply seen before its request: the receiver is the client
            return dst, dport, src, sport, 0
        return src, sport, dst, dport, 0

    def icmp_key(self, packet_dict, src, dst):
        icmp_type = str(
            _first(packet_dict.get("icmp.type", packet_dict.get("icmpv6.type", "")))
        )
        code = str(
            _first(packet_dict.get("icmp.code", packet_dict.get("icmpv6.code", "")))
        )
        if icmp_type in ICMP_ECHO:
            return ("icmp-echo", src, dst), (src, icmp_type, dst, code, 1)
        if icmp_type in ICMP_ECHO_REPLY:
            # the reply joins its request's row, keyed from the requester's side
            request = ICMP_ECHO_REPLY[icmp_type]
            return ("icmp-echo", dst, src), (dst, request, src, code, 0)
        return ("icmp", src, dst, icmp_type, code), (src, icmp_type, dst, code, 0)

    def tls_facts(self, conn, packet_dict):
        handshake = packet_dict.get("tls.handshake_type")
        if handshake is None:
            return
        if has_value(handshake, "1") and not conn.tls_ja3:
            conn.tls_ja3 = wire_string(packet_dict.get("tls.handshake_ja3"))
            conn.tls_sni = wire_string(
                packet_dict.get("tls.handshake_extensions_server_name")
            )
        if has_value(handshake, "2") and not conn.tls_version:
            version = _first(
                packet_dict.get(
                    "tls.handshake_extensions_supported_version",
                    packet_dict.get("tls.handshake_version"),
                )
            )
            conn.tls_version = TLS_VERSIONS.get(str(version), str(version or ""))
        if has_value(handshake, "11") and conn.cert_self_signed == "":
            conn.cert_self_signed = self_signed(packet_dict)
            conn.cert_not_before, conn.cert_not_after = certificate_validity(
                packet_dict
            )

    def http_facts(self, conn, packet_dict):
        if "http.request.method" not in packet_dict:
            return
        conn.http_requests += 1
        if conn.http_requests == 1:
            conn.http_host = wire_string(packet_dict.get("http.host"))
            conn.http_user_agent = wire_string(packet_dict.get("http.user_agent"))
            conn.http_uri = wire_string(packet_dict.get("http.request.uri"))

    def sweep(self, now):
        """Move connections that have ended by time now (msec) to the finished list."""
        for key in [k for k, c in self.active.items() if self.ended(c, now)]:
            self.finish(key)

    def drain(self, everything=False):
        """Finished connections, oldest first; with everything, also the ones still open."""
        if everything:
            self.finished.extend(self.active.values())
            self.active = {}
        rows, self.finished = self.finished, []
        return sorted(rows, key=lambda c: c.start)

    def row(self, conn, labels=()):
        return {
            "start_msec": conn.start,
            "end_msec": conn.last,
            "src": conn.src,
            "sport": conn.sport,
            "dst": conn.dst,
            "dport": conn.dport,
            "proto": conn.proto,
            "initiated": conn.initiated,
            "src_home": int(self.home_net.contains(conn.src)),
            "dst_home": int(self.home_net.contains(conn.dst)),
            "service": "+".join(sorted(conn.services)),
            "pkts_out": conn.pkts_out,
            "pkts_in": conn.pkts_in,
            "bytes_out": conn.bytes_out,
            "bytes_in": conn.bytes_in,
            "state": conn.state(),
            "syn_retries": conn.syn_retries,
            "tls_sni": conn.tls_sni,
            "tls_ja3": conn.tls_ja3,
            "tls_version": conn.tls_version,
            "cert_self_signed": conn.cert_self_signed,
            "cert_not_before": conn.cert_not_before,
            "cert_not_after": conn.cert_not_after,
            "http_requests": conn.http_requests,
            "http_host": conn.http_host,
            "http_user_agent": conn.http_user_agent,
            "http_uri": conn.http_uri,
            "label": connection_labels(labels, conn),
        }


def is_outbound(conn, src, sport):
    """True when the packet came from the originator (ICMP rows are keyed by address only)."""
    if conn.proto == "icmp":
        return src == conn.src
    return (src, sport) == (conn.src, conn.sport)


def connection_labels(labels, conn):
    """Names of labeled intervals overlapping the connection that name either address (or none)."""
    names = []
    for label in labels:
        if label["start_msec"] <= conn.last and label["end_msec"] >= conn.start:
            if not label["ips"] or conn.src in label["ips"] or conn.dst in label["ips"]:
                names.append(label["name"])
    return "+".join(dict.fromkeys(names))
