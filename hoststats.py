# Per-host statistics for one tumbling window, plus the window-level fan-out and entropy columns
# derived from them. Used only by counts.py (the TimesAndCounts process), so the state lives in that
# process and nothing here crosses a queue.
#
# "Contacted" means contact this host initiated, so that servers answering many clients and the
# victim of a scan (replying with RSTs to the scanner's ephemeral ports) do not look like scanners:
#   TCP: a SYN without ACK               -> contacted dst ip and dst port
#   UDP: dst port < 1024 and <= src port -> contacted dst ip and dst port (client -> well-known
#        service; traffic between two high ports is too often replies or P2P to call initiated)
#   ICMP/ICMPv6 echo request, ARP        -> contacted dst ip

import ipaddress
import math
from collections import Counter

DEFAULT_HOME_NET = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
# remote-login ports; SYNs to these feed the brute-force rule
AUTH_PORTS = {"21", "22", "23", "3389", "5900"}
TRUE_VALUES = (True, "1", "true", "True")
ICMP_ECHO_REQUEST = {"8", "128"}
ICMP_UNREACH = {("icmp", "3"), ("icmpv6", "1")}
FTP_DATA = "ftpdata"

HOST_FIELDNAMES = [
    "window_start_time",
    "window_end_time",
    "host",
    "is_home",
    "pkts_out",
    "pkts_in",
    "bytes_out",
    "bytes_in",
    "upload_bytes_ext",
    "download_bytes_ext",
    "contacted_ips",
    "contacted_ports",
    "contacting_ips",
    "new_contacted_ips",
    "new_contacted_ports",
    "syn_out",
    "synack_in",
    "rst_in",
    "syn_in",
    "auth_syn_out",
    "auth_syn_in",
    "icmp_unreach_in",
    "label",
]


class HomeNet:
    """Membership test for the --home-net CIDRs, cached per address."""

    def __init__(self, cidrs=DEFAULT_HOME_NET):
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self.cache = {}

    def contains(self, ip):
        if ip not in self.cache:
            try:
                address = ipaddress.ip_address(ip)
                self.cache[ip] = any(
                    address.version == n.version and address in n for n in self.networks
                )
            except ValueError:
                self.cache[ip] = False
        return self.cache[ip]


class Novelty:
    """Remembers, across windows, when each host last contacted each ip and port.

    A contact is "new" if this host has not made it within the horizon. Entries older than the
    horizon are pruned at each window flush so memory stays bounded.
    """

    def __init__(self, horizon_msec=600 * 1000):
        self.horizon_msec = horizon_msec
        self.last_seen = {}

    def is_new(self, key, now_msec):
        previous = self.last_seen.get(key)
        self.last_seen[key] = now_msec
        return previous is None or now_msec - previous > self.horizon_msec

    def prune(self, now_msec):
        cutoff = now_msec - self.horizon_msec
        self.last_seen = {k: t for k, t in self.last_seen.items() if t >= cutoff}


class HostStats:
    __slots__ = (
        "pkts_out",
        "pkts_in",
        "bytes_out",
        "bytes_in",
        "upload_bytes_ext",
        "download_bytes_ext",
        "contacted_ip_set",
        "contacted_port_set",
        "contacting_ip_set",
        "new_ip_set",
        "new_port_set",
        "syn_out",
        "synack_in",
        "rst_in",
        "syn_in",
        "auth_syn_out",
        "auth_syn_in",
        "icmp_unreach_in",
    )

    def __init__(self):
        for name in self.__slots__:
            setattr(self, name, set() if name.endswith("_set") else 0)


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def addresses(packet_dict, protocol):
    if protocol == "arp":
        return packet_dict.get("arp.src.proto_ipv4"), packet_dict.get(
            "arp.dst.proto_ipv4"
        )
    if "ip.src" in packet_dict:
        return packet_dict.get("ip.src"), packet_dict.get("ip.dst")
    return packet_dict.get("ipv6.src"), packet_dict.get("ipv6.dst")


def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    # abs(): a single-valued distribution would otherwise print as -0.0
    return abs(-sum((n / total) * math.log2(n / total) for n in counter.values()))


class WindowHosts:
    """Accumulates per-host statistics for one window."""

    def __init__(self):
        self.hosts = {}
        self.src_counts = Counter()
        self.dst_counts = Counter()
        self.dst_port_counts = Counter()

    def host(self, ip):
        stats = self.hosts.get(ip)
        if stats is None:
            stats = self.hosts[ip] = HostStats()
        return stats

    def update(self, packet_dict, protocol, frame_time_msec, home_net, novelty):
        src, dst = addresses(packet_dict, protocol)
        if not src or not dst:
            return
        src, dst = str(_first(src)), str(_first(dst))
        frame_len = int(packet_dict.get("frame.len", 0))
        src_home, dst_home = home_net.contains(src), home_net.contains(dst)

        sport = dport = None
        syn = synack = rst = False
        if protocol == "tcp":
            sport = _first(packet_dict.get("tcp.srcport"))
            dport = _first(packet_dict.get("tcp.dstport"))
            flag_syn = packet_dict.get("tcp.flags.syn") in TRUE_VALUES
            flag_ack = packet_dict.get("tcp.flags.ack") in TRUE_VALUES
            syn, synack = flag_syn and not flag_ack, flag_syn and flag_ack
            rst = packet_dict.get("tcp.flags.reset") in TRUE_VALUES
        elif protocol == "udp":
            sport = _first(packet_dict.get("udp.srcport"))
            dport = _first(packet_dict.get("udp.dstport"))

        self.src_counts[src] += 1
        self.dst_counts[dst] += 1
        if dport is not None:
            self.dst_port_counts[dport] += 1

        sender, receiver = self.host(src), self.host(dst)
        sender.pkts_out += 1
        sender.bytes_out += frame_len
        receiver.pkts_in += 1
        receiver.bytes_in += frame_len

        # client-role transfer with an external peer: the client's port is the higher one
        client_side = (
            sport is not None and dport is not None and int(sport) > int(dport)
        )
        server_side = (
            sport is not None and dport is not None and int(sport) < int(dport)
        )
        if client_side and not dst_home:
            sender.upload_bytes_ext += frame_len
        if server_side and not src_home:
            receiver.download_bytes_ext += frame_len

        initiated_port = None
        initiated = False
        if protocol == "tcp" and syn:
            # active-mode FTP data: the server connects from port 20 to a port the client chose,
            # so every transfer would otherwise be a new "contacted port"
            initiated = True
            initiated_port = FTP_DATA if str(sport) == "20" else dport
        elif (
            protocol == "udp"
            and dport is not None
            and sport is not None
            and int(dport) <= int(sport)
            and int(dport) < 1024
        ):
            initiated, initiated_port = True, dport
        elif protocol == "icmp" and (
            str(packet_dict.get("icmp.type")) in ICMP_ECHO_REQUEST
            or str(packet_dict.get("icmpv6.type")) in ICMP_ECHO_REQUEST
        ):
            initiated = True
        elif protocol == "arp" and str(packet_dict.get("arp.opcode")) == "1":
            initiated = True

        if initiated:
            sender.contacted_ip_set.add(dst)
            receiver.contacting_ip_set.add(src)
            if novelty.is_new(("ip", src, dst), frame_time_msec):
                sender.new_ip_set.add(dst)
            if initiated_port is not None:
                sender.contacted_port_set.add(initiated_port)
                if novelty.is_new(("port", src, initiated_port), frame_time_msec):
                    sender.new_port_set.add(initiated_port)

        if syn:
            sender.syn_out += 1
            receiver.syn_in += 1
            if dport in AUTH_PORTS:
                sender.auth_syn_out += 1
                receiver.auth_syn_in += 1
        if synack:
            receiver.synack_in += 1
        if rst:
            receiver.rst_in += 1
        if protocol == "icmp" and (
            ("icmp", str(packet_dict.get("icmp.type"))) in ICMP_UNREACH
            or ("icmpv6", str(packet_dict.get("icmpv6.type"))) in ICMP_UNREACH
        ):
            receiver.icmp_unreach_in += 1

    def window_columns(self):
        """Fan-out and entropy columns for windows.csv."""

        def top(attribute):
            best_ip, best = "", 0
            for ip, stats in self.hosts.items():
                size = len(getattr(stats, attribute))
                if size > best:
                    best_ip, best = ip, size
            return best, best_ip

        ports, ports_ip = top("contacted_port_set")
        ips, ips_ip = top("contacted_ip_set")
        srcs, srcs_ip = top("contacting_ip_set")
        return {
            "max_contacted_ports_per_src": ports,
            "top_src_by_contacted_ports": ports_ip,
            "max_contacted_ips_per_src": ips,
            "top_src_by_contacted_ips": ips_ip,
            "max_contacting_ips_per_dst": srcs,
            "top_dst_by_contacting_ips": srcs_ip,
            "top_src_by_packets": self.src_counts.most_common(1)[0][0]
            if self.src_counts
            else "",
            "top_dst_by_packets": self.dst_counts.most_common(1)[0][0]
            if self.dst_counts
            else "",
            "entropy_src_ip": round(entropy(self.src_counts), 4),
            "entropy_dst_ip": round(entropy(self.dst_counts), 4),
            "entropy_dst_port": round(entropy(self.dst_port_counts), 4),
        }

    def host_rows(self, home_net, topk):
        """Rows for hosts.csv: every active home host, plus the top-k external hosts."""

        def row(ip, s):
            return {
                "host": ip,
                "is_home": int(home_net.contains(ip)),
                "pkts_out": s.pkts_out,
                "pkts_in": s.pkts_in,
                "bytes_out": s.bytes_out,
                "bytes_in": s.bytes_in,
                "upload_bytes_ext": s.upload_bytes_ext,
                "download_bytes_ext": s.download_bytes_ext,
                "contacted_ips": len(s.contacted_ip_set),
                "contacted_ports": len(s.contacted_port_set),
                "contacting_ips": len(s.contacting_ip_set),
                "new_contacted_ips": len(s.new_ip_set),
                "new_contacted_ports": len(s.new_port_set),
                "syn_out": s.syn_out,
                "synack_in": s.synack_in,
                "rst_in": s.rst_in,
                "syn_in": s.syn_in,
                "auth_syn_out": s.auth_syn_out,
                "auth_syn_in": s.auth_syn_in,
                "icmp_unreach_in": s.icmp_unreach_in,
            }

        home = [(ip, s) for ip, s in self.hosts.items() if home_net.contains(ip)]
        external = [
            (ip, s) for ip, s in self.hosts.items() if not home_net.contains(ip)
        ]

        def interest(item):
            s = item[1]
            return max(
                len(s.contacted_port_set),
                len(s.contacted_ip_set),
                len(s.contacting_ip_set),
                s.syn_out,
                s.syn_in,
                s.pkts_out // 10,
            )

        chosen_external = sorted(external, key=interest, reverse=True)[:topk]
        return [row(ip, s) for ip, s in home + chosen_external]


def labels_for(labels, start_msec, end_msec, host=None):
    """Names of labeled intervals overlapping [start, end); host-specific when the label lists ips."""
    names = []
    for label in labels:
        if label["start_msec"] < end_msec and label["end_msec"] >= start_msec:
            if host is None or not label["ips"] or host in label["ips"]:
                names.append(label["name"])
    return "+".join(dict.fromkeys(names))


def load_labels(path):
    """CSV with columns label,start,end[,ips]: epoch seconds, ips space-separated."""
    import csv

    labels = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            labels.append(
                {
                    "name": row["label"],
                    "start_msec": float(row["start"]) * 1000,
                    "end_msec": float(row["end"]) * 1000,
                    "ips": set((row.get("ips") or "").split()),
                }
            )
    return labels
