#!/usr/bin/env python3
"""Write a pcap of synthetic attacks with exact ground truth, for injection into a benign capture.

    python3 tools/eval/gen_attacks.py OUT.pcap START_EPOCH LABELS.csv [--victim IP] [--attacker IP]

Needs scapy (not in requirements.txt). Packets are crafted offline; nothing is sent. Every attack
is placed at a fixed offset from START_EPOCH, and LABELS.csv (label,start,end,ips) records each
one. The whole schedule fits in START_EPOCH + 560 s. The random seed is fixed, so the output is
reproducible.

Attacks: fast TCP SYN port scan, slow scan, spoofed SYN flood, SSH brute force, DNS tunnel,
C2 beacon (30 s period to EXTERNAL:443) and a 40 MB bulk upload.
"""

import argparse
import csv
import random
import string

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
parser.add_argument("out")
parser.add_argument("start", type=float)
parser.add_argument("labels")
parser.add_argument("--victim", default="192.168.10.50")
parser.add_argument("--attacker", default="192.168.10.66")
parser.add_argument("--external", default="203.0.113.77")
args = parser.parse_args()

random.seed(7)
out, start, labels = args.out, args.start, args.labels
VICTIM, ATTACKER, EXTERNAL = args.victim, args.attacker, args.external
MAC_A, MAC_V = "02:00:00:00:00:66", "02:00:00:00:00:50"

pkts = []
truth = []


def eth(p, rev=False):
    return Ether(src=MAC_V if rev else MAC_A, dst=MAC_A if rev else MAC_V) / p


def stamp(p, t):
    p.time = t
    pkts.append(p)


def tcp_session(t, src, dst, sport, dport, payloads, gap=0.002):
    """3-way handshake, alternating payload exchange, FIN close."""
    seq_c, seq_s = random.randint(1, 2**31), random.randint(1, 2**31)
    stamp(
        eth(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c)),
        t,
    )
    t += gap
    stamp(
        eth(
            IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
            True,
        ),
        t,
    )
    seq_c += 1
    seq_s += 1
    t += gap
    stamp(
        eth(
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s)
        ),
        t,
    )
    for from_client, data in payloads:
        t += gap
        if from_client:
            stamp(
                eth(
                    IP(src=src, dst=dst)
                    / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s)
                    / Raw(data)
                ),
                t,
            )
            seq_c += len(data)
        else:
            stamp(
                eth(
                    IP(src=dst, dst=src)
                    / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
                    / Raw(data),
                    True,
                ),
                t,
            )
            seq_s += len(data)
    t += gap
    stamp(
        eth(
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s)
        ),
        t,
    )
    t += gap
    stamp(
        eth(
            IP(src=dst, dst=src)
            / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1),
            True,
        ),
        t,
    )
    return t


def mark(name, t0, t1, src, dst, note):
    ips = " ".join(ip for ip in (src, dst) if "/" not in ip and " " not in ip)
    truth.append(
        {
            "label": name,
            "start": round(t0, 3),
            "end": round(t1, 3),
            "ips": ips,
            "note": note,
        }
    )


t = start
# 1. TCP SYN port scan: 1000 ports in ~8 s, closed ports answer RST
t0 = t
for i, port in enumerate(random.sample(range(1, 10000), 1000)):
    ts = t0 + i * 0.008
    stamp(
        eth(
            IP(src=ATTACKER, dst=VICTIM)
            / TCP(sport=40000 + i % 1000, dport=port, flags="S")
        ),
        ts,
    )
    stamp(
        eth(
            IP(src=VICTIM, dst=ATTACKER)
            / TCP(sport=port, dport=40000 + i % 1000, flags="RA"),
            True,
        ),
        ts + 0.0005,
    )
mark("portscan", t0, ts, ATTACKER, VICTIM, "1000 SYN to distinct ports, RST replies")

# 2. Slow scan (low-and-slow): 60 ports over 100 s
t = start + 45
t0 = t
for i, port in enumerate(random.sample(range(1, 1024), 60)):
    ts = t0 + i * 1.7
    stamp(
        eth(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=port, flags="S")),
        ts,
    )
    stamp(
        eth(
            IP(src=VICTIM, dst=ATTACKER) / TCP(sport=port, dport=50000 + i, flags="RA"),
            True,
        ),
        ts + 0.0005,
    )
mark("slowscan", t0, ts, ATTACKER, VICTIM, "60 SYN over 100 s")

# 3. SYN flood from spoofed sources, 15k SYN over 10 s, no replies
t = start + 165
t0 = t
for i in range(15000):
    src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    stamp(
        eth(
            IP(src=src, dst=VICTIM)
            / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        ),
        t0 + i * 0.00066,
    )
mark(
    "synflood",
    t0,
    t0 + 15000 * 0.00066,
    "spoofed 10/8",
    VICTIM,
    "15k SYN to :80, spoofed",
)

# 4. SSH brute force: 40 full sessions to :22 over 80 s, banner + small encrypted-looking records
t = start + 200
t0 = t
for i in range(40):
    payloads = [
        (False, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"),
        (True, b"SSH-2.0-libssh2_1.10.0\r\n"),
    ]
    payloads += [
        (
            j % 2 == 0,
            bytes(random.getrandbits(8) for _ in range(random.randint(48, 400))),
        )
        for j in range(14)
    ]
    tcp_session(t0 + i * 2.0, ATTACKER, VICTIM, 33000 + i, 22, payloads)
mark("ssh_bruteforce", t0, t0 + 80, ATTACKER, VICTIM, "40 short SSH sessions")

# 5. DNS tunnelling exfil: 1500 TXT queries with long random labels over 60 s
t = start + 300
t0 = t
for i in range(1500):
    label = "".join(random.choices(string.ascii_lowercase + "234567", k=60))
    q = (
        IP(src=VICTIM, dst="198.51.100.53")
        / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(
            id=i, rd=1, qd=DNSQR(qname=f"{label}.{i:x}.exfil.example.net", qtype="TXT")
        )
    )
    stamp(Ether(src=MAC_V, dst=MAC_A) / q, t0 + i * 0.04)
mark("dns_tunnel", t0, t0 + 60, VICTIM, "198.51.100.53", "1500 long TXT queries")

# 6. C2 beaconing: one tiny HTTPS-port session every 30 s for 9 min (overlaps later attacks' windows)
t0 = start + 15
for i in range(18):
    tcp_session(
        t0 + i * 30 + random.uniform(-1, 1),
        VICTIM,
        EXTERNAL,
        51000 + i,
        443,
        [
            (True, bytes(random.getrandbits(8) for _ in range(180))),
            (False, bytes(random.getrandbits(8) for _ in range(90))),
        ],
    )
mark("beacon", t0, t0 + 540, VICTIM, EXTERNAL, "18 tiny :443 sessions, 30 s period")

# 7. Bulk exfil: ~40 MB upload to external host over 30 s (single session)
t0 = start + 400
payloads = [(True, bytes(1400)) for _ in range(28000)]
tcp_session(t0, VICTIM, EXTERNAL, 52000, 443, payloads, gap=30 / 28000)
mark("bulk_exfil", t0, t0 + 30, VICTIM, EXTERNAL, "~40 MB upload, one session")

pkts.sort(key=lambda p: float(p.time))
wrpcap(out, pkts)
with open(labels, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["label", "start", "end", "ips", "note"])
    w.writeheader()
    w.writerows(truth)
print(f"{len(pkts)} packets, {len(truth)} labels")
