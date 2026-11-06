#!/usr/bin/env python3
"""Beacon scoring over the connection log (main.py -oc connections.csv). Stdlib only.

A beacon is a host contacting the same destination and port at a steady period for a long time:
C2 check-ins, but also NTP, update polls and telemetry. Each (src, dst, dport) pair of outbound
contacts from a home host to a non-home host is scored from 0 to 1 on:

  coverage    (primary) the share of median-gap slots across the pair's span holding an
              attempt. A beacon fills nearly every slot; bursts fill a few.
  regularity  1 - MAD / median of the gaps between attempts
  symmetry    1 - |Bowley skew| of the gaps
  size        1 - MAD / median of the bytes sent per attempt

Before scoring, a connection that follows an unanswered one (S0 or REJ) to the same (src, dst,
dport) within retry_sec is a retry and joins that attempt; answered connections are never merged,
so a burst stays a burst. Multicast and broadcast destinations are dropped. A pair is scored only
with min_contacts attempts over min_span_sec, and with a median gap of at least min_gap_sec
(shorter is a burst, not a beacon). It alerts with coverage >= min_coverage and the mean of the
four scores >= beacon_score.

False-alarm controls, applied after scoring:
  allowlist   beacon_allow.txt (shipped; --beacon-allow replaces it): proto/port entries and
              CIDRs for traffic that polls by design. Kept short; every entry is a blind spot.
  popularity  destinations contacted by at least max(beacon_popular_hosts,
              beacon_popular_share * active home hosts) home hosts are shared services.
Every alert carries `evidence`, a count of TLS/HTTP facts that are odd for the pair (no SNI,
a JA3 or user agent this host uses toward this destination only, a self-signed certificate, a
bare-IP Host header) and their names in `facts`. Evidence ranks alerts; it never creates one.

Design and the numbers it must beat: docs/plans/2026-11-06-connection-log.md, step 2, and the
RITA reference in tools/eval/reference/.

    python3 beacons.py connections.csv [more.csv ...] [--top 20] [--mark SRC>DST=NAME]
"""

import argparse
import csv
import ipaddress
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone

UNANSWERED = {"S0", "REJ"}
ALLOW_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "beacon_allow.txt"
)

DEFAULTS = {
    "beacon_retry_sec": 3,
    "beacon_min_contacts": 10,
    "beacon_min_span_sec": 300,
    "beacon_min_gap_sec": 5,
    "beacon_min_coverage": 0.6,
    "beacon_score": 0.8,
    "beacon_popular_hosts": 5,
    "beacon_popular_share": 0.1,
}


def excluded_destination(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or (address.version == 4 and str(address).endswith(".255"))
    )


def is_ip(text):
    host = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class Aggregate:
    """Everything the scorer needs from the connection log, gathered in one streaming pass."""

    def __init__(self):
        self.attempts = defaultdict(
            list
        )  # (src, dst, dport) -> [(start, bytes, answered)]
        self.protocol = {}  # (src, dst, dport) -> tcp/udp
        self.hellos = defaultdict(int)  # pair -> TLS ClientHellos seen
        self.no_sni = defaultdict(int)  # pair -> ClientHellos without SNI
        self.self_signed = set()  # pairs with a self-signed certificate
        self.bare_ip_host = set()  # pairs with an HTTP Host header that is an IP
        self.ja3 = defaultdict(set)  # pair -> JA3s
        self.agents = defaultdict(set)  # pair -> user agents
        self.ja3_dsts = defaultdict(set)  # (src, ja3) -> destinations
        self.agent_dsts = defaultdict(set)  # (src, user agent) -> destinations
        self.dst_sources = defaultdict(set)  # dst -> home hosts that contacted it
        self.home_sources = set()  # home hosts that initiated any outbound contact

    def add(self, row):
        if row["initiated"] != "1" or row["proto"] not in ("tcp", "udp"):
            return
        if row["src_home"] != "1" or row["dst_home"] == "1":
            return
        src, dst = row["src"], row["dst"]
        if excluded_destination(dst):
            return
        pair = (src, dst, row["dport"])
        self.attempts[pair].append(
            (
                int(row["start_msec"]) / 1000,
                int(row["bytes_out"]),
                row["state"] not in UNANSWERED,
            )
        )
        self.protocol[pair] = row["proto"]
        self.dst_sources[dst].add(src)
        self.home_sources.add(src)
        if row["tls_ja3"]:
            self.hellos[pair] += 1
            self.no_sni[pair] += not row["tls_sni"]
            self.ja3[pair].add(row["tls_ja3"])
            self.ja3_dsts[(src, row["tls_ja3"])].add(dst)
        if row["cert_self_signed"] == "1":
            self.self_signed.add(pair)
        if row["http_host"] and is_ip(row["http_host"]):
            self.bare_ip_host.add(pair)
        if row["http_user_agent"]:
            self.agents[pair].add(row["http_user_agent"])
            self.agent_dsts[(src, row["http_user_agent"])].add(dst)

    def facts(self, pair):
        """Names of the odd TLS/HTTP facts for this pair."""
        src, dst, _ = pair
        found = []
        if self.hellos[pair] and self.no_sni[pair] == self.hellos[pair]:
            found.append("tls_no_sni")
        if any(self.ja3_dsts[(src, j)] == {dst} for j in self.ja3[pair]):
            found.append("ja3_single_destination")
        if pair in self.self_signed:
            found.append("cert_self_signed")
        if pair in self.bare_ip_host:
            found.append("http_host_is_ip")
        if any(self.agent_dsts[(src, a)] == {dst} for a in self.agents[pair]):
            found.append("user_agent_single_destination")
        return found


def aggregate(rows):
    agg = Aggregate()
    for row in rows:
        agg.add(row)
    for attempts in agg.attempts.values():
        attempts.sort()
    return agg


def collapse_retries(attempts, retry_sec):
    """[(start, bytes)] with each retry (a contact within retry_sec after an unanswered one)
    merged into the attempt it retries; bytes add up."""
    merged = []  # [first start, bytes, latest start, latest answered]
    for start, sent, answered in attempts:
        if merged and not merged[-1][3] and start - merged[-1][2] < retry_sec:
            merged[-1][1] += sent
            merged[-1][2:] = [start, answered]
        else:
            merged.append([start, sent, start, answered])
    return [(first, sent) for first, sent, _, _ in merged]


def mad_score(values):
    median = statistics.median(values)
    if median <= 0:
        return 1.0 if all(v == 0 for v in values) else 0.0
    mad = statistics.median(abs(v - median) for v in values)
    return max(0.0, 1.0 - mad / median)


def bowley_score(values):
    if len(values) < 4:
        return 0.0
    q1, q2, q3 = statistics.quantiles(values, n=4)
    if q3 == q1:
        return 1.0
    return max(0.0, 1.0 - abs((q1 + q3 - 2 * q2) / (q3 - q1)))


def coverage(times, gap):
    span = times[-1] - times[0]
    slots = max(1, round(span / gap))
    filled = {min(int((t - times[0]) / gap), slots - 1) for t in times}
    return len(filled) / slots


def score_pair(attempts, t):
    """Scores for one pair's attempts (already collapsed), or None if it does not qualify."""
    if len(attempts) < t["beacon_min_contacts"]:
        return None
    times = [start for start, _ in attempts]
    if times[-1] - times[0] < t["beacon_min_span_sec"]:
        return None
    gaps = [b - a for a, b in zip(times, times[1:])]
    gap = statistics.median(gaps)
    if gap < t["beacon_min_gap_sec"]:
        return None
    scores = {
        "coverage": coverage(times, gap),
        "regularity": mad_score(gaps),
        "symmetry": bowley_score(gaps),
        "size": mad_score([sent for _, sent in attempts]),
    }
    return {
        **{k: round(v, 3) for k, v in scores.items()},
        "score": round(sum(scores.values()) / len(scores), 3),
        "attempts": len(attempts),
        "period_sec": round(gap, 1),
        "first": times[0],
        "last": times[-1],
    }


def score_all(agg, t=None):
    """Every qualifying pair, best first, before any allowlist or filter."""
    t = {**DEFAULTS, **(t or {})}
    results = []
    for pair, attempts in agg.attempts.items():
        scored = score_pair(collapse_retries(attempts, t["beacon_retry_sec"]), t)
        if scored:
            src, dst, dport = pair
            results.append(
                {
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "proto": agg.protocol[pair],
                    **scored,
                    "facts": agg.facts(pair),
                }
            )
    results.sort(key=lambda r: (-r["score"], -r["coverage"], -r["attempts"]))
    return results


def load_allowlist(path=ALLOW_FILE):
    """(set of 'proto/port', list of networks) from an allowlist file; '#' starts a comment."""
    ports, networks = set(), []
    with open(path) as f:
        for line in f:
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            if "/" in entry and entry.split("/")[0] in ("tcp", "udp"):
                ports.add(entry)
            else:
                networks.append(ipaddress.ip_network(entry, strict=False))
    return ports, networks


def allowed(result, allowlist):
    ports, networks = allowlist
    if f"{result['proto']}/{result['dport']}" in ports:
        return True
    address = ipaddress.ip_address(result["dst"])
    return any(address.version == n.version and address in n for n in networks)


def popular(result, agg, t):
    limit = max(
        t["beacon_popular_hosts"], t["beacon_popular_share"] * len(agg.home_sources)
    )
    return len(agg.dst_sources[result["dst"]]) >= limit


def beacon_alerts(rows, t=None, allowlist=None):
    """detect.py alerts for the beacons in the connection rows."""
    t = {**DEFAULTS, **(t or {})}
    allowlist = allowlist if allowlist is not None else load_allowlist()
    agg = aggregate(rows)
    alerts = []
    for r in score_all(agg, t):
        if r["coverage"] < t["beacon_min_coverage"] or r["score"] < t["beacon_score"]:
            continue
        if allowed(r, allowlist) or popular(r, agg, t):
            continue
        peer = f"{r['dst']}:{r['dport']}"
        hours = (r["last"] - r["first"]) / 3600
        alerts.append(
            {
                "ts_start": datetime.fromtimestamp(
                    r["first"], tz=timezone.utc
                ).isoformat(),
                "window_start_time": int(r["first"] * 1000),
                "kind": "beacon",
                "host": r["src"],
                "peer": peer,
                "observed": {
                    k: r[k]
                    for k in (
                        "score",
                        "coverage",
                        "regularity",
                        "symmetry",
                        "size",
                        "attempts",
                        "period_sec",
                    )
                },
                "threshold": {
                    "score": t["beacon_score"],
                    "coverage": t["beacon_min_coverage"],
                },
                "evidence": len(r["facts"]),
                "facts": r["facts"],
                "detail": f"{r['attempts']} contacts about every {r['period_sec']:g} s "
                f"to {peer} over {hours:.1f} h",
            }
        )
    return alerts


def read_connections(paths):
    for path in paths:
        with open(path, newline="") as f:
            yield from csv.DictReader(f)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("connections", nargs="+")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--mark", action="append", default=[], metavar="SRC>DST=NAME")
    args = parser.parse_args(argv)
    marks = {}
    for item in args.mark:
        pair, _, name = item.partition("=")
        src, _, dst = pair.partition(">")
        marks[(src, dst)] = name
    results = score_all(aggregate(read_connections(args.connections)))
    print("rank score  cov   reg   sym   size  attempts  period  src dst:dport  facts")
    for rank, r in enumerate(results, 1):
        mark = marks.get((r["src"], r["dst"]), "")
        if rank <= args.top or mark:
            print(
                f"{rank:4d} {r['score']:.3f} {r['coverage']:.3f} {r['regularity']:.3f} "
                f"{r['symmetry']:.3f} {r['size']:.3f} {r['attempts']:8d} {r['period_sec']:7.1f} "
                f" {r['src']} {r['dst']}:{r['dport']}  {','.join(r['facts'])} {mark}"
            )
    print(f"{len(results)} pairs scored", file=sys.stderr)


if __name__ == "__main__":
    main()
