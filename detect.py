#!/usr/bin/env python3
"""Offline intrusion detector over the dataset creator's output.

    python3 detect.py windows.csv hosts.csv -o alerts.jsonl --incidents incidents.jsonl

Reads windows.csv (-o) and hosts.csv (-oh) from main.py and writes one JSON alert per line.
Three layers:

1. Window rules with absolute thresholds: SYN floods (half-open SYNs plus many sources to one
   destination) and fast scans (one source contacting many ports or hosts in a window).
2. Per-host rules over a trailing time span: slow scans (contacts new to the host), failed
   connection pressure, remote-login brute force, and upload-heavy external transfers.
3. Volume anomalies: each named windows.csv column is scored against a rolling median/MAD of
   the same capture's earlier windows (log scale), excluding windows that already alerted. A
   column alerts after two consecutive anomalous windows (or one extreme window), and only for a material change (a
   minimum number of packets or bytes above the baseline), so near-silent networks stay quiet. No baseline is imported from another
   capture: across captures, normal levels differed by 20x.

Hosts that behave the same way all the time (a scanner you run, a busy resolver, a P2P client)
alert on every window. --learn-suppressions records the (kind, host) pairs that alert on a clean
capture of the same network; --suppress drops those later unless the value reaches
suppress_escalation times the learned peak.

Thresholds are in THRESHOLDS and can be changed with --set name=value. They are attack-defined
starting points, checked against the labeled captures in datasets/ (see
docs/plans/2026-11-05-per-host-detector.md), not tuned to your network.
"""

import argparse
import csv
import json
import math
import statistics
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

THRESHOLDS = {
    # window rules
    "syn_flood_half_open": 1000,  # num_syn - num_synack in one window
    "syn_flood_sources": 200,  # distinct sources initiating to one destination
    "scan_ports_per_window": 100,  # distinct ports one source contacted in one window
    "sweep_ips_per_window": 100,  # distinct hosts one source contacted in one window
    # per-host rules over trailing spans
    "slow_scan_span_sec": 600,
    "slow_scan_new_ports": 40,  # ports new to the host within the novelty horizon
    "slow_sweep_new_ips": 200,
    "failed_conn_span_sec": 600,
    "failed_conn_count": 100,  # SYNs sent minus SYN-ACKs received
    "login_span_sec": 600,
    "login_syns": 20,  # SYNs to remote-login ports
    "upload_span_sec": 60,
    "upload_bytes": 20_000_000,
    "upload_ratio": 5.0,  # upload bytes / download bytes with external hosts
    # volume baseline
    "baseline_windows": 720,  # trailing windows in the baseline (1 h of 5 s windows)
    "baseline_min_windows": 60,  # no volume alerts before this much history
    "volume_z": 6.0,
    "volume_min_scale": 0.5,  # floor on the log-scale spread, so near-constant columns don't explode
    "volume_consecutive": 2,
    "volume_single_window_z": 12.0,  # a window this extreme alerts on its own (5 s floods)
    # and the change must be material: at least this far above the baseline median per window
    "volume_min_delta_packets": 250,
    "volume_min_delta_bytes": 250_000,
    # incidents
    "incident_gap_sec": 120,
    # learned suppressions still alert when the value reaches this multiple of the learned peak
    "suppress_escalation": 3.0,
}

VOLUME_COLUMNS = [
    "num_packets",
    "num_tcp",
    "num_udp",
    "num_icmp",
    "num_arp",
    "tcp_frame_length",
    "udp_frame_length",
    "icmp_frame_length",
    "num_connection_pairs",
    "num_ports",
    "num_ip_fragments",
    "num_syn",
    "num_rst",
]


def iso(msec):
    return datetime.fromtimestamp(int(msec) / 1000, tz=timezone.utc).isoformat()


def num(row, column):
    value = row.get(column, "")
    return float(value) if value not in ("", None) else 0.0


def alert(window, kind, host, observed, threshold, detail, baseline=None):
    record = {
        "ts_start": iso(window["window_start_time"]),
        "window_start_time": int(window["window_start_time"]),
        "kind": kind,
        "host": host,
        "observed": observed,
        "threshold": threshold,
        "detail": detail,
    }
    if baseline is not None:
        record["baseline"] = baseline
    return record


def window_rules(w, t):
    out = []
    half_open = num(w, "num_syn") - num(w, "num_synack")
    sources = num(w, "max_contacting_ips_per_dst")
    if half_open >= t["syn_flood_half_open"] and sources >= t["syn_flood_sources"]:
        out.append(
            alert(
                w,
                "syn_flood",
                w.get("top_dst_by_contacting_ips", ""),
                {"half_open": half_open, "sources": sources},
                {
                    "half_open": t["syn_flood_half_open"],
                    "sources": t["syn_flood_sources"],
                },
                "many unanswered SYNs from many sources to one destination",
            )
        )
    return out


class RollingSums:
    """Running per-host sums of some columns over a trailing time span."""

    def __init__(self, span_sec, columns):
        self.span_msec = span_sec * 1000
        self.columns = columns
        self.rows = defaultdict(deque)
        self.sums = defaultdict(lambda: dict.fromkeys(columns, 0.0))

    def add(self, host, now, row):
        values = {c: num(row, c) for c in self.columns}
        rows, sums = self.rows[host], self.sums[host]
        rows.append((now, values))
        for c in self.columns:
            sums[c] += values[c]
        while rows and rows[0][0] <= now - self.span_msec:
            _, old = rows.popleft()
            for c in self.columns:
                sums[c] -= old[c]
        return sums


class HostRules:
    """Per-host fast rules (one window) and slow rules (running sums over trailing spans)."""

    RULE_COLUMNS = {
        "slow_scan_span_sec": ["new_contacted_ports", "new_contacted_ips"],
        "failed_conn_span_sec": ["syn_out", "synack_in"],
        "login_span_sec": ["auth_syn_out"],
        "upload_span_sec": ["upload_bytes_ext", "download_bytes_ext"],
    }

    def __init__(self, t):
        self.t = t
        # one RollingSums per distinct span, holding every column any rule with that span needs
        by_span = defaultdict(list)
        for span_key, columns in self.RULE_COLUMNS.items():
            by_span[t[span_key]] += columns
        self.rolling = {
            span: RollingSums(span, columns) for span, columns in by_span.items()
        }

    def update(self, row):
        t, host, now = self.t, row["host"], int(row["window_start_time"])
        sums = {}
        for span, rolling in self.rolling.items():
            sums[span] = rolling.add(host, now, row)

        def trailing(span_key, column):
            return sums[t[span_key]][column]

        out = []
        ports, ips = num(row, "contacted_ports"), num(row, "contacted_ips")
        if ports >= t["scan_ports_per_window"]:
            out.append(
                alert(
                    row,
                    "port_scan",
                    host,
                    ports,
                    t["scan_ports_per_window"],
                    "one host contacted many ports in one window",
                )
            )
        if ips >= t["sweep_ips_per_window"]:
            out.append(
                alert(
                    row,
                    "host_sweep",
                    host,
                    ips,
                    t["sweep_ips_per_window"],
                    "one host contacted many hosts in one window",
                )
            )

        new_ports = trailing("slow_scan_span_sec", "new_contacted_ports")
        if (
            new_ports >= t["slow_scan_new_ports"]
            and num(row, "new_contacted_ports") > 0
        ):
            out.append(
                alert(
                    row,
                    "slow_port_scan",
                    host,
                    new_ports,
                    t["slow_scan_new_ports"],
                    f"ports new to this host over {t['slow_scan_span_sec']:g} s",
                )
            )
        new_ips = trailing("slow_scan_span_sec", "new_contacted_ips")
        if new_ips >= t["slow_sweep_new_ips"] and num(row, "new_contacted_ips") > 0:
            out.append(
                alert(
                    row,
                    "slow_sweep",
                    host,
                    new_ips,
                    t["slow_sweep_new_ips"],
                    f"hosts new to this host over {t['slow_scan_span_sec']:g} s",
                )
            )

        failed = trailing("failed_conn_span_sec", "syn_out") - trailing(
            "failed_conn_span_sec", "synack_in"
        )
        if failed >= t["failed_conn_count"] and num(row, "syn_out") > 0:
            out.append(
                alert(
                    row,
                    "failed_connections",
                    host,
                    failed,
                    t["failed_conn_count"],
                    f"SYNs without SYN-ACK over {t['failed_conn_span_sec']:g} s",
                )
            )

        logins = trailing("login_span_sec", "auth_syn_out")
        if logins >= t["login_syns"] and num(row, "auth_syn_out") > 0:
            out.append(
                alert(
                    row,
                    "login_bruteforce",
                    host,
                    logins,
                    t["login_syns"],
                    f"SYNs to remote-login ports over {t['login_span_sec']:g} s",
                )
            )

        upload = trailing("upload_span_sec", "upload_bytes_ext")
        download = trailing("upload_span_sec", "download_bytes_ext")
        if (
            upload >= t["upload_bytes"]
            and upload >= t["upload_ratio"] * max(download, 1)
            and num(row, "upload_bytes_ext") > 0
        ):
            out.append(
                alert(
                    row,
                    "large_upload",
                    host,
                    {"upload": upload, "download": download},
                    {"upload": t["upload_bytes"], "ratio": t["upload_ratio"]},
                    f"client-side upload to external hosts over {t['upload_span_sec']:g} s",
                )
            )
        return out


class VolumeBaseline:
    """Rolling robust baseline per column; alerts after N consecutive anomalous windows."""

    def __init__(self, t, columns):
        self.t = t
        self.columns = columns
        self.history = deque(maxlen=int(t["baseline_windows"]))
        self.streak = defaultdict(int)

    def update(self, w):
        t = self.t
        values = {c: math.log1p(num(w, c)) for c in self.columns}
        out = []
        anomalous = False
        if len(self.history) >= t["baseline_min_windows"]:
            for c in self.columns:
                past = [h[c] for h in self.history]
                median = statistics.median(past)
                mad = statistics.median(abs(x - median) for x in past) * 1.4826
                scale = max(mad, t["volume_min_scale"])
                z = (values[c] - median) / scale
                delta = num(w, c) - math.expm1(median)
                min_delta = (
                    t["volume_min_delta_bytes"]
                    if c.endswith("_length")
                    else t["volume_min_delta_packets"]
                )
                if z >= t["volume_z"] and delta >= min_delta:
                    self.streak[c] += 1
                    anomalous = True
                    if (
                        self.streak[c] >= t["volume_consecutive"]
                        or z >= t["volume_single_window_z"]
                    ):
                        out.append(
                            alert(
                                w,
                                f"volume_{c}",
                                w.get("top_dst_by_packets", ""),
                                num(w, c),
                                round(math.expm1(median + t["volume_z"] * scale)),
                                f"robust z {z:.1f} against the trailing {len(self.history)} windows",
                                baseline=round(math.expm1(median)),
                            )
                        )
                else:
                    self.streak[c] = 0
        # alerted windows stay out of the baseline so an attack doesn't become normal
        if not anomalous:
            self.history.append(values)
        return out


def read_rows(path):
    with open(path, newline="") as f:
        yield from csv.DictReader(f)


def detect(windows_path, hosts_path, t):
    host_rows = read_rows(hosts_path) if hosts_path else iter(())
    pending = next(host_rows, None)
    host_rules = HostRules(t)
    baseline = VolumeBaseline(t, VOLUME_COLUMNS)
    alerts = []
    for w in read_rows(windows_path):
        start = int(w["window_start_time"])
        alerts += window_rules(w, t)
        alerts += baseline.update(w)
        while pending is not None and int(pending["window_start_time"]) <= start:
            alerts += host_rules.update(pending)
            pending = next(host_rows, None)
    while pending is not None:
        alerts += host_rules.update(pending)
        pending = next(host_rows, None)
    return alerts


def incidents(alerts, gap_sec):
    """Merge alerts with the same kind and host that are within gap_sec of each other."""
    merged = {}
    out = []
    for a in sorted(alerts, key=lambda a: a["window_start_time"]):
        key = (a["kind"], a["host"])
        current = merged.get(key)
        if (
            current
            and a["window_start_time"] - current["last_window"] <= gap_sec * 1000
        ):
            current["last_window"] = a["window_start_time"]
            current["alerts"] += 1
        else:
            current = merged[key] = {
                "kind": a["kind"],
                "host": a["host"],
                "first_window": a["window_start_time"],
                "last_window": a["window_start_time"],
                "first": a["ts_start"],
                "alerts": 1,
                "detail": a["detail"],
            }
            out.append(current)
    return out


def scalar(observed):
    """Single number for an alert's observed value (the first value of a dict)."""
    if isinstance(observed, dict):
        return float(next(iter(observed.values()), 0))
    return float(observed)


def learn_suppressions(alerts, until_msec=None, exclude_hosts=()):
    """Peak observed value per (kind, host) among alerts before until_msec.

    exclude_hosts: hosts known to be involved in incidents during the learning capture, so their
    alerts are not learned as normal.
    """
    peaks = {}
    for a in alerts:
        if until_msec is not None and a["window_start_time"] >= until_msec:
            continue
        if a["host"] in exclude_hosts:
            continue
        key = (a["kind"], a["host"])
        peaks[key] = max(peaks.get(key, 0.0), scalar(a["observed"]))
    return peaks


def write_suppressions(path, peaks):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["kind", "host", "peak"])
        for (kind, host), peak in sorted(peaks.items()):
            writer.writerow([kind, host, peak])


def read_suppressions(path):
    return {(row["kind"], row["host"]): float(row["peak"]) for row in read_rows(path)}


def apply_suppressions(alerts, peaks, escalation):
    """Drop alerts for known-noisy (kind, host) pairs unless they escalate past the learned peak."""
    kept = []
    for a in alerts:
        peak = peaks.get((a["kind"], a["host"]))
        if peak is None or scalar(a["observed"]) >= escalation * peak:
            kept.append(a)
    return kept


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("windows", help="windows CSV from main.py -o")
    parser.add_argument("hosts", nargs="?", help="hosts CSV from main.py -oh")
    parser.add_argument("-o", "--alerts", default="-", help="alerts JSONL [stdout]")
    parser.add_argument("--incidents", help="also write merged incidents JSONL here")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="override a threshold; repeatable",
    )
    parser.add_argument(
        "--learn-suppressions",
        metavar="OUT",
        help="write the (kind, host) pairs that alert, with their peak, as a suppression file",
    )
    parser.add_argument(
        "--learn-until",
        type=float,
        metavar="EPOCH",
        help="only learn from windows before this epoch time (seconds), e.g. before a known attack",
    )
    parser.add_argument(
        "--learn-exclude",
        default="",
        metavar="IPS",
        help="comma-separated hosts involved in known incidents; never learned as normal",
    )
    parser.add_argument(
        "--suppress",
        metavar="FILE",
        help="suppression file learned from a clean capture of the same network",
    )
    args = parser.parse_args(argv)

    t = dict(THRESHOLDS)
    for item in args.set:
        name, _, value = item.partition("=")
        if name not in t:
            parser.error(f"unknown threshold {name}; known: {', '.join(t)}")
        t[name] = float(value)

    alerts = detect(args.windows, args.hosts, t)
    if args.learn_suppressions:
        until = args.learn_until * 1000 if args.learn_until else None
        exclude = {h.strip() for h in args.learn_exclude.split(",") if h.strip()}
        peaks = learn_suppressions(alerts, until, exclude)
        write_suppressions(args.learn_suppressions, peaks)
        print(f"learned {len(peaks)} suppressions", file=sys.stderr)
    if args.suppress:
        before = len(alerts)
        alerts = apply_suppressions(
            alerts, read_suppressions(args.suppress), t["suppress_escalation"]
        )
        print(f"suppressed {before - len(alerts)} alerts", file=sys.stderr)
    out = sys.stdout if args.alerts == "-" else open(args.alerts, "w")
    for a in alerts:
        out.write(json.dumps(a) + "\n")
    if out is not sys.stdout:
        out.close()
    if args.incidents:
        with open(args.incidents, "w") as f:
            for i in incidents(alerts, t["incident_gap_sec"]):
                f.write(json.dumps(i) + "\n")
    print(f"{len(alerts)} alerts", file=sys.stderr)


if __name__ == "__main__":
    main()
