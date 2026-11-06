#!/usr/bin/env python3
"""Reimplementation of RITA's beacon scoring on a Zeek conn.log.

Follows activecm/rita (v5, analysis/beacons.go) with the legacy v4
(activecm/rita-legacy pkg/beacon/analyzer.go) variants reported alongside.

Per (src, dst) IP pair (RITA's "unique connection", all ports/protocols pooled):
  ts list    = sorted conn.log ts truncated to whole seconds
  bytes list = sorted orig_ip_bytes (v5 uses src_ip_bytes_list; legacy used orig_bytes)

  tsScore   = round3( (tsSkewScore + tsMadScore) / 2 )
  dsScore   = round3( (dsSkewScore + dsMadScore) / 2 )            # v5
  dsScoreL  = ceil3( (dsSkewScore + dsMadScore + dsSmallness) / 3 ) # legacy
  histScore = max(cvScore, bimodalFitScore) over 24 equal bins of the dataset span
  durScore  = max(coverage, consistency) if non-empty bins >= 6 else 0
  score     = round3( 0.25*tsScore + 0.25*dsScore + 0.25*durScore + 0.25*histScore )

  skewScore = 1 - |Bowley skew|, Bowley = (Q1 + Q3 - 2*Q2) / (Q3 - Q1),
              forced to 0 when Q3-Q1 < 10 or Q2 == Q1 or Q2 == Q3
  madScore  = (median - MAD) / median clipped at 0 (default 1 for ts, 0 for ds when median < 1)
  smallness = 1 - dsMode/65535 (legacy only)
  cvScore   = 1 - sd/mean of the 24-bin connection histogram (0 if cv > 1)
  bimodal   = (top two histogram-height bins) / (nonEmptyBins - 1), only if nonEmptyBins >= 11
  coverage  = (last ts - first ts) / (dataset max - dataset min)
  consistency = longest wrap-around run of non-empty bins / 12
"""
import argparse
import ipaddress
import math
import statistics
import sys
from collections import defaultdict


def round3(x):
    return math.floor(x * 1000 + 0.5) / 1000


def ceil3(x):
    return math.ceil(x * 1000) / 1000


def median(xs):
    return statistics.median(xs)


def quartiles(sorted_xs):
    """montanaflynn/stats.Quartile: median of lower/upper halves, excluding the median for odd n."""
    n = len(sorted_xs)
    if n % 2 == 0:
        c1 = c2 = n // 2
    else:
        c1 = (n - 1) // 2
        c2 = c1 + 1
    return median(sorted_xs[:c1]), median(sorted_xs), median(sorted_xs[c2:])


def legacy_quartiles(sorted_xs):
    """rita-legacy: direct index Round(.25*(n-1)) etc. (Go Round = half away from zero)."""
    n = len(sorted_xs)

    def r(x):
        return int(math.floor(x + 0.5))

    return (
        sorted_xs[r(0.25 * (n - 1))],
        sorted_xs[r(0.5 * (n - 1))],
        sorted_xs[r(0.75 * (n - 1))],
    )


def bowley(q1, q2, q3):
    num = q1 + q3 - 2 * q2
    den = q3 - q1
    skew = 0.0
    if den >= 10 and q2 != q1 and q2 != q3:
        skew = num / den
    return skew, 1.0 - abs(skew)


def mad_score(sorted_xs, default):
    med = median(sorted_xs)
    mad = median([abs(x - med) for x in sorted_xs])
    score = default
    if med >= 1:
        score = (med - mad) / med
    if score < 0 or math.isnan(score):
        score = 0.0
    return med, mad, score


def distinct_counts(sorted_xs):
    counts = defaultdict(int)
    for x in sorted_xs:
        counts[int(x)] += 1
    mode = sorted_xs[0]
    best = counts[int(mode)]
    for x in sorted(counts):
        if counts[x] > best:
            best = counts[x]
            mode = x
    return int(mode), best


def histogram(ds_min, ds_max, ts_sorted, nbins=24, sensitivity=0.05):
    step = (ds_max - ds_min) / nbins
    edges = [ds_min + i * step for i in range(nbins + 1)]
    edges[-1] = ds_max
    freq = [0] * nbins
    for t in ts_sorted:
        b = nbins - 1
        for i in range(nbins):
            if t < edges[i + 1]:
                b = i
                break
        freq[b] += 1
    total_bars = sum(1 for f in freq if f > 0)
    largest = max(freq)
    bin_size = math.ceil(largest * sensitivity)
    freq_count = defaultdict(int)
    longest = cur = 0
    for i in range(nbins * 2):
        f = freq[i % nbins]
        if f > 0:
            cur += 1
        else:
            longest = max(longest, cur)
            cur = 0
        if i < nbins and f > 0:
            freq_count[int(math.floor(f / bin_size) * bin_size)] += 1
    longest = min(max(longest, cur), nbins)
    # cv score
    mean = sum(freq) / nbins
    sd = math.sqrt(sum((f - mean) ** 2 for f in freq) / nbins)
    cv = sd / abs(mean)
    cv_score = 0.0 if cv > 1.0 else min(round3(1.0 - cv), 1.0)
    # bimodal fit
    bimodal = 0.0
    if total_bars >= 11:
        vals = sorted(freq_count.values(), reverse=True)
        top2 = vals[0] + (vals[1] if len(vals) > 1 else 0)
        bimodal = min(round3(top2 / max(total_bars - 1, 1)), 1.0)
    return freq, total_bars, longest, cv_score, bimodal, max(cv_score, bimodal)


def duration_score(ds_min, ds_max, first, last, total_bars, longest):
    coverage = consistency = 0.0
    if total_bars >= 6:
        coverage = min(ceil3((last - first) / (ds_max - ds_min)), 1.0)
        consistency = min(ceil3(longest / 12.0), 1.0)
    return coverage, consistency, max(coverage, consistency)


def score_pair(ts_list, bytes_list, ds_min, ds_max):
    ts = sorted(ts_list)
    deltas_full = sorted(ts[i + 1] - ts[i] for i in range(len(ts) - 1))
    nonzero = [d for d in deltas_full if d > 0]
    if len(ts) < 4 or len(nonzero) < 3:
        return None
    r = {}
    q1, q2, q3 = quartiles(nonzero)
    r["ts_skew"], ts_skew_score = bowley(q1, q2, q3)
    r["ts_med"], r["ts_mad"], ts_mad_score = mad_score(nonzero, 1.0)
    r["ts_skew_score"], r["ts_mad_score"] = ts_skew_score, ts_mad_score
    r["ts_score"] = round3((ts_skew_score + ts_mad_score) / 2)
    r["ts_mode"], r["ts_mode_n"] = distinct_counts(deltas_full)

    bs = sorted(bytes_list)
    q1, q2, q3 = quartiles(bs)
    r["ds_skew"], ds_skew_score = bowley(q1, q2, q3)
    r["ds_med"], r["ds_mad"], ds_mad_score = mad_score(bs, 0.0)
    r["ds_skew_score"], r["ds_mad_score"] = ds_skew_score, ds_mad_score
    r["ds_score"] = round3((ds_skew_score + ds_mad_score) / 2)
    r["ds_mode"], r["ds_mode_n"] = distinct_counts(bs)
    r["ds_small"] = max(1.0 - r["ds_mode"] / 65535.0, 0.0)
    r["ds_score_legacy"] = ceil3((ds_skew_score + ds_mad_score + r["ds_small"]) / 3)

    freq, bars, longest, cv_s, bim_s, hist = histogram(ds_min, ds_max, ts)
    r["bars"], r["longest_run"], r["cv_score"], r["bimodal_score"], r["hist_score"] = (
        bars,
        longest,
        cv_s,
        bim_s,
        hist,
    )
    r["coverage"], r["consistency"], r["dur_score"] = duration_score(
        ds_min, ds_max, ts[0], ts[-1], bars, longest
    )
    r["score"] = round3(
        0.25 * (r["ts_score"] + r["ds_score"] + r["dur_score"] + r["hist_score"])
    )
    # legacy v4: ceil rounding, 3-part ds score, index quartiles; weights the same 0.25 each
    lq1, lq2, lq3 = legacy_quartiles(nonzero)
    _, lts_skew = bowley(lq1, lq2, lq3)
    lts_mad = median([abs(x - lq2) for x in nonzero])
    lts_mad_score = max(1.0 - lts_mad / lq2, 0.0) if lq2 >= 1 else 1.0
    lts = ceil3((lts_skew + lts_mad_score) / 2)
    lq1, lq2, lq3 = legacy_quartiles(bs)
    _, lds_skew = bowley(lq1, lq2, lq3)
    lds_mad = median([abs(x - lq2) for x in bs])
    lds_mad_score = max(1.0 - lds_mad / lq2, 0.0) if lq2 >= 1 else 0.0
    lds = ceil3((lds_skew + lds_mad_score + r["ds_small"]) / 3)
    r["score_legacy"] = ceil3(0.25 * (lts + lds + r["dur_score"] + r["hist_score"]))
    r["conns"] = len(ts)
    return r


def load_conn(path, internal, allow_any=False):
    fields = None
    pairs = defaultdict(lambda: {"ts": [], "bytes": [], "ports": defaultdict(int)})
    tmin, tmax = None, None
    nets = [ipaddress.ip_network(n) for n in internal]
    # RITA v5 config/filter.go GetMandatoryNeverIncludeSubnets: dropped at import whatever the config says
    never = [
        ipaddress.ip_network(n)
        for n in (
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "::/128",
            "fe80::/10",
            "ff00::/8",
        )
    ]

    def is_internal(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)

    def never_included(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(a in n for n in never)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                continue
            cols = line.rstrip("\n").split("\t")
            row = dict(zip(fields, cols))
            ts = float(row["ts"])
            tmin = ts if tmin is None else min(tmin, ts)
            tmax = ts if tmax is None else max(tmax, ts)
            src, dst = row["id.orig_h"], row["id.resp_h"]
            if never_included(src) or never_included(dst):
                continue
            if not allow_any and not (is_internal(src) and not is_internal(dst)):
                continue
            p = pairs[(src, dst)]
            p["ts"].append(int(ts))
            b = row.get("orig_ip_bytes", "-")
            p["bytes"].append(float(b) if b != "-" else 0.0)
            p["ports"][f'{row["proto"]}/{row["id.resp_p"]}'] += 1
    return pairs, tmin, tmax


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("conn_log")
    ap.add_argument(
        "--internal",
        action="append",
        default=[],
        help="CIDR of the home network (repeatable)",
    )
    ap.add_argument(
        "--any",
        action="store_true",
        help="do not apply RITA's internal->external filter",
    )
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument(
        "--mark", action="append", default=[], help="src>dst=LABEL to tag rows"
    )
    ap.add_argument("--min-conns", type=int, default=4)
    args = ap.parse_args()
    marks = {}
    for m in args.mark:
        pair, label = m.split("=", 1)
        s, d = pair.split(">")
        marks[(s, d)] = label
    pairs, tmin, tmax = load_conn(
        args.conn_log,
        args.internal or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
        args.any,
    )
    results = []
    for (s, d), p in pairs.items():
        if len(p["ts"]) < args.min_conns:
            continue
        r = score_pair(p["ts"], p["bytes"], int(tmin), int(tmax))
        if r is None:
            continue
        ports = sorted(p["ports"].items(), key=lambda kv: -kv[1])
        r["ports"] = ",".join(f"{k}x{v}" for k, v in ports[:3])
        r["src"], r["dst"] = s, d
        r["mark"] = marks.get((s, d), "")
        results.append(r)
    results.sort(key=lambda r: (-r["score"], -r["conns"]))
    print(f"# {args.conn_log}")
    print(
        f"# dataset span {tmin:.0f}-{tmax:.0f} ({tmax - tmin:.0f} s), {len(pairs)} pairs after filter, {len(results)} scored (>= {args.min_conns} conns, >= 3 nonzero intervals)"
    )
    hdr = "rank score legacy | ts ds hist dur | tsSkewS tsMadS tsMed tsMAD | dsSkewS dsMadS dsMode small | cv bim cov cons bars | n src dst ports mark"
    print(hdr)
    # rank of every marked pair under each component (ties share the best rank)
    comps = [
        "score",
        "score_legacy",
        "ts_score",
        "ds_score",
        "hist_score",
        "dur_score",
        "ts_mad_score",
        "ts_skew_score",
        "ds_mad_score",
        "ds_skew_score",
        "cv_score",
        "bimodal_score",
        "coverage",
    ]
    for r in results:
        if r["mark"]:
            ranks = {c: 1 + sum(1 for o in results if o[c] > r[c]) for c in comps}
            print(
                f'# {r["mark"]:>10} {r["src"]}>{r["dst"]} ranks: '
                + " ".join(f"{c}={ranks[c]}" for c in comps)
            )
    for i, r in enumerate(results, 1):
        if i <= args.top or r["mark"]:
            print(
                f'{i:4d} {r["score"]:.3f} {r["score_legacy"]:.3f} | {r["ts_score"]:.3f} {r["ds_score"]:.3f} {r["hist_score"]:.3f} {r["dur_score"]:.3f} | '
                f'{r["ts_skew_score"]:.3f} {r["ts_mad_score"]:.3f} {r["ts_med"]:.0f} {r["ts_mad"]:.0f} | '
                f'{r["ds_skew_score"]:.3f} {r["ds_mad_score"]:.3f} {r["ds_mode"]} {r["ds_small"]:.3f} | '
                f'{r["cv_score"]:.3f} {r["bimodal_score"]:.3f} {r["coverage"]:.3f} {r["consistency"]:.3f} {r["bars"]:2d} | '
                f'{r["conns"]:5d} {r["src"]} {r["dst"]} {r["ports"]} {r["mark"]}'
            )


if __name__ == "__main__":
    main()
