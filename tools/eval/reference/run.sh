#!/bin/sh
# Runs Zeek and the RITA-formula reference scorer on the beacon captures. Output goes to
# eval-runs/reference/<capture>/ (Zeek's logs) and eval-runs/reference/<capture>.txt (the ranking).
# Zeek's logs are kept, so a second run only re-scores. Needs zeek on the PATH; see README.md.
#
#   sh tools/eval/reference/run.sh            # every capture below that is present
#   sh tools/eval/reference/run.sh posh_24hr  # one capture
set -e
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
OUT="$REPO/eval-runs/reference"
SCORER="$REPO/tools/eval/reference/rita_beacon.py"
D="$REPO/datasets"

BACKOFF='--mark 192.168.99.55>157.245.128.27=C2 --mark 192.168.99.55>52.184.216.174=DECOY --mark 192.168.99.55>52.184.216.246=DECOY'
POSH='--mark 10.0.0.62>157.230.93.100=C2 --mark 10.0.0.62>68.64.13.6=DECOY --mark 10.0.0.62>68.64.25.254=DECOY --mark 10.0.0.62>173.199.15.254=DECOY --mark 10.0.0.62>78.108.118.250=DECOY'
MIRAI='--mark 192.168.1.195>185.244.25.235=C2'

# name|pcap|scorer arguments
CAPTURES="backoff_24hr|$D/acm-backoff/backoff_24hr.pcap|$BACKOFF
backoff_1hr|$D/acm-backoff/backoff_1hr.pcap|$BACKOFF
posh_24hr|$D/acm-poshc2/posh_stealthy_24hr.pcap|$POSH
posh_1hr|$D/acm-poshc2/posh_stealthy_1hr.pcap|$POSH
mirai|$D/iot23-34-1-mirai/2018-12-21-15-50-14-192.168.1.195.pcap|$MIRAI"

echo "$CAPTURES" | while IFS='|' read -r name pcap marks; do
    if [ -n "$1" ] && [ "$1" != "$name" ]; then
        continue
    fi
    if [ ! -f "$pcap" ]; then
        echo "$name: missing $pcap (see datasets/SOURCES.md)"
        continue
    fi
    mkdir -p "$OUT/$name"
    if [ ! -f "$OUT/$name/conn.log" ]; then
        # -C: ignore checksums (offloaded in these captures); TSV logs, which the scorer reads
        (cd "$OUT/$name" && zeek -C -r "$pcap" LogAscii::use_json=F > zeek.out 2>&1)
    fi
    # shellcheck disable=SC2086
    python3 -I "$SCORER" "$OUT/$name/conn.log" $marks > "$OUT/$name.txt"
    printf '%-13s ' "$name"
    grep -E '^# +C2 ' "$OUT/$name.txt" | sed -E 's/.* ranks: score=([0-9]+).*/C2 rank \1/'
done
