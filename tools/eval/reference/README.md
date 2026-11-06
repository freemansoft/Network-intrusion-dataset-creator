# Reference: RITA's beacon formula

A comparison baseline, not part of the detector. Nothing in `main.py`, `detect.py` or the rest of `tools/eval/`
imports or runs it.

[RITA](https://github.com/activecm/rita) (Real Intelligence Threat Analytics, from Active Countermeasures, who also
published the beacon captures in `datasets/acm-*`) is the most widely used free beacon detector. It reads Zeek's
`conn.log` and scores every (internal source, external destination) pair. Running RITA itself needs its database, so
`rita_beacon.py` reimplements the v5 beacon score from its source (`analysis/beacons.go`, with the legacy v4 variant
printed alongside): interval skew and MAD, size skew and MAD, a 24-bin connection histogram scored by coefficient of
variation or a bimodal fit, and a duration score, weighted equally. The docstring states every formula.

It exists to answer one question for each capture: at what rank does RITA's formula put the true C2 pair? Those
ranks are the bar the project's own beacon scorer has to clear (`docs/plans/2026-11-06-connection-log.md`, step 2 and
"Keep or archive").

## Running

Needs [Zeek](https://zeek.org) on the PATH (`brew install zeek`; 9.0.1 was used). Zeek is needed only here.

```bash
sh tools/eval/reference/run.sh             # every beacon capture present in datasets/
sh tools/eval/reference/run.sh posh_24hr   # one capture
```

Zeek's logs go to `eval-runs/reference/<capture>/` and are reused on later runs; the full ranking, with each
component's rank for every marked pair, goes to `eval-runs/reference/<capture>.txt`. The scorer can also be run on any
`conn.log` directly: `python3 -I tools/eval/reference/rita_beacon.py conn.log --internal 10.0.0.0/24 --mark 'SRC>DST=C2'`.

## Results (2026-11-05, Zeek 9.0.1)

| Capture | C2 rank | Beaten by |
| - | - | - |
| Backoff 24 h | 1 (0.989) | nothing, but the 900 s Microsoft pair is 0.986 and wins on timing alone |
| Backoff 1 h | 1 | |
| PoshC2 24 h | 18 (0.992) | 17 benign pairs at a perfect 1.000: a 300 s poll and 16 burst pairs, all four decoys among them |
| PoshC2 1 h | 1 | |
| IoT-23 34-1 Mirai | 9 (0.640) | eight NTP servers; 5,000 failed SYN retries wreck the C2's interval statistics |

CTU-13 is left out: its captures are truncated to the headers and Zeek cannot reassemble them, so the scores mean
nothing.
