# Evaluation harness

Runs the pipeline and the detector on the labeled captures in `datasets/` and scores the alerts
against the labels. No live traffic is available to this project, so these captures are both the
development data and the test data; every change to `detect.py` or the per-host columns is judged
here.

| File | Purpose |
| - | - |
| `datasets.yaml` | one entry per dataset: pcaps, home net, label file, optional injection recipe |
| `labels/*.csv` | ground truth, `label,start,end,ips` (epoch seconds; attacker and victim IPs); derived from the sources in `datasets/SOURCES.md` |
| `run.py` | `main.py` per pcap (in parallel), `detect.py` over all of them, `score.py` against the labels |
| `score.py` | detection per label (with time to first alert) and the false-alarm window rate |
| `inject.py` | cuts a benign stretch of a capture and merges in the synthetic attacks |
| `gen_attacks.py` | the synthetic attacks (scapy): scans, SYN flood, SSH brute force, DNS tunnel, beacon, bulk upload |

```bash
python3 tools/eval/run.py --list
python3 tools/eval/run.py ctu5
python3 tools/eval/run.py darpa-attackfree --learn-suppressions eval-runs/darpa-supp.csv
python3 tools/eval/run.py darpa99 --suppress eval-runs/darpa-supp.csv
python3 tools/eval/run.py injected --python ~/venv-scapy/bin/python   # builds datasets/injected-ctu5/ first
```

Outputs: `eval-runs/<dataset>/<pcap>/windows.csv`, `hosts.csv`, `console.txt` and the logs, then
`eval-runs/<dataset>/alerts.jsonl`, `incidents.jsonl` and `score.txt`. Existing `windows.csv` files
are reused; pass `--recapture` after changing the pipeline.

Scoring: an alert matches a label when its host is one of the label's IPs (any host when the label
names none) and its window starts between 10 s before the label and `--window-after` (600 s) after
it ends. A window with an alert that matches no label is a false-alarm window. The unmatched alerts
are listed by kind and host; each one should be explained (a documented background quirk, an
unlabeled real event) or fixed, not tuned away.

Several pcaps in one dataset are read by `detect.py` as one run in time order, so they must be
consecutive captures from the same sensor. Two sensors of the same period (DARPA inside and
outside) are separate datasets.
