#!/usr/bin/env python3
"""Run main.py and detect.py on a named dataset and score the alerts against its labels.

    python3 tools/eval/run.py --list
    python3 tools/eval/run.py darpa99
    python3 tools/eval/run.py darpa-attackfree --learn-suppressions darpa-supp.csv
    python3 tools/eval/run.py darpa99 --suppress darpa-supp.csv --set volume_z=8

Datasets are declared in tools/eval/datasets.yaml. Output goes to <runs_dir>/<dataset>/
(eval-runs/, gitignored): one directory per pcap with windows.csv, hosts.csv, console.txt and the
logs, then alerts.jsonl, incidents.jsonl and score.txt at the top. A pcap whose windows.csv
already exists is not captured again unless --recapture is given, so detector changes can be
re-scored in seconds. --jobs captures that many pcaps at once (each main.py run uses about 5
cores).
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import score as scoring  # noqa: E402


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def repo_path(path):
    return path if os.path.isabs(path) else os.path.join(REPO, path)


def pcaps_of(dataset):
    paths = []
    for pattern in dataset["pcaps"]:
        found = sorted(glob.glob(repo_path(pattern)))
        paths += found or [repo_path(pattern)]
    return paths


def build_injected(dataset, python):
    spec = dataset["inject"]
    out = pcaps_of(dataset)[0]
    if os.path.exists(out):
        return
    cmd = [
        sys.executable,
        os.path.join(HERE, "inject.py"),
        repo_path(spec["source"]),
        out,
        "--cut",
        str(spec["cut"][0]),
        str(spec["cut"][1]),
        "--attack-start",
        str(spec["attack_start"]),
        "--victim",
        spec["victim"],
        "--attacker",
        spec["attacker"],
        "--python",
        python,
    ]
    if spec.get("headers_only"):
        cmd.append("--headers-only")
    subprocess.run(cmd, check=True)


def capture(pcap, run_dir, dataset, recapture):
    """Run main.py on one pcap into run_dir; return (pcap, exit code, seconds, summary)."""
    windows = os.path.join(run_dir, "windows.csv")
    if os.path.exists(windows) and not recapture:
        return pcap, 0, 0, "kept"
    os.makedirs(run_dir, exist_ok=True)
    shutil.copy(os.path.join(REPO, "logging_config.yaml"), run_dir)
    cmd = [
        sys.executable,
        os.path.join(REPO, "main.py"),
        "-s",
        pcap,
        "-wt",
        str(dataset.get("window_msec", 5000)),
        "-o",
        "windows.csv",
        "-oh",
        "hosts.csv",
        "--home-net",
        dataset["home_net"],
    ]
    if dataset.get("labels"):
        cmd += ["--labels", repo_path(dataset["labels"])]
    started = time.time()
    with open(os.path.join(run_dir, "console.txt"), "w") as console:
        result = subprocess.run(
            cmd, cwd=run_dir, stdout=console, stderr=subprocess.STDOUT
        )
    summary = ""
    info = os.path.join(run_dir, "info.log")
    if os.path.exists(info):
        with open(info) as f:
            for line in f:
                found = re.search(r"recognized=\d+ unrecognized=\d+ pps=[\d.]+", line)
                if found:
                    summary = found.group(0)
                    skipped = re.search(r"'not_analyzed_ip': (\{[^}]*\})", line)
                    if skipped and skipped.group(1) != "set()":
                        summary += " not_analyzed_ip=" + skipped.group(1)
    return pcap, result.returncode, int(time.time() - started), summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("dataset", nargs="?")
    parser.add_argument(
        "--list", action="store_true", help="list the datasets and exit"
    )
    parser.add_argument("--config", default=os.path.join(HERE, "datasets.yaml"))
    parser.add_argument(
        "--jobs", type=int, default=2, help="pcaps captured at once [2]"
    )
    parser.add_argument(
        "--recapture",
        action="store_true",
        help="re-run main.py even if windows.csv exists",
    )
    parser.add_argument(
        "--window-after",
        type=float,
        default=600,
        help="seconds after a label an alert still counts",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter with scapy, for injected datasets",
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="detect.py threshold",
    )
    parser.add_argument("--learn-suppressions", metavar="OUT")
    parser.add_argument("--learn-until", metavar="EPOCH")
    parser.add_argument("--learn-exclude", metavar="IPS")
    parser.add_argument("--suppress", metavar="FILE")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    datasets = config["datasets"]
    if args.list or not args.dataset:
        for name, d in datasets.items():
            print(f"{name:18s} {len(pcaps_of(d))} pcap(s)  {d.get('about', '')}")
        return
    if args.dataset not in datasets:
        parser.error(f"unknown dataset {args.dataset}; known: {', '.join(datasets)}")
    dataset = datasets[args.dataset]
    if "inject" in dataset:
        build_injected(dataset, args.python)
    pcaps = pcaps_of(dataset)
    missing = [p for p in pcaps if not os.path.exists(p)]
    if missing:
        sys.exit(
            "missing capture(s), see datasets/SOURCES.md:\n  " + "\n  ".join(missing)
        )

    out_dir = os.path.join(repo_path(config.get("runs_dir", "eval-runs")), args.dataset)
    run_dirs = [
        os.path.join(out_dir, os.path.splitext(os.path.basename(p))[0]) for p in pcaps
    ]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(
            pool.map(
                lambda pr: capture(pr[0], pr[1], dataset, args.recapture),
                zip(pcaps, run_dirs),
            )
        )
    failed = False
    for pcap, code, secs, summary in results:
        print(f"{os.path.basename(pcap):45s} exit={code} secs={secs:5d} {summary}")
        failed |= code != 0
    if failed:
        sys.exit("a capture failed; see its console.txt and errors.log")

    windows = [os.path.join(d, "windows.csv") for d in run_dirs]
    hosts = [os.path.join(d, "hosts.csv") for d in run_dirs]
    alerts = os.path.join(out_dir, "alerts.jsonl")
    cmd = [sys.executable, os.path.join(REPO, "detect.py")] + windows + hosts
    cmd += ["-o", alerts, "--incidents", os.path.join(out_dir, "incidents.jsonl")]
    for item in args.set:
        cmd += ["--set", item]
    for flag in ("learn_suppressions", "learn_until", "learn_exclude", "suppress"):
        value = getattr(args, flag)
        if value:
            cmd += ["--" + flag.replace("_", "-"), value]
    print(
        "+",
        " ".join(os.path.relpath(c, REPO) if os.path.isabs(c) else c for c in cmd[1:]),
    )
    subprocess.run(cmd, check=True)

    if dataset.get("labels"):
        text, _ = scoring.score(
            alerts, repo_path(dataset["labels"]), windows, args.window_after
        )
        print(text)
        with open(os.path.join(out_dir, "score.txt"), "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
