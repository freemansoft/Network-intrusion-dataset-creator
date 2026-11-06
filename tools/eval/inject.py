#!/usr/bin/env python3
"""Inject the synthetic attacks from gen_attacks.py into a cut of a benign capture.

    python3 tools/eval/inject.py SOURCE.pcap OUT.pcap --cut START END --attack-start EPOCH \
        --victim IP --attacker IP [--headers-only] [--python /path/to/python-with-scapy]

1. editcap cuts SOURCE to [START, END) epoch seconds (the benign background).
2. gen_attacks.py writes the attacks starting at --attack-start, using --python (an interpreter
   that has scapy; default: this one). Labels go next to OUT as OUT-labels.csv.
3. With --headers-only the attack packets are truncated like a headers-only capture (TCP to
   54 bytes, UDP to 42), so they look like the CTU-13 background they are mixed into.
4. mergecap merges background and attacks into OUT (classic pcap).

The Wireshark tools (editcap, mergecap, tshark) must be on the PATH or in --wireshark-dir.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def tool(name, wireshark_dir):
    path = shutil.which(name) or (wireshark_dir and os.path.join(wireshark_dir, name))
    if not path or not os.path.exists(path):
        sys.exit(f"{name} not found; add it to the PATH or pass --wireshark-dir")
    return path


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("source")
    parser.add_argument("out")
    parser.add_argument(
        "--cut", nargs=2, type=float, metavar=("START", "END"), required=True
    )
    parser.add_argument("--attack-start", type=float, required=True)
    parser.add_argument("--victim", required=True)
    parser.add_argument("--attacker", required=True)
    parser.add_argument("--headers-only", action="store_true")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--wireshark-dir", default="/Applications/Wireshark.app/Contents/MacOS"
    )
    args = parser.parse_args(argv)

    editcap = tool("editcap", args.wireshark_dir)
    mergecap = tool("mergecap", args.wireshark_dir)
    tshark = tool("tshark", args.wireshark_dir)
    labels = os.path.splitext(args.out)[0] + "-labels.csv"
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        background = os.path.join(tmp, "background.pcap")
        attacks = os.path.join(tmp, "attacks.pcap")
        start, end = args.cut
        run(
            [
                editcap,
                "-F",
                "pcap",
                "-A",
                f"{start:.6f}",
                "-B",
                f"{end:.6f}",
                args.source,
                background,
            ]
        )
        run(
            [
                args.python,
                os.path.join(HERE, "gen_attacks.py"),
                attacks,
                str(args.attack_start),
                labels,
                "--victim",
                args.victim,
                "--attacker",
                args.attacker,
            ]
        )
        parts = [attacks]
        if args.headers_only:
            parts = []
            for proto, snaplen in (("tcp", 54), ("udp", 42)):
                full = os.path.join(tmp, f"{proto}.pcap")
                cut = os.path.join(tmp, f"{proto}-headers.pcap")
                run([tshark, "-r", attacks, "-Y", proto, "-F", "pcap", "-w", full])
                run([editcap, "-s", str(snaplen), full, cut])
                parts.append(cut)
        run([mergecap, "-F", "pcap", "-w", args.out, background] + parts)
    print(f"wrote {args.out} and {labels}")


if __name__ == "__main__":
    main()
