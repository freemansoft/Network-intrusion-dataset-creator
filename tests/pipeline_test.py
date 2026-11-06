# end-to-end tests: run main.py on the fixture captures in tests/fixtures (needs tshark)
# The fixtures are built by tests/fixtures/make_fixtures.py; see its docstring for what each frame is.

import csv
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO, "tests", "fixtures")

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark is not on the PATH"
)


def run_pipeline(tmp_path, capture):
    shutil.copy(os.path.join(REPO, "logging_config.yaml"), tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            os.path.join(REPO, "main.py"),
            "-s",
            os.path.join(FIXTURES, capture),
            "-wt",
            "5000",
            "-o",
            "out.csv",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    with open(tmp_path / "out.csv") as f:
        rows = list(csv.DictReader(f))
    totals = {
        key: sum(int(row[key]) for row in rows)
        for key in rows[0]
        if not key.startswith("window_")
    }
    errors = (tmp_path / "errors.log").read_text()
    info = (tmp_path / "info.log").read_text()
    return result, totals, errors, info


def test_icmp_mix_counts_every_packet(tmp_path):
    result, totals, errors, info = run_pipeline(tmp_path, "icmp_mix.pcap")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Traceback" not in errors
    assert "recognized=8 unrecognized=0" in info
    assert totals["num_packets"] == 8
    # 2 echo, 2 unreachable quoting UDP/TCP, ICMPv6 echo + neighbor solicitation
    assert totals["num_icmp"] == 6
    assert totals["num_icmp_echo"] == 3
    assert totals["num_icmp_unreach"] == 2
    assert totals["num_igmp"] == 1  # ICMPv6 used to be counted here too
    assert totals["num_tcp"] == 1  # the SYN; quoted TCP headers are not TCP packets
    assert totals["num_udp"] == 0  # quoted UDP headers are not UDP packets


def test_fragments_are_all_counted(tmp_path):
    result, totals, errors, info = run_pipeline(tmp_path, "fragments.pcap")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "recognized=5 unrecognized=0" in info
    assert totals["num_packets"] == 5
    assert totals["num_udp"] == 2  # one reassembled datagram each for IPv4 and IPv6
    # 2 earlier IPv4 fragments + 1 earlier IPv6 fragment
    assert totals["num_ip_fragments"] == 3
    assert totals["ip_fragment_frame_length"] == 1234 + 1234 + 1294
