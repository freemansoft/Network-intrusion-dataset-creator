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
        if not key.startswith(("window_", "top_", "entropy_")) and key != "label"
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


def test_host_file_and_labels(tmp_path):
    shutil.copy(os.path.join(REPO, "logging_config.yaml"), tmp_path)
    # icmp_mix.pcap frames are stamped 1600000000.00 to 1600000000.07
    (tmp_path / "labels.csv").write_text(
        "label,start,end,ips\nprobe,1600000000.0,1600000001.0,10.0.0.3\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            os.path.join(REPO, "main.py"),
            "-s",
            os.path.join(FIXTURES, "icmp_mix.pcap"),
            "-wt",
            "5000",
            "-o",
            "out.csv",
            "-oh",
            "hosts.csv",
            "--home-net",
            "10.0.0.0/8",
            "--labels",
            "labels.csv",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    with open(tmp_path / "out.csv") as f:
        windows = list(csv.DictReader(f))
    with open(tmp_path / "hosts.csv") as f:
        hosts = {row["host"]: row for row in csv.DictReader(f)}
    assert windows[0]["label"] == "probe"
    assert windows[0]["num_syn"] == "1"
    assert hosts["10.0.0.3"]["label"] == "probe"
    assert hosts["10.0.0.1"]["label"] == ""
    assert hosts["10.0.0.1"]["is_home"] == "1"
    # 10.0.0.3 sent the two ICMP port-unreachables to 10.0.0.2
    assert hosts["10.0.0.2"]["icmp_unreach_in"] == "2"
    # 10.0.0.1 initiated the echo request and the SYN
    assert hosts["10.0.0.1"]["contacted_ports"] == "1"
    assert hosts["10.0.0.1"]["syn_out"] == "1"


def test_bad_labels_path_exits_without_starting_stages(tmp_path):
    shutil.copy(os.path.join(REPO, "logging_config.yaml"), tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            os.path.join(REPO, "main.py"),
            "-s",
            os.path.join(FIXTURES, "icmp_mix.pcap"),
            "-wt",
            "5000",
            "--labels",
            "missing.csv",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
