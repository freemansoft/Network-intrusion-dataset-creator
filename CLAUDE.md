# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pip3 install -r requirements.txt          # pyyaml, pytest (unpinned)

# Run against a pcap file (one of -wt / -wp is required; both may be given)
python3 main.py -s Razi_15012021.pcap -wt 5000 -o dataset.csv   # 5000 msec time windows
python3 main.py -s Razi_15012021.pcap -wp 100                    # 100-packet windows

# Live capture (may need sudo for promiscuous mode)
python3 main.py -i eth0 -l 120 -wt 5000

# Per-host rows, home network, labels; then the offline detector
python3 main.py -s capture.pcap -wt 5000 -o windows.csv -oh hosts.csv --home-net 10.0.0.0/8 --labels labels.csv
python3 detect.py windows.csv hosts.csv -o alerts.jsonl --incidents incidents.jsonl [--set name=value]

# Tests (pipeline_test.py runs main.py on tests/fixtures/*.pcap and is skipped without tshark)
python3 -m pytest
python3 -m pytest tests/tumblingwindow_test.py::test_inside_window

# Regenerate the fixture captures (needs scapy, which is not in requirements.txt)
python3 tests/fixtures/make_fixtures.py
```

- `tshark` (Wireshark CLI) must be on the PATH, or passed in with `-t`.
- Code is formatted with `black`. There is no linter config.
- `*.pcap`, `*.pcapng`, `*.cap`, `*.csv` and `*.log` are gitignored. The sample captures in the repo root exist only locally (more are at https://wiki.wireshark.org/SampleCaptures); `sample_output/*.csv` is the only committed output. `tests/fixtures/*.pcap` is un-ignored explicitly.
- `datasets/` holds downloaded labeled intrusion captures and is gitignored. `datasets/SOURCES.md` (committed) records each file's URL, SHA-256, label source and attack intervals.

## Architecture

The program is a 4-process pipeline plus a `tshark` subprocess. The processes communicate through module-level `multiprocessing.Queue`s defined in `queues.py`:

```
tshark -T ek ─pipe─> PacketCapture ─sharedQ─> PacketAnalyse ─serviceQ─> ServiceIdentity ─timesQ─> TimesAndCounts ─> CSV
                     capture.py               detectors.py               services.py               counts.py
```

- **Fork only.** `main.py` forces `mp.set_start_method("fork")`. The queues are module globals that child processes inherit, so `spawn` (the macOS default) breaks the pipeline. Don't add designs that rely on pickling state into children.
- **Shutdown.** Each stage forwards an empty `{}`/`[]` downstream when its input ends, then exits. Any new stage must pass this sentinel along, or later stages will never stop. Each stage's `run()` also forwards the sentinel and re-raises if it throws, and `main.py` stops the remaining stages and exits 1 when any stage exits non-zero. Keep both when adding a stage.
- **Message shape.** Starting at `PacketAnalyse`, each queue message is a dict keyed by the constants in `transitkeys.py` (`Id`, `Packet`, `Protocol`, `Services`). `Id` is a node-pair key with src and dst sorted, so both directions of a conversation map to the same pair.
- **Field names.** `capture.py` rewrites tshark's EK labels back into dotted Wireshark names (`ip_src` → `ip.src`, etc.). Detectors and services look up fields such as `packet_dict["frame.time_epoch"]` and `ip.len` by those dotted names. The renaming is ad hoc, so check what `PacketCapture.unwrap` produces before matching a new field (the IPv6 fragment offset comes out as `ipv6_fraghdr.offset`). When a field appears in several layers, the outermost wins: an ICMP error nests the quoted IP/UDP header inside its `icmp` object, and letting that overwrite the outer header misclassified the packet.
- **Protocol detection** (`detectors.py`). `find_ip` tries `find_icmp` (ICMP and ICMPv6) and `find_ip_fragment` first, then `find_tcp`, `find_udp` and `find_igmp` (IPv4 only). The order matters: ICMP errors carry quoted TCP/UDP ports, and non-final fragments have an IP protocol number but no transport header (tshark attaches the reassembled datagram to the final fragment, which is counted under its own protocol). Anything that isn't IP goes to `find_non_ip`, which handles only ARP. Unrecognized packets are dropped but counted in `dvar.datasetSummary` (including the set of unanalyzed IP protocol numbers), which is logged once at exit and not written anywhere else.
- **Service detection** (`services.py`). Services are identified by the presence of a field or port. One packet can match several services (for example, SSDP is also counted as HTTP).
- **Per-host state** (`hoststats.py`). Each window owns a `WindowHosts` (`cvar.windowcounts.host_window`) that `analyze_update_window` feeds every packet. It produces the fan-out/entropy columns of `windows.csv` and the rows of `hosts.csv`. Cross-window novelty ("contacted for the first time within the horizon") lives in `Novelty` on `TimesAndCounts`. "Contacted" means contact the host initiated (TCP SYN, UDP to a port below 1024, ICMP echo request, ARP request); keep that rule when adding per-host columns, or servers and scan victims look like scanners.
- **Detector** (`detect.py`). Offline and stdlib-only: reads `windows.csv` and `hosts.csv` in time order and writes JSONL alerts. Thresholds live in `detect.THRESHOLDS`. Plan, rationale and acceptance criteria: `docs/plans/2026-11-05-per-host-detector.md`.
- **Windowing.** `tumblingwindow.TumblingWindow` decides window boundaries. Windows are non-overlapping and bounded by time (msec), packet count, or both; the window start is inclusive and the end is exclusive. `counts.py` flushes empty windows when time jumps forward past them.

### Adding a CSV column

A new column must be added in three places:
1. A default-valued attribute on `cvar.windowcounts`
2. The `fieldnames` list in `counts.TimesAndCounts`, which sets the column order
3. The accumulation logic in `counts.py` (`count_services` / `analyze_update_window`)

Window columns computed from per-host state are returned by `WindowHosts.window_columns()` instead of step 3. String columns must be set explicitly in `write_window`, because the CSV writer's `restval` would write `"0"`. A per-host column goes in `hoststats.HOST_FIELDNAMES`, `HostStats.__slots__`, `WindowHosts.update` and `host_rows`.

New service or protocol counts also need a detector in `services.py` or `detectors.py`. The README's sample CSV table and "Issues" list document current column semantics and known gaps; update them when column behavior changes.

## Claude Code plugins

Project plugins (`superpowers`, `skill-creator`, `security-guidance`, `claude-md-management`) are declared in `.claude/settings.json`; one-time install commands and the reason for leaving out a `SessionStart` install hook are in the README's "Claude Code plugins" section. Sessions signed in with a claude.ai account may also see `anthropic-skills:skill-creator`, which overlaps the project's `skill-creator`. `.gitignore` excludes `*.json`, so `.claude/settings.json` is un-ignored explicitly.

## Logging

Logging is configured by `logging_config.yaml` (loaded by `loggingconfig.load_logging()`, which tests also call). Each run overwrites `info.log`, `errors.log` and `debug.log` in the working directory. Per-packet detail is logged at `debug`.
