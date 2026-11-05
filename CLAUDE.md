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

# Tests (only tumblingwindow.py is covered)
python3 -m pytest
python3 -m pytest tests/tumblingwindow_test.py::test_inside_window
```

- `tshark` (Wireshark CLI) must be on the PATH, or passed in with `-t`.
- Code is formatted with `black`. There is no linter config.
- `*.pcap`, `*.pcapng`, `*.cap`, `*.csv` and `*.log` are gitignored. The sample captures in the repo root exist only locally (more are at https://wiki.wireshark.org/SampleCaptures); `sample_output/*.csv` is the only committed output.

## Architecture

The program is a 4-process pipeline plus a `tshark` subprocess. The processes communicate through module-level `multiprocessing.Queue`s defined in `queues.py`:

```
tshark -T ek ─pipe─> PacketCapture ─sharedQ─> PacketAnalyse ─serviceQ─> ServiceIdentity ─timesQ─> TimesAndCounts ─> CSV
                     capture.py               detectors.py               services.py               counts.py
```

- **Fork only.** `main.py` forces `mp.set_start_method("fork")`. The queues are module globals that child processes inherit, so `spawn` (the macOS default) breaks the pipeline. Don't add designs that rely on pickling state into children.
- **Shutdown.** Each stage forwards an empty `{}`/`[]` downstream when its input ends, then exits. Any new stage must pass this sentinel along, or later stages will never stop.
- **Message shape.** Starting at `PacketAnalyse`, each queue message is a dict keyed by the constants in `transitkeys.py` (`Id`, `Packet`, `Protocol`, `Services`). `Id` is a node-pair key with src and dst sorted, so both directions of a conversation map to the same pair.
- **Field names.** `capture.py` rewrites tshark's EK labels back into dotted Wireshark names (`ip_src` → `ip.src`, etc.). Detectors and services look up fields such as `packet_dict["frame.time_epoch"]` and `ip.len` by those dotted names.
- **Protocol detection** (`detectors.py`). `find_ip` dispatches to `find_tcp`, `find_udp` and `find_igmp`. Anything that isn't IP goes to `find_non_ip`, which handles only ARP. Unrecognized packets are dropped but counted in `dvar.datasetSummary` (including the set of unanalyzed IP protocol numbers), which is logged once at exit and not written anywhere else.
- **Service detection** (`services.py`). Services are identified by the presence of a field or port. One packet can match several services (for example, SSDP is also counted as HTTP).
- **Windowing.** `tumblingwindow.TumblingWindow` decides window boundaries. Windows are non-overlapping and bounded by time (msec), packet count, or both; the window start is inclusive and the end is exclusive. `counts.py` flushes empty windows when time jumps forward past them.

### Adding a CSV column

A new column must be added in three places:
1. A default-valued attribute on `cvar.windowcounts`
2. The `fieldnames` list in `counts.TimesAndCounts`, which sets the column order
3. The accumulation logic in `counts.py` (`count_services` / `analyze_update_window`)

New service or protocol counts also need a detector in `services.py` or `detectors.py`. The README's sample CSV table and "Issues" list document current column semantics and known gaps; update them when column behavior changes.

## Claude Code plugins

Project plugins (`superpowers`, `skill-creator`, `security-guidance`, `claude-md-management`) are declared in `.claude/settings.json`; one-time install commands and the reason for leaving out a `SessionStart` install hook are in the README's "Claude Code plugins" section. Sessions signed in with a claude.ai account may also see `anthropic-skills:skill-creator`, which overlaps the project's `skill-creator`. `.gitignore` excludes `*.json`, so `.claude/settings.json` is un-ignored explicitly.

## Logging

Logging is configured by `logging_config.yaml` (loaded by `loggingconfig.load_logging()`, which tests also call). Each run overwrites `info.log`, `errors.log` and `debug.log` in the working directory. Per-packet detail is logged at `debug`.
