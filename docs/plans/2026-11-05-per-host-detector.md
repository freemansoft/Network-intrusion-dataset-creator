# Plan: per-host output and a coded detector

Status: phases 1-3 implemented on branch `feature/per-host-detector` (stacked on `fix/icmp-fragments-nested-layers`). Results against the acceptance criteria are at the end.

## Why

Testing the window CSV against labeled captures (datasets/SOURCES.md) showed that whole-network totals per window catch
volumetric floods and little else. A slow scan, SSH brute force and a 40 MB upload, injected into real university
traffic, were each 0 of their windows. Each one is obvious when viewed per host. Every packet already reaches
`counts.py` with its addresses, ports and TCP flags, so the tool can keep per-host state per window without a new
process or queue.

## Phase 1: new window columns (`windows.csv`, appended after the existing columns)

| Column | Meaning | Unlocks |
| - | - | - |
| `num_syn`, `num_synack`, `num_rst`, `num_fin` | TCP packets with SYN only, SYN+ACK, RST, FIN | flood vs scan, half-open floods, closed-port scans (RST replies) |
| `max_contacted_ports_per_src`, `top_src_by_contacted_ports` | most ports any one source initiated contact with, and that source | vertical port scans, with the attacker IP |
| `max_contacted_ips_per_src`, `top_src_by_contacted_ips` | most hosts any one source initiated contact with | horizontal sweeps |
| `max_contacting_ips_per_dst`, `top_dst_by_contacting_ips` | most sources initiating contact with any one destination | spoofed SYN floods, DDoS, with the victim IP |
| `top_src_by_packets`, `top_dst_by_packets` | busiest sender and receiver | names the host behind a volume alert (for example an ACK flood) |
| `entropy_src_ip`, `entropy_dst_ip`, `entropy_dst_port` | Shannon entropy (bits) of the packet distribution | distribution shifts that barely move volume |
| `label` | names of labeled attacks overlapping the window (`--labels`) | turns the tool into the labeled-dataset builder it was designed as |

## Phase 2: per-host output (`--hostfile hosts.csv`)

One row per (window, host) for home hosts (`--home-net`, default RFC 1918 + fc00::/7) that sent or received traffic,
plus the top `--host-topk` (default 20) external hosts by fan-out and packets.

Columns: `window_start_time`, `window_end_time`, `host`, `is_home`, `phttps://www.activecountermeasures.com/malware-of-the-day-backoff/kts_out`, `pkts_in`, `bytes_out`, `bytes_in`,
`upload_bytes_ext` and `download_bytes_ext` (client-side transfer with non-home addresses: the host's port is the higher
one, so a server's responses are not counted as uploads), `contacted_ips`, `contacted_ports`, `contacting_ips`,
`new_contacted_ips` and `new_contacted_ports` (not contacted by this host within `--novelty-horizon`, default 600 s),
`syn_out`, `synack_in`, `rst_in`, `syn_in`, `auth_syn_out` and `auth_syn_in` (SYNs to or from remote-login ports
21, 22, 23, 3389, 5900), `icmp_unreach_in`, `label`.

"Contacted" counts only contacts the host initiated: TCP SYN, UDP to a port below 1024 from a higher port, ICMP echo
request, ARP request. Without this, servers and scan victims (replying to ephemeral ports) look like scanners, and UDP
between two high ports (replies, P2P) floods the novelty counts.

## Phase 3: offline detector (`detect.py windows.csv hosts.csv -o alerts.jsonl`)

- Rules with absolute, attack-defined thresholds (configurable):
  - SYN flood: half-open `num_syn - num_synack` high with `max_src_ips_per_dst` high.
  - Fast scan: `max_dst_ports_per_src` or `max_dst_ips_per_src` above a threshold.
  - Per host over a rolling window (default 10 min):
    - slow scan: cumulative `new_dst_ports` / `new_dst_ips` above a threshold;
    - failed-connection pressure: cumulative `syn_out - synack_in`;
    - login brute force: cumulative `auth_syn_out` to one host;
    - upload-heavy external transfer: `bytes_out_ext` well above `bytes_in_ext` and above a size floor.
- Volume anomalies: rolling per-sensor robust baseline (median/MAD of log values over the trailing hour, alerted
  windows excluded). Each named column is scored separately with a floor on the spread, the change must be material
  (packets or bytes above the median), and a column alerts after 2 consecutive windows or 1 extreme window. The baseline is never imported from another capture.
- Output: JSONL alerts (`ts_start`, `ts_end`, `kind`, `host`, `observed`, `threshold`, `baseline`, `detail`), merged
  into incidents by kind and host.
- No supervised model: the public datasets' artifacts would be learned instead of the attacks.

## Acceptance criteria (labeled captures in `datasets/`)

1. Injected CTU-5 capture: fast port scan, slow scan, SYN flood, SSH brute force and bulk upload each raise an alert
   naming the right host within 10 minutes of onset.
2. False alarms: at most 1% of windows alerted on the un-injected CTU-5 capture and at most 0.5% on DARPA 1999 week 5
   Monday inside (15,835 windows).
3. Still catches the floods: IoT-23 floods (4), CTU-11 ICMP DDoS, LLDoS DDoS, DARPA neptune.
4. Tests for each new column, the host output and each rule; `pytest` passes.

## Deferred

Planned in `docs/plans/2026-11-05-deferred-detection.md`, validated on public captures only.

- C2 beaconing (needs per-destination contact timing; consider a contacts output or RITA).
- DNS tunnelling (needs payload; the CTU captures are header-only).
- Hour-of-day baselines (need days of capture from one sensor).
- LLM triage of alerts (annotate only, never create alerts; see the analysis notes).

## Results (2026-11-05)

| Criterion | Result |
| - | - |
| 1. Injected attacks detected with the right host within 10 min | Met for fast port scan, slow scan, SYN flood, SSH brute force and bulk upload (all within 11 s). DNS tunnel and beacon are deferred, as planned. |
| 2a. ≤1% alerted windows on un-injected CTU-5 | Met (0.83%) with suppressions learned from all of CTU-11 minus its labeled hosts. Without suppressions, 93%: a few always-noisy background hosts alert in every window. One of them (147.32.84.118) has failed-connection counts in the same range as the Virut bot, so no absolute threshold separates them. |
| 2b. ≤0.5% on DARPA 1999 week 5 Monday inside | Not met: 0.80%. 92 of the 127 windows are a DNS storm from hume (172.16.112.100), a misconfiguration the dataset documents; excluding it gives 0.22%. No clean capture of that network was used for suppressions. |
| 3. Floods still caught | Met: IoT-23 (4/4), CTU-11 ICMP DDoS, LLDoS ACK flood (single 5 s window), DARPA neptune and udpstorm. |
| 4. Tests | Met: 61 passing. |

Also found during testing:
- Suppressions learned from 8-10 minutes of traffic catch noisy hosts at a quiet moment and under-estimate their peaks.
  Learn from a full capture (hours to days), excluding hosts in known incidents.
- CTU-11 tested with suppressions learned from the 30-minute CTU-5 capture still alerts on 73% of windows. Hosts that
  were quiet on the learning day (147.32.84.59 failed connections, 147.32.84.179 remote-login SYNs) alert throughout.
  CTU labels background hosts as unknown, not benign, so some of these may be real.
