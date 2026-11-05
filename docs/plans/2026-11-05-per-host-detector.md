# Plan: per-host output and a coded detector

Status: in progress, branch `feature/per-host-detector`, stacked on `fix/icmp-fragments-nested-layers`.

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
| `max_dst_ports_per_src`, `top_src_by_dst_ports` | largest distinct destination-port count of any source, and that source | vertical port scans, with the attacker IP |
| `max_dst_ips_per_src`, `top_src_by_dst_ips` | largest distinct destination-IP count of any source | horizontal sweeps |
| `max_src_ips_per_dst`, `top_dst_by_src_ips` | largest distinct source-IP count of any destination | spoofed floods, DDoS, with the victim IP |
| `entropy_src_ip`, `entropy_dst_ip`, `entropy_dst_port` | Shannon entropy (bits) of the packet distribution | distribution shifts that barely move volume |
| `label` | names of labeled attacks overlapping the window (`--labels`) | turns the tool into the labeled-dataset builder it was designed as |

## Phase 2: per-host output (`--hostfile hosts.csv`)

One row per (window, host) for home hosts (`--home-net`, default RFC 1918 + fc00::/7) that sent or received traffic,
plus the top `--host-topk` (default 20) external hosts by fan-out and packets.

Columns: `window_start_time`, `window_end_time`, `host`, `is_home`, `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in`,
`bytes_out_ext` (to non-home addresses), `bytes_in_ext`, `distinct_dst_ips`, `distinct_dst_ports`, `distinct_src_ips`,
`new_dst_ports` and `new_dst_ips` (not contacted by this host in the previous `--novelty-horizon`, default 600 s),
`syn_out`, `synack_in`, `rst_in`, `syn_in`, `auth_syn_out` and `auth_syn_in` (SYNs to or from login ports
22, 23, 21, 3389, 5900, 445, 1433, 3306, 110, 143), `icmp_unreach_in`, `label`.

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
  windows excluded). Each named column is scored separately, sparse counters are skipped, and a window must be
  anomalous for 2 consecutive windows. The baseline is never imported from another capture.
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

- C2 beaconing (needs per-destination contact timing; consider a contacts output or RITA).
- DNS tunnelling (needs payload; the CTU captures are header-only).
- Hour-of-day baselines (need days of capture from one sensor).
- LLM triage of alerts (annotate only, never create alerts; see the analysis notes).
