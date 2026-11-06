# Plan: baseline capture, beacons, DNS tunnelling, seasonal baselines, LLM triage

Status: not started. This plan covers the items deferred from `docs/plans/2026-11-05-per-host-detector.md`.

## Why

The per-host detector catches scans, floods, brute force and bulk uploads, naming the right host, but it misses three
things:

- **C2 beacons and DNS tunnels.** The injected beacon, the injected DNS tunnel and the CTU-11 C2 bootstrap went
  undetected. Per-window totals discard the per-destination timing and query names that reveal them.
- **Busy real networks.** False alarms stay low only after the detector has learned that network's noisy hosts, and
  every public capture we have is 8 minutes to 24 hours long.

The phases below are listed in the order we recommend doing them. Phase 0 is operational and the others depend on it
for real-world tuning. Phases 1, 2 and 4 can each be built and tested on the existing labeled captures without it.

| Phase | Needs | Testable now on |
| - | - | - |
| 0. Long baseline of your own network | live capture for 1-2 weeks | n/a |
| 1. Beacon detection | new contacts output | injected CTU-5, IoT-23 (24 h), CTU-5 HTTP C2 |
| 2. DNS tunnelling | DNS fields already in tshark EK output | injected CTU-5 only (the CTU captures are header-only) |
| 3. Hour-of-day baselines | 1-2 weeks from one sensor | DARPA (22 h, weak test) |
| 4. LLM triage of incidents | an API key; optional dependency | all existing incident files |

## Phase 0: collect a long baseline

Goal: 1-2 weeks of `windows.csv`, `hosts.csv` and (after phase 1) `contacts.csv` from the network to be monitored. Use
it to learn suppressions and to tune phases 1-3.

- Run one capture per day, so a crash loses at most one day, for example from launchd or cron:
  `python3 main.py -i en0 -l 86400 -wt 5000 -o windows-$(date +%F).csv -oh hosts-$(date +%F).csv --home-net <cidrs>`.
- Code changes:
  - `detect.py` accepts several windows and hosts files (repeat the argument or pass a glob) and reads them in time
    order. Days are separate files.
  - `--learn-suppressions` over a multi-day set records each (kind, host) peak as now.
- Measure CPU and memory use of a 24-hour live run. `capture.py` runs tshark with `-V -T ek` (full dissection), which
  may be too slow on a busy link. If it is, pass tshark only the fields we read (`-e`), and check `PacketCapture.unwrap`
  against the new output.
- The data is personal (who talked to whom, and DNS names after phase 2). Keep it in a gitignored directory, never in
  `datasets/`.

Done when: a week of daily files exists, `detect.py` reads them as one run, and suppressions learned from the first
week cut the second week's alert rate to under 1% of windows.

## Phase 1: beacon detection

A beacon is malware checking in with its C2 server on a timer: one small connection every N seconds, with some jitter,
for hours. Each check-in is unremarkable. The giveaway is the regular timing between one internal host and one external
destination.

### New output: `--contactfile contacts.csv` (`-oc`)

- One row per initiated contact, using the same "initiated" rule as `hosts.csv`: TCP SYN, UDP to a port below 1024,
  ICMP echo request.
- Columns: `time_msec`, `src`, `dst`, `protocol`, `sport`, `dport`, `bytes_out`, `bytes_in`, `pkts_out`, `pkts_in`.
- Bytes and packets: `WindowHosts` keeps a 5-tuple table and adds each packet to the matching flow until the window
  flushes. Rows are written at flush. Traffic after the window ends is not counted, which is acceptable because
  beacons are small and finish inside one window.
- Default scope is home source to non-home destination (`--contact-scope outbound|all`), which keeps the file small on
  busy networks.
- Shares `cvar.windowcounts.host_window`, so there is no new process or queue. Written by `TimesAndCounts` next to the
  hosts writer.

### New module: `beacons.py` (stdlib only), used by `detect.py --contacts contacts.csv`

- Group contacts by (src, dst, dport). Score each pair that has at least `beacon_min_contacts` (default 10) over at
  least `beacon_min_span_sec` (default 300).
- Scores, each from 0 to 1, in the style of RITA:
  - **Interval regularity:** 1 - min(1, MAD / median) of the gaps between contacts. MAD-based, so jitter of a few
    percent still scores high.
  - **Interval symmetry:** 1 - |Bowley skew| of the gaps.
  - **Size regularity:** the same MAD measure on `bytes_out + bytes_in` per contact.
  - **Coverage:** contacts seen / (span / median gap), capped at 1. A beacon doesn't skip many beats.
- The pair alerts as `beacon` when the mean score is at least `beacon_score` (default 0.8, provisional).
- Each alert carries `host` = src, a new `peer` field = `dst:dport`, the period, the contact count and each score.
- False-alarm controls. Software update checks, NTP, telemetry, chat keepalives and cloud sync all beacon
  legitimately.
  - **Popularity:** skip destinations contacted by at least `beacon_popular_hosts` home hosts (default 5, or 10% of
    active home hosts) during the run.
  - **Allowlist:** `--beacon-allow FILE` lists destination IPs or CIDRs.
  - **Suppressions:** suppressions key on (kind, host, peer) when the alert has a peer, so learning one host's NTP
    beacon doesn't hide that host's other beacons.
- Initial version scores once at end of input. A later `--beacon-every SEC` could rescore the trailing 24 hours
  periodically for live use.
- Known limits:
  - A beacon slower than span / 10 is invisible. For example, a 1-hour beacon needs 10 hours of data.
  - Heavy jitter (over 50%) or randomized destinations defeat the timing scores.
  - Beacons over DNS are counted per resolver, not per C2 domain. Phase 2 covers that.

### Acceptance criteria

1. The injected beacon in the CTU-5 test capture (18 sessions, 30 s period, about 9 minutes) raises `beacon` for
   VICTIM to EXTERNAL:443. Score the scenario with `beacon_min_contacts` at 10.
2. IoT-23 34-1 (24 h): the Mirai C2 contacts raise `beacon` for 192.168.1.195. The device's NTP and DNS traffic
   either doesn't alert or is suppressed by the popularity filter or the allowlist; record which.
3. CTU-5: the HTTP C2 (94.63.150.63:80, 91.220.0.52:80) is reported, or the miss is explained (an 18-minute span may
   be too short).
4. False alarms on DARPA week 5 Monday inside (22 h): at most 5 beacon pairs not explained by labels or documented
   benign services. Report what they are.
5. Unit tests for the contacts output, each score, the popularity filter and suppression keying. `pytest` passes.

## Phase 2: DNS tunnelling

A DNS tunnel carries data in query names (long, random-looking subdomains of one domain) and in TXT/NULL answers, at a
query rate no person produces.

- **Data.** tshark's full EK output already includes `dns.qry.name`, `dns.qry.type` and `dns.resp.len`. Check the
  dotted names `PacketCapture.unwrap` produces before using them. Headers-only captures (CTU-13) have no DNS payload,
  so this phase can be tested only on the injected capture, DARPA (benign DNS, including the hume storm) and phase 0
  data.
- **New per-host columns in `hosts.csv`:**
  - `dns_queries`
  - `dns_names`: unique query names
  - `dns_max_label_len`
  - `dns_txt_null`: TXT or NULL queries
  - `dns_top_base_domain`
  - `dns_top_base_unique`: unique subdomains under the busiest base domain
  - `dns_label_entropy`: mean Shannon entropy of the leftmost labels under that base domain
- **Base domain.** Use the last two labels, or three when the second-level label is a known public second-level such as
  `co.uk` or `com.au`. A small built-in list is enough; no public-suffix-list dependency. Document that this is an
  approximation.
- **Rules in `detect.py`, per host over a rolling window (default 10 min):**
  - `dns_tunnel`: unique subdomains under one base domain at or above `dns_unique_subdomains` (default 300), with mean
    label entropy at or above `dns_entropy` (default 3.5 bits) or max label length at or above 50.
  - `dns_txt_burst`: TXT/NULL queries at or above `dns_txt_queries` (default 100).
  - Both name the base domain in `detail` and use the existing suppressions. CDNs and some anti-virus products also
    produce many unique subdomains, so learning matters here too.
- **Security.** Query names are attacker-controlled strings. They are written to CSV and JSONL as data, and must reach
  phase 4 escaped and labeled as untrusted.

### Acceptance criteria

1. The injected tunnel (1,500 TXT queries over 60 s, 60-character random labels under `exfil.example.net`) raises
   `dns_tunnel` and `dns_txt_burst` for VICTIM within 60 s.
2. DARPA week 5 Monday inside: no `dns_tunnel` alert. The hume DNS storm may raise `dns_txt_burst` only if it really is
   TXT; record what it raises.
3. Phase 0 data: at most 1 `dns_tunnel` incident per day after suppressions, each explained.
4. Tests for the base-domain function, each column and each rule. `pytest` passes.

## Phase 3: hour-of-day baselines

`VolumeBaseline` compares each window with the trailing hour. On a real network this alerts at predictable changes,
such as the start of the working day, nightly backups and the end of the day.

- With at least `seasonal_min_days` (default 3) of history, compare each window with the same hour of day on previous
  days: median and MAD of log values over those days' windows in a 1-hour bucket. With at least 7 days, use
  hour-of-week instead, so weekends get their own baseline.
- Alert only when the window is anomalous against both the seasonal and the trailing baseline. That keeps the trailing
  baseline's quick adaptation and removes the scheduled jumps.
- `--tz` names the sensor's timezone; buckets are local hours.
- Add per-host volume baselines (`bytes_out`, `pkts_out`, `contacted_ips`) for home hosts with enough history. They
  use the same median/MAD method with the seasonal option. They catch a host whose behaviour changes without crossing
  any absolute rule.
- Memory: hour buckets × days × columns, plus per-host state for home hosts only. Stores summaries per bucket, not raw
  windows, once a bucket is older than the trailing hour.

### Acceptance criteria

1. On phase 0 data (week 2 tested with week 1 as history): volume alerts at least halve compared with the trailing-only
   baseline, with no labeled or injected event lost.
2. Injected events replayed into a phase 0 day (the CTU-5 injection harness pointed at a phase 0 capture) are still
   detected.
3. DARPA: no regression from the current 0.80% false-alarm windows. 22 hours is too short for a real seasonal test,
   so this only checks that nothing breaks.
4. Tests with synthetic multi-day windows. `pytest` passes.

## Phase 4: LLM triage of incidents

Our evaluation and published work (Houssel et al. 2024, about 50% accuracy on flow records, which is chance) agree that
an LLM given raw rows adds nothing to detection. Its use is explaining incidents the coded detector has already raised,
so a person can decide faster.

- New script `triage.py incidents.jsonl windows.csv hosts.csv [contacts.csv] -o triaged.jsonl`, an optional extra.
  `anthropic` goes in `requirements-triage.txt`, not `requirements.txt`, and `detect.py` stays stdlib-only.
- For each incident, the context sent is:
  - the incident and its alerts
  - the host's rows from 10 minutes before to 10 minutes after (capped at 200 rows)
  - the matching window rows
  - the host's earlier incidents in the run
  - any learned suppression peaks for the host
- The model returns JSON:
  - `summary`
  - `benign_explanations[]`
  - `malicious_explanations[]`
  - `checks[]`: what to look at next, such as a pcap filter or which host to inspect
  - `priority`: low, medium or high
- The output is the incident with an added `triage` object. It never adds, removes or changes alerts or incidents,
  and a test enforces that.
- **Privacy.** IPs are replaced with stable pseudonyms (`home-3`, `ext-17`) by default and restored in the output;
  `--no-pseudonymize` turns this off. Nothing is sent without an explicit `--yes` or a confirmation prompt, because
  sending is publishing to a third party.
- **Prompt injection.** Phase 2 DNS names and any future payload fields are attacker-controlled. They go in a clearly
  marked data block, the model has no tools, and the output is parsed as JSON only.
- **Cost controls:** `--max-incidents` (default 50, highest observed/threshold ratio first), prompt caching of the
  fixed instructions, and a configurable model.

### Acceptance criteria

1. On the existing labeled runs (injected CTU-5, CTU-5, CTU-11, IoT-23, DARPA, LLDoS), report whether `priority`
   ranks labeled incidents above unlabeled ones (ROC AUC). No minimum is set: it is a measurement, because the value
   being tested is the explanations.
2. The user reviews 20 sampled incidents with their triage and judges whether the explanations and checks are correct
   and useful. Ship only if most are.
3. Tests with a mocked client: the alert set is unchanged, pseudonyms round-trip, and malformed model output is
   recorded as a triage error without failing the run.

## Not planned

- **Supervised models** trained on the public datasets. They would learn dataset artifacts, such as DARPA's TTL and
  timing quirks, instead of attacks.
- **Payload inspection** beyond DNS, such as exploits and web attacks. That needs an IDS with signatures (Suricata or
  Zeek), not this tool.
