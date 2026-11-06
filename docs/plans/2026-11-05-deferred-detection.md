# Plan: public baselines, beacons, DNS tunnelling, seasonal baselines, LLM triage

Status: not started. This plan covers the items deferred from `docs/plans/2026-11-05-per-host-detector.md`.

## Why

The per-host detector catches scans, floods, brute force and bulk uploads, and names the right host. It misses C2
beacons and DNS tunnels: the injected beacon, the injected DNS tunnel and the CTU-11 C2 bootstrap all went undetected.
Per-window totals throw away the per-destination timing and the query names that reveal those attacks.

**Everything here is built, tuned and validated on public captures only.** No live traffic is available to us, so the
captures in `datasets/` are both the development data and the test data. The tool is meant for networks in general,
from a single host (IoT-23, Active Countermeasures) to a university router (CTU-13). Two consequences:

- **Thresholds and allowlists ship with the tool.** They must work on every capture without site-specific tuning.
  Learned suppressions stay an optional feature, evaluated only within a dataset: learn on that network's attack-free
  capture, then test on its attack capture (DARPA weeks 1 and 3, then week 5).
- **Every control is tested on both small and large captures.** A filter that only helps on a busy network (the
  popularity filter) and one that only helps on a quiet one (the allowlist) are both kept, and the acceptance criteria
  say which capture exercises which.

All datasets are recorded in `datasets/SOURCES.md`.

| Phase | Builds | Validated on |
| - | - | - |
| 0. Public long baselines and injection | multi-file input, injection harness in the repo | DARPA 1999 weeks 1 and 3, then week 5 |
| 1. Beacon detection | contacts output, beacon scorer, shipped allowlist | Active Countermeasures Backoff and PoshC2, IoT-23, injected beacon, DARPA weeks 1 and 3 |
| 2. DNS tunnelling | DNS columns and rules | injected tunnel, CIC-Bell-DNS-EXF-2021, DARPA weeks 1 and 3 |
| 3. Hour-of-day baselines (lowest priority) | seasonal and per-host volume baselines | DARPA weeks 1 and 3, then week 5 |
| 4. LLM triage of incidents | optional `triage.py` | incident files from every labeled run |

## Phase 0: public long baselines and an injection harness

- **Multi-file input.** `detect.py` accepts several windows and hosts files (repeat the argument or pass a glob) and
  reads them in time order. `main.py` produces one file per pcap, and DARPA weeks 1 and 3 are 10 pcaps.
- **Injection harness.** Move the evaluation harness from the scratchpad into `tools/eval/`. It covers:
  - injecting synthetic attacks into a benign pcap (scapy, an optional dependency)
  - running `main.py` and `detect.py`
  - scoring alerts against label files (host and time match, false-alarm windows)
  - a `labels/` directory with the label CSVs for each dataset in `SOURCES.md`
- **Inject into more than one benign capture.** Use DARPA week 1 (a LAN with many hosts) and the attack-free parts of
  the Active Countermeasures captures (one host), as well as the CTU-13 university traffic. That checks the existing
  rules at three network sizes.
- **Within-dataset learning test.** Learn suppressions from DARPA weeks 1 and 3, apply them to week 5, and report the
  false-alarm rate with and without them. Week 5 currently stands at 0.80% with no suppressions; the target is 0.5%.

Done when:

1. The harness runs from the repo with one command per dataset.
2. DARPA week 5 is reported with and without week 1-3 suppressions.
3. The injected attacks are detected in at least two benign captures besides CTU-5.

## Phase 1: beacon detection

A beacon is malware checking in with its C2 server on a timer: one small connection every N seconds, with some jitter,
for hours. Each check-in is unremarkable. What gives it away is the regular timing between one internal host and one
external destination.

### What the captures show

Ground truth is in `SOURCES.md` section 7:

| Capture | Beacon | Decoys in the same capture |
| - | - | - |
| Backoff (Cobalt Strike), 24 h | 192.168.99.55 to 157.245.128.27:80, 3,020 connections, median gap 28.6 s, MAD 0.8 s | the same host to two Microsoft Azure addresses on :443, every 900.2 s, MAD 0: more regular than the beacon |
| PoshC2, 25 h | 10.0.0.62 to 157.230.93.100:443, 757 connections, 120.2 s, MAD 0 | the same host to four :443 servers, about 160 connections each in bursts 2.1 s apart (median gap 2.1 s, MAD 0) |

Timing regularity alone ranks both decoys at or above the real beacons. The scorer needs more evidence than the
median and MAD of the gaps.

### New output: `--contactfile contacts.csv` (`-oc`)

- One row per initiated contact, using the same "initiated" rule as `hosts.csv`: TCP SYN, UDP to a port below 1024,
  ICMP echo request.
- Columns: `time_msec`, `src`, `dst`, `protocol`, `sport`, `dport`, `bytes_out`, `bytes_in`, `pkts_out`, `pkts_in`.
- Bytes and packets: `WindowHosts` keeps a 5-tuple table and adds each packet to its flow until the window flushes,
  then writes the rows. Traffic after the window ends is not counted, which is acceptable because beacons are small and
  finish inside one window.
- Default scope is home source to non-home destination (`--contact-scope outbound|all`).
- No new process or queue. `TimesAndCounts` writes it next to the hosts file.

### New module: `beacons.py` (stdlib only), used by `detect.py --contacts contacts.csv`

- Group contacts by (src, dst, dport). Score each pair that has at least `beacon_min_contacts` (default 10) over at
  least `beacon_min_span_sec` (default 300).
- Scores, each from 0 to 1:
  - **Interval regularity:** 1 - min(1, MAD / median) of the gaps.
  - **Interval symmetry:** 1 - |Bowley skew| of the gaps.
  - **Size regularity:** the same MAD measure on bytes per contact.
  - **Coverage:** the share of `median gap` slots across the pair's span that contain at least one contact. Bursts of
    retries (the PoshC2 decoy) cover a tiny share of the span, while a beacon covers nearly all of it.
- Alert as `beacon` when the mean score is at least `beacon_score` (default 0.8, provisional) and coverage is at least
  `beacon_min_coverage` (default 0.6).
- Each alert names `host` = src, a new `peer` field = `dst:dport`, the period, the contact count and each score.
- **False-alarm controls:**
  - **Shipped allowlist.** `beacon_allow.txt` in the repo lists vendor destinations for OS updates, telemetry, time
    sync and major SaaS. Matching is by domain when phase 2's DNS data maps the IP to a name, and by published CIDR
    otherwise. The Microsoft decoy in the Backoff capture (one host, so nothing else can catch it) is the test case.
    Keep the list short, record where each entry comes from, and let `--beacon-allow FILE` add to or replace it.
  - **Popularity filter.** Skip destinations contacted by at least `beacon_popular_hosts` home hosts (default 5, or
    10% of active home hosts). DARPA weeks 1 and 3 and CTU-5 are the test cases: it should remove the shared services
    (DNS, mail, proxies) that every host on those networks beacons to.
  - **Learned suppressions.** Suppressions key on (kind, host, peer) when an alert has a peer. This stays optional and
    is tested within a dataset only.
- Scoring runs once at end of input. Periodic rescoring for live use is out of scope.
- **Known limits:**
  - A beacon slower than span / 10 is invisible.
  - Heavy jitter (over 50%) or rotating destinations defeat the timing scores.
  - Beacons over DNS show up per resolver, not per C2 domain; phase 2 covers that.
  - An allowlist entry is a blind spot if C2 is hosted on that vendor's infrastructure.

### Acceptance criteria

1. Backoff 24 h and PoshC2 24 h: each beacon pair raises `beacon` naming the implant host and C2 peer.
2. Backoff and PoshC2 1 h: same result. Each has about 30 or more contacts, so this tests the minimum span.
3. Neither decoy alerts. The Microsoft pair is stopped by the shipped allowlist, and the 2.1 s bursts by the coverage
   check. Record which control stopped each one.
4. IoT-23 34-1: the Mirai C2 contacts raise `beacon` for 192.168.1.195; its NTP and DNS do not.
5. The injected beacon in CTU-5 (18 sessions, 30 s period) raises `beacon`, and the un-injected CTU-5 and CTU-11
   captures raise at most 5 beacon pairs each after the popularity filter, with each one identified. CTU labels its
   background hosts as unknown, so some of these may be real; say so rather than tuning them away.
6. DARPA weeks 1 and 3 (10 days, no attacks): at most 1 beacon pair per day after the allowlist and popularity filter,
   with each one identified. No learned suppressions are used for this criterion.
7. Unit tests for the contacts output, each score, the coverage check, the allowlist and suppression keying.
   `pytest` passes.

## Phase 2: DNS tunnelling

A DNS tunnel carries data in query names (long, random-looking subdomains of one domain) and in TXT/NULL answers, at a
query rate no person produces.

- **Data.** tshark's full EK output already includes `dns.qry.name`, `dns.qry.type` and `dns.resp.len`. Check the
  dotted names `PacketCapture.unwrap` produces before matching them. The CTU-13 captures are header-only, so they
  can't be used here.
- **New per-host columns in `hosts.csv`:**
  - `dns_queries`
  - `dns_names`: unique query names
  - `dns_max_label_len`
  - `dns_txt_null`: TXT or NULL queries
  - `dns_top_base_domain`
  - `dns_top_base_unique`: unique subdomains under the busiest base domain
  - `dns_label_entropy`: mean Shannon entropy of the leftmost labels under that base domain
- **Base domain.** Use the last two labels, or three when the second-level label is a known public second level such
  as `co.uk` or `com.au`. A small built-in list is enough, with no public-suffix-list dependency. Document the
  approximation.
- **Rules in `detect.py`, per host over a rolling window (default 10 min):**
  - `dns_tunnel`: unique subdomains under one base domain at or above `dns_unique_subdomains` (default 300), with mean
    label entropy at or above `dns_entropy` (default 3.5 bits) or max label length at or above 50.
  - `dns_txt_burst`: TXT/NULL queries at or above `dns_txt_queries` (default 100).
  - Both name the base domain in `detail`. CDN and anti-virus lookups also produce many unique subdomains; add the
    common ones to a shipped domain allowlist, sharing its format with `beacon_allow.txt`.
- **Security.** Query names are attacker-controlled strings. They are written to CSV and JSONL as data, and must reach
  phase 4 escaped and marked as untrusted.

### Acceptance criteria

1. The injected tunnel (1,500 TXT queries over 60 s, 60-character random labels under `exfil.example.net`) raises
   `dns_tunnel` and `dns_txt_burst` for VICTIM within 60 s.
2. CIC-Bell-DNS-EXF-2021: light and heavy exfiltration are detected. Report the per-file detection rate, and the false
   alarms on its benign captures. This needs the UNB download form, so the user downloads it by hand.
3. DARPA weeks 1 and 3 and week 5 (benign DNS, including the hume storm in week 5): no `dns_tunnel` alert. Record what
   `dns_txt_burst` raises.
4. Tests for the base-domain function, each column and each rule. `pytest` passes.

## Phase 3: hour-of-day baselines (lowest priority)

`VolumeBaseline` compares each window with the trailing hour, so it alerts at scheduled changes: start of day, nightly
jobs, end of day. Only DARPA has enough days from one network to test this, so do it only if phase 0 shows DARPA
volume alerts clustering at the same times each day.

- With at least `seasonal_min_days` (default 3) of history, compare each window with the same hour of day on previous
  days: median and MAD of log values in a 1-hour bucket. With at least 7 days, use hour-of-week.
- Alert only when the window is anomalous against both the seasonal and the trailing baseline.
- `--tz` names the capture's timezone, and buckets use local hours. DARPA weeks 1 and 3 are EST and week 5 is EDT; see
  `SOURCES.md`.
- Per-host volume baselines (`bytes_out`, `pkts_out`, `contacted_ips`) for home hosts with enough history, using the
  same method.

### Acceptance criteria

1. DARPA week 5, with weeks 1 and 3 as history: volume alerts at least halve compared with trailing-only, and no
   labeled attack detected today is lost.
2. Injected attacks in DARPA week 1 are still detected.
3. Tests with synthetic multi-day windows. `pytest` passes.

## Phase 4: LLM triage of incidents

Our evaluation and published work (Houssel et al. 2024, about 50% accuracy on flow records, which is chance) agree: an
LLM reading raw rows adds nothing to detection. Its use is explaining incidents the coded detector has already raised,
so a person can decide faster.

- New script `triage.py incidents.jsonl windows.csv hosts.csv [contacts.csv] -o triaged.jsonl`.
  - It is optional: `anthropic` goes in `requirements-triage.txt`, not `requirements.txt`, and `detect.py` stays
    stdlib-only.
- Context per incident:
  - the incident and its alerts
  - the host's rows from 10 minutes before to 10 minutes after (capped at 200 rows)
  - the matching window rows
  - the host's earlier incidents in the run
  - any suppression peaks
- The model returns JSON:
  - `summary`
  - `benign_explanations[]`
  - `malicious_explanations[]`
  - `checks[]`
  - `priority`: low, medium or high
- Output is the incident with an added `triage` object. It never adds, removes or changes alerts or incidents, and a
  test enforces that.
- **Privacy:**
  - IPs are replaced with stable pseudonyms by default and restored in the output; `--no-pseudonymize` turns this off.
  - Nothing is sent without `--yes` or a confirmation prompt.
- **Prompt injection.** DNS names and any future payload fields are attacker-controlled. They go in a marked data
  block, the model has no tools, and the output is parsed as JSON only.
- **Cost.** `--max-incidents` (default 50, highest observed/threshold ratio first), prompt caching of the fixed
  instructions, configurable model.

### Acceptance criteria

1. On every labeled run, report how well `priority` ranks labeled incidents above unlabeled ones (ROC AUC). This is a
   measurement, with no target.
2. The user reviews 20 sampled incidents with their triage and judges the explanations and checks. Ship only if most
   are correct and useful.
3. Tests with a mocked client:
   - the alert set is unchanged
   - pseudonyms round-trip
   - malformed model output is recorded as a triage error

## Not planned

- **Live capture for development or tuning.** None is available, so everything ships with defaults validated on the
  public captures. Live operation (rotating captures, incremental detection, alert delivery) is a later engineering
  task that adds no detection.
- **Supervised models trained on the public datasets.** They would learn dataset artifacts, such as DARPA's TTL and
  timing quirks, instead of attacks.
- **Payload inspection beyond DNS.** Exploits and web attacks need a signature IDS such as Suricata or Zeek.
