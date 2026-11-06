# Plan: public baselines, beacons, host profiles, TLS/HTTP facts, DNS tunnelling, seasonal baselines, LLM triage

Status: phase 0 implemented on branch `feature/public-baselines` (results below). Phases 1-3 were scoped by three
investigations on 2026-11-05 (RITA reference scores, long-horizon host profiles, TLS/HTTP metadata); their findings are
in the phase sections. This plan covers the items deferred from `docs/plans/2026-11-05-per-host-detector.md`.

**Superseded on 2026-11-06.** The investigations showed that phases 1-3 each need per-connection records (contact
times per destination, destination sets over days, TLS/HTTP handshake fields) that a window summary cannot hold, so
the project is being reframed around a connection log as the primary output (README, "What the window-summary
approach is and isn't good for"; plan: `docs/plans/2026-11-06-connection-log.md`). The phase sections below remain
the record of what was learned and the acceptance criteria carry over to the steps of that plan.

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

All datasets are recorded in `datasets/SOURCES.md`; `tools/eval/run.py` runs and scores each one.

| Phase | Builds | Validated on |
| - | - | - |
| 0. Public long baselines and injection (done) | multi-file `detect.py`, `tools/eval/` harness | DARPA 1999 weeks 1 and 3, then week 5; injected CTU-5 |
| 1. Beacon detection | contacts output, beacon scorer, shipped allowlist | Active Countermeasures Backoff and PoshC2, IoT-23, injected beacon, CTU-5, DARPA weeks 1 and 3 |
| 2. Long-horizon host profiles | profile file learned over days; unknown-source and novel-port rules | DARPA weeks 1 and 3, then week 5; CTU-5 for real background |
| 3. TLS and HTTP facts per host and destination | corroborating columns attached to beacon and profile alerts | Backoff, PoshC2, DARPA (HTTP only) |
| 4. DNS tunnelling | DNS columns and rules | injected tunnel, CIC-Bell-DNS-EXF-2021, DARPA weeks 1 and 3 |
| 5. Hour-of-day baselines (lowest priority) | seasonal and per-host volume baselines | DARPA weeks 1 and 3, then week 5 |
| 6. LLM triage of incidents | optional `triage.py` | incident files from every labeled run |

Order: 1, 2 and 3 share the contacts output and the per-destination state, so build 1 first and let 2 and 3 reuse
it. 4 is independent. 5 only if phase 0's DARPA volume alerts turn out to cluster by hour. 6 last.

## Phase 0: public long baselines and an injection harness (done)

- **Multi-file input.** `detect.py` accepts any number of windows and hosts CSVs, tells them apart by header and reads
  them in time order, so DARPA's 10 attack-free days are one run.
- **Harness in `tools/eval/`.** `datasets.yaml` registry, `labels/*.csv`, `run.py` (capture, detect, score),
  `score.py`, `inject.py` and `gen_attacks.py` (scapy). Labels may name the alert kinds that count, so an overlapping
  attack on the same host is not credited for another's alert (this had made the injected beacon and DNS tunnel look
  detected when they were not).
- **Within-dataset learning test.** `run.py darpa-attackfree --learn-suppressions` then `run.py darpa99 --suppress`.

### Results (2026-11-05)

| Check | Result |
| - | - |
| `inject.py` reproduces the earlier injected capture | Yes: 1,394,340 packets, identical labels |
| Injected CTU-5, CTU-11 suppressions (labeled hosts excluded) | 5/7 with the right kinds: fast and slow scan, SYN flood, SSH brute force (36 s), upload (11 s); beacon and DNS tunnel not detected; 0% false-alarm windows |
| CTU-11, no suppressions | ICMP DDoS yes, C2 bootstrap no; 85.6% false-alarm windows, nearly all `slow_sweep` and `failed_connections` from 147.32.84.59 |
| CTU-5, CTU-11 suppressions | Virut bot 200 s after onset (`failed_connections`); 0.83% false-alarm windows (3, one host) |
| DARPA week 5, no suppressions | 10/26 labels (as before); 0.80% false-alarm windows (127 of 15,835), 92 of them the documented hume DNS storm |
| DARPA week 5, suppressions learned from weeks 1 and 3 (66 learned, 136 alerts suppressed) | the same 10/26, none lost; **0.03%** false-alarm windows (5 of 15,835): two hosts' TCP volume and two external hosts' single windows. Target 0.5% met. The attack-free weeks taught the detector hume's DNS storm and the busy FTP servers |

Each DARPA day captures in 4-6 minutes (5,300-6,800 packets/s); the 10 learning days took 25 minutes two at a time.

Injecting into DARPA week 1 and the Active Countermeasures captures (three network sizes) is not done yet; the
`inject` block in `datasets.yaml` supports it once a cut and the victim/attacker addresses are chosen for each.

## Phase 1: beacon detection

A beacon is malware checking in with its C2 server on a timer: one small connection every N seconds, with some jitter,
for hours. Each check-in is unremarkable. What gives it away is the regular timing between one internal host and one
external destination.

### What the captures show

Ground truth is in `SOURCES.md` section 7:

| Capture | Beacon | Decoys in the same capture |
| - | - | - |
| Backoff (Cobalt Strike), 24 h | 192.168.99.55 to 157.245.128.27:80, 3,020 connections, median gap 28.6 s, MAD 0.8 s | the same host to two Microsoft Azure addresses on :443, every 900.2 s, MAD 0: more regular than the beacon |
| PoshC2, 25 h | 10.0.0.62 to 157.230.93.100:443, 757 connections, 120.2 s, MAD 0 | the same host to four :443 servers, about 160 connections each in bursts 2.1 s apart (median gap 2.1 s, MAD 0); these are empty connect/disconnect probes with no TLS hello |

Timing regularity alone ranks both decoys at or above the real beacons. The scorer needs more evidence than the
median and MAD of the gaps.

### Reference: RITA's algorithm on these captures

RITA itself needs a database, so its v5 beacon formula (`analysis/beacons.go`: interval skew and MAD, size skew and
MAD, a 24-bin connection histogram scored by coefficient of variation or a bimodal fit, and a duration score; equal
weights) was reimplemented on Zeek `conn.log` and run on every beacon capture (scripts in the scratchpad; Zeek 9.0.1
was installed with Homebrew for this). Where the true C2 ranks:

| Capture | C2 rank | Beaten by |
| - | - | - |
| Backoff 24 h | 1 (0.989) | nothing, but the 900 s Microsoft pair is 0.986 and wins on timing alone |
| Backoff 1 h | 1 | |
| PoshC2 24 h | 18 (0.992) | 17 benign pairs at a perfect 1.000: a 300 s poll and 16 burst pairs, all four decoys among them |
| PoshC2 1 h | 1 | |
| IoT-23 Mirai | 9 (0.640) | eight NTP servers; 5,000 failed SYN retries wreck the C2's interval statistics |
| CTU-5 | not meaningful | Zeek cannot parse the header-truncated capture |

Design constraints taken from this:

- The best single component is **evenness of connection counts across the capture** (the histogram CV): the C2 is
  first on it in all four Active Countermeasures captures. That is the plan's coverage check; make it the primary
  score, not one of four equal terms.
- RITA ignores the interval magnitude, so a 2 s burst and a 120 s beacon look alike. **A median gap below
  `beacon_min_gap_sec` (default 5) is a burst, not a beacon.**
- RITA's bimodal-histogram fallback is what lets hourly bursts score 1.000. **Do not copy it.**
- **Collapse SYN retries into attempts** (same src, dst, dport within a few seconds count once) before scoring, or a
  C2 with a flaky server loses to NTP.
- **Exclude multicast and broadcast destinations up front**, or mDNS, LLMNR and SSDP score 1.000.
- These numbers are the yardstick: criterion 8 below requires our scorer to beat them.

### New output: `--contactfile contacts.csv` (`-oc`)

- One row per initiated contact, using the same "initiated" rule as `hosts.csv`: TCP SYN, UDP to a port below 1024,
  ICMP echo request. SYNs from source port 20 (active-mode FTP data) are not contacts the client chose; record them
  with `dport` = `ftpdata` so they collapse (see phase 2).
- Columns: `time_msec`, `src`, `dst`, `protocol`, `sport`, `dport`, `bytes_out`, `bytes_in`, `pkts_out`, `pkts_in`,
  `answered` (a SYN-ACK or reply was seen in the window).
- Bytes and packets: `WindowHosts` keeps a 5-tuple table and adds each packet to its flow until the window flushes,
  then writes the rows. Traffic after the window ends is not counted, which is acceptable because beacons are small and
  finish inside one window.
- Default scope is home source to non-home destination (`--contact-scope outbound|all`).
- No new process or queue. `TimesAndCounts` writes it next to the hosts file.

### New module: `beacons.py` (stdlib only), used by `detect.py --contacts contacts.csv`

- Collapse retries: contacts with the same (src, dst, dport) within `beacon_retry_sec` (default 3) are one attempt.
- Group attempts by (src, dst, dport). Score each pair that has at least `beacon_min_contacts` (default 10) over at
  least `beacon_min_span_sec` (default 300), and whose median gap is at least `beacon_min_gap_sec` (default 5).
- Scores, each from 0 to 1:
  - **Coverage** (primary): the share of `median gap` slots across the pair's span that contain at least one attempt.
    Bursts cover a tiny share of the span; a beacon covers nearly all of it.
  - **Interval regularity:** 1 - min(1, MAD / median) of the gaps.
  - **Interval symmetry:** 1 - |Bowley skew| of the gaps.
  - **Size regularity:** the same MAD measure on bytes per attempt.
- Alert as `beacon` when coverage is at least `beacon_min_coverage` (default 0.6) and the mean of the four scores is
  at least `beacon_score` (default 0.8, provisional). Both numbers are to be set from the captures, not guessed.
- Each alert names `host` = src, a new `peer` field = `dst:dport`, the period, the attempt count and each score, plus
  the phase 3 facts for that pair when available.
- **False-alarm controls:**
  - **Shipped allowlist.** `beacon_allow.txt` in the repo lists vendor destinations for OS updates, telemetry, time
    sync and major SaaS. Matching is by domain when phase 4's DNS data maps the IP to a name, and by published CIDR
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
  - Beacons over DNS show up per resolver, not per C2 domain; phase 4 covers that.
  - An allowlist entry is a blind spot if C2 is hosted on that vendor's infrastructure.

### Acceptance criteria

1. Backoff 24 h and PoshC2 24 h: each beacon pair raises `beacon` naming the implant host and C2 peer.
2. Backoff and PoshC2 1 h: same result. Each has about 30 or more contacts, so this tests the minimum span.
3. Neither decoy alerts. The Microsoft pair is stopped by the shipped allowlist, and the 2.1 s bursts by the minimum
   gap and coverage checks. Record which control stopped each one.
4. IoT-23 34-1: the Mirai C2 contacts raise `beacon` for 192.168.1.195; its NTP and DNS do not.
5. The injected beacon in CTU-5 (18 sessions, 30 s period) raises `beacon`, and the un-injected CTU-5 and CTU-11
   captures raise at most 5 beacon pairs each after the popularity filter, with each one identified. CTU labels its
   background hosts as unknown, so some of these may be real; say so rather than tuning them away.
6. DARPA weeks 1 and 3 (10 days, no attacks): at most 1 beacon pair per day after the allowlist and popularity filter,
   with each one identified. No learned suppressions are used for this criterion.
7. Unit tests for the contacts output, retry collapsing, each score, the coverage check, the allowlist and suppression
   keying. `pytest` passes.
8. Ranked by our score before any allowlist or filter, the true C2 is first in all four Active Countermeasures
   captures and above every NTP server in IoT-23 (RITA's formula: 1, 1, 18, 1 and 9).

## Phase 2: long-horizon host profiles

`hoststats.Novelty` forgets a contact after 10 minutes. A profile that remembers, per home host, every destination and
port it has initiated contact with over days turns "this host did something it has never done" into a rule. The
investigation (DARPA weeks 1 and 3 as the profile, week 5 scored; scripts in the scratchpad) found:

- **Novel destination IP is useless:** every host browses to 25-60 new IPs a day. Not a rule.
- **Active-mode FTP data** (the server SYNs from port 20 to the client's ephemeral port) produced 400-700 "novel ports"
  a day until collapsed into one `ftpdata` key, after which week 5 had 3 benign novel-port events. `contacted_ports`
  in `hosts.csv` has the same flaw today.
- Three rules, scored per host in 10-minute buckets on week 5:

| Rule | Labels caught (of 26) | False-alarm buckets in 22 h |
| - | - | - |
| `unknown_inbound_source`: an external IP never seen initiating contact in the profile contacts a home host | 9-10 (neptune, both apache2 DoS, telnet guessing, ping-of-death, warezclient, syslogd, crashiis, dosnuke) | 9, all attacker IPs probing outside their label windows; none benign |
| `unknown_home_source`: a home address never seen initiating contact | 3 (portsweep, dictionary brute force, ncftp) | 3, planted test hosts |
| `novel_port`: a known home host uses a destination port it never used, excluding 80, 443, 53 and `ftpdata` | 6 (arppoison, dict, imap, loadmodule, ncftp, udpstorm) | 5, none clearly benign |

Together, 17 of 26 labels show some signal (10 today). The misses are smurf (ICMP replies, not requests), a FIN-only
sweep, and payload-level exploits, which no contact rule can see. Leave-one-day-out over the 10 attack-free days gave
the same benign rates as week 5, so the profile is stable.

Caveats that shape the design: DARPA's background is scripted (only 11 external hosts ever initiate inbound), so
`unknown_inbound_source` has an unrealistically clean baseline; on an Internet-facing network inbound scanners would
fire it constantly. Victims almost never show novelty, so this detects initiators only.

### Design

- **Profile file.** `detect.py --learn-profile OUT` writes, from the contacts output, per home host: the set of
  (dst, dport) pairs and the set of dports, plus the set of external sources seen initiating, each with the number of
  days seen. `--profile FILE` loads it. The file is CSV, like suppressions. Learning needs the contacts output from
  phase 1 (`-oc`).
- **Rules** (names as above), each over 10-minute buckets per host, thresholds configurable:
  - `unknown_inbound_source` fires only for contacts that were **answered** (SYN-ACK or reply seen), with
    `unknown_inbound_min` (default 1) contacts. Unanswered probes from unknown sources are counted in the alert's
    detail but do not fire; that is the restriction the caveat calls for, and criterion 3 measures whether it is
    enough on real background.
  - `unknown_home_source`: any contact; detail says "new device on the LAN".
  - `novel_port`: dport not in `profile_web_ports` (default 80, 443, 53, `ftpdata`) and never used by this host;
    `novel_port_min` (default 1).
- **FTP fix in `hoststats.py` too:** SYNs from source port 20 count as `ftpdata` in `contacted_ports` and
  `new_contacted_ports`, in the same change.
- Without a profile file the rules are off, so nothing changes for existing users.

### Acceptance criteria

1. DARPA week 5 with the week 1-3 profile: at least 16 of 26 labels raise one of the three rules naming the attacker
   or victim within 10 minutes (the investigation's 17 is the reference), and at most 20 false-alarm buckets, each
   identified.
2. DARPA leave-one-day-out: profile on 9 attack-free days, run the 10th; at most 2 `novel_port` and 2
   `unknown_home_source` alerts per day, each identified.
3. CTU-5, profile learned from the first 8 minutes (before the bot): report the `unknown_inbound_source` rate on the
   remaining 22 minutes with and without the answered-only restriction. This is the real-background test; the
   number is reported, not targeted, and decides whether the rule ships on by default.
4. The `ftpdata` fix removes the FTP-data ports from `contacted_ports` on DARPA (hume's count drops to the tens) and
   changes nothing on the captures without active FTP.
5. Tests for profile learning, loading, each rule and the `ftpdata` key. `pytest` passes.

## Phase 3: TLS and HTTP facts per host and destination

Both lab C2s stand out in metadata tshark already decodes. On PoshC2 (HTTPS) every one of these fields separates the
C2 from the host's 125 other TLS destinations with at most one benign outlier: no SNI (716 of 716 hellos), a JA3
fingerprint used toward one destination only, TLS 1.0, and a self-signed certificate with no SAN and a 10-year validity
starting 58 minutes before the capture (seen on only 12 of 716 sessions because the server resumes with tickets). On
Backoff (HTTP) the `Host` header is a bare IP (the C2 only), the user agent is used toward one destination only, the URI
is constant (`/updates`, 3,020 times) and every response is an empty 200. In neither capture does any DNS answer return
the C2 address.

These are corroboration, not a detector: both frameworks ran default profiles, real desktops make "unique JA3" and
"unique user agent" far noisier, TLS 1.3 and resumption hide certificates, and the burst decoys carry no TLS at all.

### Design

- **Per (home host, destination, port) facts**, kept by `WindowHosts` across windows and written at end of input to
  `--factsfile facts.csv` (`-of`), one row per pair: `tls_hellos`, `tls_no_sni`, `tls_sni`, `tls_ja3`,
  `tls_min_version`, `cert_seen`, `cert_self_signed`, `cert_no_san`, `cert_days_valid`, `http_requests`,
  `http_host_is_ip`, `http_user_agents`, `http_distinct_uris`, `dns_answered` (some DNS answer in the capture mapped a
  name to this destination).
- **Derived per host:** JA3 fan-out (destinations per JA3) and user-agent fan-out, so "used toward one destination
  only" can be stated.
- `detect.py --facts facts.csv` attaches the pair's facts to every `beacon`, `novel_port` and `unknown_*` alert for that
  pair, and raises the alert's `evidence` count by one for each of: no SNI, single-destination JA3, self-signed cert,
  bare-IP Host, single-destination user agent, no DNS answer. `evidence` is for ranking and triage; it does not create
  alerts.
- **Parser work.** `capture.unwrap` turns `tls_tls_handshake_extensions_server_name` into
  `tls.handshake_extensions_server_name` (not the Wireshark dotted name), and likewise for the `x509*` and `http_*`
  keys; look-ups use the mangled names, which the investigation listed. tshark emits `x509af_utcTime` twice at one
  level (not-before, not-after) and `json.loads` keeps the last, so validity needs both values recovered from the raw
  EK line or `cert_days_valid` is dropped. This tshark (4.0.1) has JA3 but not JA4.
- Cost: the TLS dissection is already paid for by `-V`; the full EK pass takes 24 s (Backoff) and 49 s (PoshC2) per
  24 h capture.

### Acceptance criteria

1. PoshC2: the C2 pair has `tls_no_sni`, single-destination JA3 and `cert_self_signed` set; at most 3 other pairs have
   any one of them, and none has two.
2. Backoff: the C2 pair has `http_host_is_ip` and a single-destination user agent; no other pair has either.
3. DARPA week 5: the facts file is produced (HTTP only, no TLS in 1999) and `http_host_is_ip` is reported for the
   attack hosts that use it, if any.
4. The phase 1 beacon alerts on Backoff and PoshC2 carry `evidence` of at least 2; the Microsoft and burst decoys, if
   they alert at all, carry 0.
5. Tests for each fact, the fan-out derivation and the `evidence` count. `pytest` passes.

## Phase 4: DNS tunnelling

A DNS tunnel carries data in query names (long, random-looking subdomains of one domain) and in TXT/NULL answers, at a
query rate no person produces.

- **Data.** tshark's full EK output already includes `dns.qry.name`, `dns.qry.type` and `dns.resp.len`. Check the
  names `PacketCapture.unwrap` produces before matching them (phase 3 found they are not the dotted Wireshark names).
  The CTU-13 captures are header-only, so they can't be used here.
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
  phase 6 escaped and marked as untrusted.

### Acceptance criteria

1. The injected tunnel (1,500 TXT queries over 60 s, 60-character random labels under `exfil.example.net`) raises
   `dns_tunnel` and `dns_txt_burst` for VICTIM within 60 s.
2. CIC-Bell-DNS-EXF-2021: light and heavy exfiltration are detected. Report the per-file detection rate, and the false
   alarms on its benign captures. This needs the UNB download form, so the user downloads it by hand.
3. DARPA weeks 1 and 3 and week 5 (benign DNS, including the hume storm in week 5): no `dns_tunnel` alert. Record what
   `dns_txt_burst` raises.
4. Tests for the base-domain function, each column and each rule. `pytest` passes.

## Phase 5: hour-of-day baselines (lowest priority)

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

## Phase 6: LLM triage of incidents

Our evaluation and published work (Houssel et al. 2024, about 50% accuracy on flow records, which is chance) agree: an
LLM reading raw rows adds nothing to detection. Its use is explaining incidents the coded detector has already raised,
so a person can decide faster.

- New script `triage.py incidents.jsonl windows.csv hosts.csv [contacts.csv] [facts.csv] -o triaged.jsonl`.
  - It is optional: `anthropic` goes in `requirements-triage.txt`, not `requirements.txt`, and `detect.py` stays
    stdlib-only.
- Context per incident:
  - the incident and its alerts, with their `evidence` facts
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
- **Prompt injection.** DNS names, SNI, user agents, URIs and any future payload fields are attacker-controlled. They go
  in a marked data block, the model has no tools, and the output is parsed as JSON only.
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
- **Threat-intelligence blocklist matching.** Cheap to add later, but it cannot be validated on these captures: lab
  C2 servers are on no list.
- **Supervised models trained on the public datasets.** They would learn dataset artifacts, such as DARPA's TTL and
  timing quirks, instead of attacks.
- **Payload inspection beyond DNS.** Exploits and web attacks need a signature IDS such as Suricata or Zeek. Zeek and
  RITA remain worth running alongside; RITA's scores above are the reference our scorer is measured against, not a
  dependency.
