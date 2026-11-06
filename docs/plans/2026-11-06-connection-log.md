# Plan: the connection log as the primary output

Status: archived 2026-11-06. Steps 0, 1 and 2 are done (results below each); the keep-or-archive test came out
mixed and the decision was to archive, so steps 3-5 were not started. Supersedes the window-summary framing; see the README section "What the window-summary
approach is and isn't good for" and the findings kept in `docs/plans/2026-11-05-deferred-detection.md`.

## Why

Every detection that was not a flood came from per-host state, and every detection still wanted (C2 beacons,
long-horizon host profiles, TLS/HTTP corroboration, DNS tunnels) needs per-connection records: when each host
contacted each destination, what was exchanged, and what the handshake said. A time-window summary cannot hold those
whatever its columns. The earlier plan was adding them one output at a time (`contacts.csv`, `facts.csv`, a profile
file). This plan replaces those with one connection log, which is also the natural input for an LLM triage step,
since an analyst-readable record of "who talked to whom, when, how much, and what it looked like" is what a model can
reason about.

This may be the project's last detection phase. The decision rule for continuing is written down in "Keep or archive"
below so the choice is measured, not felt.

## What stays

- The pipeline (`tshark -T ek` → capture → detectors → services → counts), fork-only, one process per stage.
- `windows.csv` and `hosts.csv`, produced in the same pass as today. The per-host rules in `detect.py` work and are
  not rewritten. They are "derived" in the sense that nothing new goes into them; new columns go into the connection
  log.
- `tools/eval/`: datasets, labels, injection, scoring. It gains the connection log as an input and otherwise does not
  change.

## Step 0: make the yardstick durable

The RITA reference ranks (C2 at 1, 1, 18, 1 on the Active Countermeasures captures and 9 on IoT-23) came from a
reimplementation of RITA v5's beacon formula that lives only in a session scratchpad. Copy it into
`tools/eval/reference/rita_beacon.py` with a README that says what it is: a comparison baseline run on Zeek
`conn.log`, not a dependency of the detector. Record the command that produced each rank. Zeek is required to run it
and is not required for anything else.

Done 2026-11-06: `tools/eval/reference/` (`run.sh`, `rita_beacon.py`, README). The ranks reproduce exactly.

## Step 1: `connections.csv` (`-oc`, `--connfile`)

One row per connection, written by `TimesAndCounts` from a new `connections.ConnectionTable` that
`analyze_update_window` feeds every packet, like `WindowHosts`. No new process or queue.

**Keying and orientation.**

- TCP: the 5-tuple. A connection starts at a SYN without ACK; its sender is the originator. A TCP packet with no
  prior SYN in the table starts a row with `initiated = 0` and the lower port as the responder side (capture started
  mid-connection, or the SYN was lost).
- UDP: the 5-tuple. The client by the rule `hosts.csv` already uses (destination port below 1024 and not above the
  source port) is the originator, with `initiated = 1` when its packet was the first seen (a reply seen first gives
  `initiated = 0`). Between two high ports the first sender is the originator with `initiated = 0`, so that traffic
  is recorded but not called a contact.
- ICMP and ICMPv6: an echo request and its replies share a row (`initiated = 1` when the request was seen); every
  other type (errors, neighbor discovery) is a row per (src, dst, type, code), so `unknown_inbound_source` and the
  beacon scorer can ignore them. As in Zeek, `sport` holds the type and `dport` the code.
- ARP, IGMP and IP fragments stay in `windows.csv` only.
- Active-mode FTP data: the connection log keeps the real ports (the row's `sport` of 20 identifies it), and readers
  collapse it. `hosts.csv` records a SYN from source port 20 as port `ftpdata` in `contacted_ports` and
  `new_contacted_ports`, as the earlier phase 2 specified.

**End of a connection.** TCP: both sides' FIN or either side's RST, then `conn_linger_sec` (default 5) with no
packets; or `conn_idle_sec` (default 300) with no packets. UDP and ICMP: `conn_idle_udp_sec` (default 60) idle. A
SYN from the originator after the responder answered starts a new connection (port reuse); before that it is a
retry. The end is checked when the connection's next packet arrives, so rows do not depend on window boundaries; a
sweep at each window flush only frees memory. Rows still open at end of input are written then (TCP `S1` or `OTH`
says the connection never closed).

**Columns.**

| Column | Meaning |
| - | - |
| `start_msec`, `end_msec` | first and last packet |
| `src`, `sport`, `dst`, `dport`, `proto` | originator and responder; `proto` is tcp, udp or icmp |
| `initiated` | 1 when the originator is known from a SYN, the UDP port rule or an echo request |
| `src_home`, `dst_home` | `--home-net` membership |
| `service` | names from `services.py` seen on the connection, joined with `+` |
| `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in` | originator to responder and back, `frame.len` bytes |
| `state` | TCP: `S0` (no answer), `REJ` (RST to the SYN), `SF` (handshake and close), `S1` (established, not closed), `RSTO`/`RSTR` (reset by originator/responder), `OTH` (no SYN seen). UDP and ICMP: `SF` if answered else `S0`. Zeek's names, so anyone who knows `conn.log` can read ours |
| `syn_retries` | SYNs beyond the first; the beacon scorer collapses them |
| `tls_sni`, `tls_ja3`, `tls_version`, `cert_self_signed`, `cert_not_before`, `cert_not_after` | from the first ClientHello and certificate on the connection; empty when not seen |
| `http_requests`, `http_host`, `http_user_agent`, `http_uri` | first request's values and the request count |
| `label` | labeled attacks overlapping the connection for either address (`--labels`) |

Rows are written when the connection ends, so the file is in end-time order; readers sort by `start_msec`.

**Parser notes carried over from the TLS/HTTP investigation.** `capture.unwrap` produces
`tls.handshake_extensions_server_name`, `tls.handshake_ja3`, `http.host`, `http.user_agent`, `http.request_uri`,
`x509af.*` (not the Wireshark dotted names); look up those. tshark 4.0.1 emits `x509af_utcTime` twice at one level
and `json.loads` keeps the last; `capture.py` parses lines containing that key with an `object_pairs_hook` that also
keeps both under `x509af.utcTime_all` (in a chain, each holds a list with the leaf first). tshark has no self-signed
flag: a one-certificate chain whose issuer and subject name attributes are equal counts as self-signed, and longer
chains do not. The CTU-13 captures are header-truncated, so these columns are empty there.

**Scope.** Default is every connection with a home address on either side (`--conn-scope home|all`). Outbound-only
is a filter in the reader, not the writer, because `unknown_inbound_source` needs inbound rows.

**Cost.** One dict lookup per packet and one row per connection, in the counts process. Simplicity wins over speed:
the table stays in that process whatever it costs. Record the runtime on DARPA week 5 Monday (22 h) and PoshC2 24 h
before and after, so the cost is known.

### Acceptance criteria

1. Every TCP connection with a visible handshake has the right originator, byte counts each way and `state`; a SYN
   from port 20 counts once in `hosts.csv`; an ICMP error does not join the echo row it quotes (unit tests and the
   `icmp_mix` fixture).
2. On PoshC2, the C2 pair's rows carry `tls_sni` empty, a JA3, `tls_version` 1.0 and `cert_self_signed = 1` on the
   rows with a certificate; on Backoff, `http_host` is the bare C2 IP. DARPA week 5 rows carry HTTP facts and no TLS.
3. `windows.csv` and `hosts.csv` are byte-identical to today's on every registered dataset except for the `ftpdata`
   change in two `hosts.csv` columns.
4. `tools/eval/run.py` passes `-oc` and hands `connections.csv` to `detect.py`; `classify_inputs` recognizes the file
   by its header (and ignores it until step 2).
5. Tests for the table (start, end, states, orientation, idle, cut-off), each handshake column and the fix in
   `hosts.csv`. `pytest` passes.

### Step 1 results (2026-11-06)

| Criterion | Result |
| - | - |
| 1. Orientation, bytes, states; `ftpdata`; ICMP errors separate | Met: 15 unit tests in `tests/connections_test.py`, the `icmp_mix` pipeline test and a `hosts.csv` test |
| 2. Handshake facts on the C2s | Met. PoshC2 1 h: the C2 is the only destination with ClientHellos lacking SNI (26 connections) and the only self-signed certificate of 41 seen, TLS1.0, valid from 1617423658 for 10 years. Backoff 1 h: the C2 is the only bare-IP `http_host` (126 requests, user agent and `/updates` URI on every row). DARPA week 5: 24,558 rows with HTTP facts, none with TLS |
| 3. `windows.csv` and `hosts.csv` unchanged except `ftpdata` | Met. Identical on PoshC2 24 h, Backoff 24 h and IoT-23. DARPA week 5 differs only in `contacted_ports` and `new_contacted_ports` (411 host rows, all decreases) and the two window columns derived from them, all on the 7 hosts that open FTP data connections from port 20 |
| 4. Harness passes `-oc`; `classify_inputs` recognizes the file | Met |
| 5. Tests | Met: 81 passing |

Agreement with Zeek on the C2 pairs: Backoff 1 h has 126 `SF` connections in both, and the 8 `OTH` rows (a lone ACK about 10 s after each close) appear in both; Zeek also writes the stray FIN before each as an `SH` row of its own, where ours folds it into the closed connection. PoshC2 1 h has 26 `SF` TLS connections in both.

Runtime, `main` vs this branch, same machine, one run each: DARPA week 5 367 s vs 356 s, PoshC2 24 h 53 s vs 54 s, Backoff 24 h 26 s vs 37 s, IoT-23 82 s vs 82 s. The connection table costs nothing measurable on three of four; the Backoff difference is within run-to-run noise for a 26 s run. Rows: 231,647 (DARPA week 5), 19,603 (PoshC2 24 h), 8,886 (Backoff 24 h), 6,243 (IoT-23).

## Step 2: beacons, from the connection log

The design is the one already written in the superseded plan's phase 1 (`beacons.py`, coverage as the primary score,
minimum gap, SYN-retry collapsing, multicast exclusion, shipped allowlist, popularity filter, suppressions keyed on
(kind, host, peer)), with the inputs changed: an attempt is a connection row with `initiated = 1`, retries are already
counted in `syn_retries`, and the per-pair facts are the connection's own TLS/HTTP columns. There is no separate
contacts or facts file.

`detect.py` recognizes a connections file by its header, runs the scorer on each file separately (each is one
recording, so two captures days apart are not one beacon span) and attaches `evidence` (no SNI,
single-destination JA3, self-signed certificate, bare-IP Host, single-destination user agent) to every `beacon`
alert.

### Acceptance criteria

Criteria 1-8 of the superseded plan's phase 1, unchanged, plus:

9. Backoff and PoshC2 beacon alerts carry `evidence` of at least 2; the Microsoft and burst decoys, if they alert
   before the allowlist and filters, carry 0.

### Step 2 results (2026-11-06)

Measured with `tools/eval/run.py` on the final code, `beacon_allow.txt` holding only `udp/123` (NTP).

| Criterion | Result |
| - | - |
| 1. Backoff and PoshC2 24 h alert | Met, each naming the implant host and C2 |
| 2. Backoff and PoshC2 1 h alert | Met |
| 3. Neither decoy alerts | Partly. The PoshC2 2 s bursts are stopped by the minimum gap. The Backoff Microsoft pair (52.184.216.174:443) alerts, because the allowlist deliberately has no vendor networks; it has evidence 0 |
| 4. Mirai C2 raises `beacon` | Not met. Its contacts cover about 37% of the day, below the coverage minimum. It is still detected by `failed_connections`. NTP is quiet only because of the allowlist |
| 5. Injected beacon alerts; at most 5 pairs on CTU | Injected beacon met. False pairs: 14 on the injected capture, 35 on CTU-5, 28 on CTU-11. They are BitTorrent peers (6881, 6889), web polling on 80 and 443 (Google, ad and CDN servers) and one SSH session. The CTU captures hold headers only, so none has evidence |
| 6. At most 1 pair per DARPA attack-free day | Not met: 14 alerts in 10 days, 2 on 4 of the days. Ten are one host polling the TIME protocol (RFC 868, tcp/37) every 20 minutes; four are web pairs. Allowlisting tcp/37 would meet it, but was not done after seeing the result |
| 7. Tests | Met, 94 pass |
| 8. C2 first by score | PoshC2 24 h 1st (RITA's formula: 18th), PoshC2 1 h 1st, Backoff 1 h 1st, Backoff 24 h 2nd by 0.001 (behind an 11-contact Microsoft poll), IoT-23 7th with NTP 1st (RITA: 9th) |
| 9. C2 evidence at least 2, decoys 0 | Met. Every C2 alert has 2 or 3 facts; every benign beacon pair on every dataset has 0 |

Other detections are unchanged: DARPA week 5 10 of 26 (0.03% false-alarm windows with learned suppressions, 0.76%
without, against 0.80% on `main`; the difference was not traced, the FTP-data port change in step 1 is the likely
cause), injected capture 6 of 7 (the beacon is now found, the DNS tunnel is not), CTU-5 0.83%, IoT-23 5 of 5 at 0.03%,
LLDoS 1 of 5 at 0.43%.

Every false beacon pair above has evidence 0. Requiring evidence of at least 1 would therefore leave none on the
captures with full packets (Active Countermeasures, DARPA) and still catch every C2 there, but it would also hide the
injected beacon on the header-only CTU capture. That gate was not implemented.

## Keep or archive

Decide after step 2, on these numbers, all from `tools/eval/run.py` and `tools/eval/reference/`:

| Question | Continue if | Archive if |
| - | - | - |
| Does our scorer beat the reference where it falls short? | The C2 is ranked first on PoshC2 24 h and above every NTP server on IoT-23 (RITA's formula: 18 and 9) | It does not, and the design constraints from the investigation were applied |
| Is it quiet enough on real background? | Criteria 5 and 6 of phase 1 are met (at most 5 pairs on CTU-5 and CTU-11, at most 1 pair per DARPA attack-free day) | More than twice those numbers after the allowlist and popularity filter |
| Does the log add anything the summaries did not? | At least one labeled attack on a registered dataset is detected from `connections.csv` that was not detected before | Nothing new is detected |

If the answer is archive: the README says so at the top, the harness stays as the deliverable, and the connection log
is kept as a feature extractor for other tools. Nothing in steps 3-5 is started.

### Decision (2026-11-06): archive

| Question | Result | Verdict |
| - | - | - |
| Beats the reference where it falls short | PoshC2 24 h: 1st against RITA's 18th. IoT-23: 7th, below NTP | Half; the continue condition needs both |
| Quiet enough on real background | CTU: 14, 35 and 28 pairs against a limit of 5. DARPA attack-free: 14 in 10 days | Archive: CTU is more than twice the limit |
| Adds something the summaries did not | All four Active Countermeasures beacon labels and the injected beacon, none detected before | Continue |

Timing finds beacons, but on a real network most beacons are benign: software updaters, ad and CDN polls, P2P peers
and time protocols. What separated the C2 servers from them was the TLS/HTTP evidence, which needs full packets and is
what Zeek's logs with RITA or AC-Hunter already provide from live traffic. The project is archived as informational:
the README says so at the top, `tools/eval/` and the connection log stay as they are, and steps 3-5 are not started.

## Step 3: host profiles

The superseded plan's phase 2, with the profile learned from `connections.csv` instead of a contacts file:
`unknown_inbound_source` (answered rows only, that is `state` not `S0` or `REJ`), `unknown_home_source`,
`novel_port`. Its acceptance criteria stand (at least 16 of 26 DARPA week 5 labels with the week 1-3 profile, at most
20 false-alarm buckets; leave-one-day-out limits).

## Step 4: DNS

A second log, `dns.csv` (`-od`), one row per query with its answer when seen: `time_msec`, `src`, `dst`, `qry_name`,
`qry_type`, `rcode`, `answers`, `resp_len`. It is separate because one UDP 5-tuple carries many queries. The tunnel
rules and the base-domain function are the superseded plan's phase 4, reading this file; `dns_answered` for a
connection (some answer mapped a name to its destination) is computed by `detect.py` from the two logs, not stored.
Same acceptance criteria.

## Step 5: LLM triage

Annotate only, never create alerts, as the earlier analysis concluded. The connection log makes the input concrete:
for each incident, `detect.py --evidence DIR` writes a text pack with the alert, the host's connections in the 10
minutes around it (sorted, capped at 200 rows, columns as above), its profile deltas and DNS rows if available, with
every string from the wire (SNI, Host, user agent, URI, query names) escaped and marked as untrusted data. A separate
`triage.py` sends the pack to a model with a fixed rubric (benign explanation, suspicious, needs a person; cite the
rows) and writes the answer beside the incident. Measured on the same labels: how often the model's call agrees with
the label, on both detected attacks and the identified false alarms from the criteria above.

Not started unless the keep-or-archive decision is "keep".

## Not planned

Unchanged from the superseded plan: threat-intelligence feeds, supervised models trained on the public datasets,
payload inspection beyond DNS, hour-of-day baselines (only if DARPA volume alerts cluster by time of day, which phase
0 did not show).
