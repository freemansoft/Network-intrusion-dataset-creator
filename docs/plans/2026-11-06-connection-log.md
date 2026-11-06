# Plan: the connection log as the primary output

Status: proposed 2026-11-06. Supersedes the window-summary framing; see the README section "What the window-summary
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

## Step 1: `connections.csv` (`-oc`, `--connfile`)

One row per connection, written by `TimesAndCounts` from a new `connections.ConnectionTable` that
`analyze_update_window` feeds every packet, like `WindowHosts`. No new process or queue.

**Keying and orientation.**

- TCP: the 5-tuple. A connection starts at a SYN without ACK; its sender is the originator. A TCP packet with no
  prior SYN in the table starts a row with `initiated = 0` and the lower port as the responder side (capture started
  mid-connection, or the SYN was lost).
- UDP: the 5-tuple. Originator is the sender of the first packet. `initiated = 1` only under the rule `hosts.csv`
  already uses (destination port below 1024 and not above the source port), so DNS and NTP clients are originators
  and high-port-to-high-port traffic is recorded but not called a contact.
- ICMP and ICMPv6: keyed by (src, dst, type). An echo request starts a row with `initiated = 1`; the reply joins it.
  Errors (unreachable, time exceeded) are rows of their own, so `unknown_inbound_source` and the beacon scorer can
  ignore them.
- ARP, IGMP and IP fragments stay in `windows.csv` only.
- Active-mode FTP data: a SYN from source port 20 is recorded with `dport = ftpdata`, and `hosts.csv` gets the same
  fix in `contacted_ports` and `new_contacted_ports`, as the earlier phase 2 specified.

**End of a connection.** TCP: both sides' FIN or either side's RST, then `conn_linger_sec` (default 5) with no
packets; or `conn_idle_sec` (default 300) with no packets. UDP and ICMP: `conn_idle_udp_sec` (default 60) idle. All
remaining rows are written at end of input with `state` saying they were cut off. Idle checks run at each window
flush, so memory is bounded by the number of connections active within the idle time.

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
and `json.loads` keeps the last, so `cert_not_before` needs the duplicate recovered in `capture.py` before
`json.loads` or is left empty with the limit documented. Self-signed is issuer equals subject. The CTU-13 captures are
header-truncated, so these columns are empty there.

**Scope.** Default is every connection with a home address on either side (`--conn-scope home|all`). Outbound-only
is a filter in the reader, not the writer, because `unknown_inbound_source` needs inbound rows.

**Cost.** One dict lookup per packet and one row per connection. Measure on DARPA week 5 Monday (22 h) and PoshC2
24 h; the pass must stay within 25% of today's time, or the table moves to a fifth process.

### Acceptance criteria

1. On the fixture captures, every TCP connection with a visible handshake has the right originator, byte counts each
   way and `state`; the FTP fixture shows `ftpdata`; an ICMP error does not join the echo row it quotes.
2. On PoshC2, the C2 pair's rows carry `tls_sni` empty, a JA3, `tls_version` 1.0 and `cert_self_signed = 1` on the
   rows with a certificate; on Backoff, `http_host` is the bare C2 IP. DARPA week 5 rows carry HTTP facts and no TLS.
3. `windows.csv` and `hosts.csv` are byte-identical to today's on every registered dataset except for the `ftpdata`
   change in two `hosts.csv` columns.
4. Runtime within 25% of today's on the two captures above.
5. `tools/eval/run.py` passes `-oc` and hands `connections.csv` to `detect.py`; `classify_inputs` recognizes the file
   by its header.
6. Tests for the table (start, end, states, orientation, idle, cut-off), each handshake column and the fix in
   `hosts.csv`. `pytest` passes.

## Step 2: beacons, from the connection log

The design is the one already written in the superseded plan's phase 1 (`beacons.py`, coverage as the primary score,
minimum gap, SYN-retry collapsing, multicast exclusion, shipped allowlist, popularity filter, suppressions keyed on
(kind, host, peer)), with the inputs changed: an attempt is a connection row with `initiated = 1`, retries are already
counted in `syn_retries`, and the per-pair facts are the connection's own TLS/HTTP columns. There is no separate
contacts or facts file.

`detect.py --connections connections.csv` runs the scorer at end of input and attaches `evidence` (no SNI,
single-destination JA3, self-signed certificate, bare-IP Host, single-destination user agent) to every `beacon`
alert.

### Acceptance criteria

Criteria 1-8 of the superseded plan's phase 1, unchanged, plus:

9. Backoff and PoshC2 beacon alerts carry `evidence` of at least 2; the Microsoft and burst decoys, if they alert
   before the allowlist and filters, carry 0.

## Keep or archive

Decide after step 2, on these numbers, all from `tools/eval/run.py` and `tools/eval/reference/`:

| Question | Continue if | Archive if |
| - | - | - |
| Does our scorer beat the reference where it falls short? | The C2 is ranked first on PoshC2 24 h and above every NTP server on IoT-23 (RITA's formula: 18 and 9) | It does not, and the design constraints from the investigation were applied |
| Is it quiet enough on real background? | Criteria 5 and 6 of phase 1 are met (at most 5 pairs on CTU-5 and CTU-11, at most 1 pair per DARPA attack-free day) | More than twice those numbers after the allowlist and popularity filter |
| Does the log add anything the summaries did not? | At least one labeled attack on a registered dataset is detected from `connections.csv` that was not detected before | Nothing new is detected |

If the answer is archive: the README says so at the top, the harness stays as the deliverable, and the connection log
is kept as a feature extractor for other tools. Nothing in steps 3-5 is started.

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
