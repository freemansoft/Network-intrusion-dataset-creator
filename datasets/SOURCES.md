# Labeled intrusion captures: provenance

This file records where each capture in `datasets/` came from and what its ground truth says. Everything else in
`datasets/` is gitignored, so this file is the only record that is committed. The files were downloaded on 2026-11-05 with
`curl -L --fail -C -`. Compressed downloads (`.gz`, `.bz2`) were decompressed and then deleted. The SHA-256 of each
original archive is listed so you can check a fresh download against it.

Packet counts and time spans come from `capinfos` (Wireshark 4.x, `/Applications/Wireshark.app/Contents/MacOS/capinfos`).
All epoch values are UTC seconds. For every capture, the label clock was checked against the pcap clock by finding
labeled attacker/victim packets in the pcap (see each section).

| Dataset dir | Capture(s) | Attack classes | Has benign background in same pcap? |
| --- | --- | --- | --- |
| `darpa1999-week5-monday/` | outside + inside tcpdump, 22 h | port sweep, IP sweep, SYN flood (neptune), smurf, UDP storm, apache2 DoS, telnet/password guessing, dict brute force, misc DoS/R2L/U2R | Yes, synthetic (simulated Air Force base LAN) |
| `darpa2000-lldos1.0/` | inside + DMZ tcpdump, 3.2 h | IP sweep, sadmind probe, exploit, trojan install (DDoS C2), mstream DDoS | Yes, synthetic |
| `ctu13-scenario11-rbot-icmp-ddos/` | full router capture, headers only, 16 min | IRC botnet C2 + volumetric ICMP DDoS | Yes, real university traffic |
| `ctu13-scenario5-virut/` | full router capture, headers only, 30 min | botnet C2 (HTTP/IRC), spam, proxying | Yes, real university traffic |
| `iot23-34-1-mirai/` | single infected IoT device, 24 h | Mirai C2 beaconing, TCP/UDP floods (DDoS), "port scan" | Only the device's own NTP/DNS (no other hosts) |

**Not covered:** exfiltration and worm propagation (see "Tried and skipped" at the end).

---

## 1. DARPA 1999 IDEVAL, test week 5, Monday (1999-04-05)

- **Citation:** R. Lippmann, J. W. Haines, D. J. Fried, J. Korba, K. Das, "The 1999 DARPA off-line intrusion detection
  evaluation," *Computer Networks* 34(4):579-595, 2000. MIT Lincoln Laboratory.
- **Landing page:** https://archive.ll.mit.edu/ideval/data/1999data.html (week 5:
  https://archive.ll.mit.edu/ideval/data/1999/testing/week5/index.html; docs: https://archive.ll.mit.edu/ideval/docs/index.html)
- **License/terms:** no explicit license on the site. MIT Lincoln Laboratory released it publicly for IDS research with no
  registration. Cite the paper above.
- **Network:** simulated "Eyrie AFB". Inside hosts are 172.16.112-115.x. The "outside" sniffer sits between the router
  and the Internet; the "inside" sniffer is on the internal LAN.

| Local path | Direct download URL | Size (bytes) | SHA-256 | Packets | Span (UTC epoch) | Span (human) |
| --- | --- | --- | --- | --- | --- | --- |
| `darpa1999-week5-monday/w5-monday-outside.pcap` | https://archive.ll.mit.edu/ideval/data/1999/testing/week5/monday/outside.tcpdump.gz | 344,257,810 | `867df6c2f00ceb354c9930eed831ae447bd8af73fb21a9b119f864bb6f1695ae` | 1,376,598 | 923313603.18-923392800.55 (79,197 s) | 1999-04-05 12:00:03 to 04-06 10:00:00 UTC (08:00 to 06:00 EDT) |
| `darpa1999-week5-monday/w5-monday-inside.pcap` | https://archive.ll.mit.edu/ideval/data/1999/testing/week5/monday/inside.tcpdump.gz | 477,303,765 | `8c1e64898e1eb651424fdaba7d8f01c61ab6943ece29194d4c842f8eaf1c0da5` | 2,291,319 | 923313602.81-923392796.18 (79,193 s) | same day, inside sniffer |
| `darpa1999-week5-monday/master_identifications.list` (labels) | https://archive.ll.mit.edu/ideval/files/master_identifications.list | 46,119 | `a846461887d3d9f9203137d631ac001648b9ecec97d21c4edc88ee19db5e9335` | | | |
| `darpa1999-week5-monday/master-listfile-condensed.txt` (detection-scoring truth) | https://archive.ll.mit.edu/ideval/files/master-listfile-condensed.txt | 274,885 | `1096218e9656c4d293d4f0fb2fb5487675658699240a08459ce1fb39c384e061` | | | |

SHA-256 of the archives as downloaded: `outside.tcpdump.gz` = `ba721025b057a22935865cdfd5d226c4e26080d75dab6bdad5b3837a9263257e`
(122,874,934 B), `inside.tcpdump.gz` = `e9faabc4893963ce1c1b1b9f17cd6627f27f3c891404156334f2f615563f65c3` (146,149,321 B).
Both are classic pcap, big-endian, snaplen 66000, Ethernet.

**Where the labels came from:** `master_identifications.list` (the identification truth for weeks 4-5). Each entry gives
ID, date, start time, duration, attacker, victim and ports. All entries dated 04/05/1999 are listed below.
`master-listfile-condensed.txt` is the detection-scoring truth: overlapping sessions are aggregated, and its header explains
the fields.

**Timezone gotcha:** label times are US Eastern *local* time. US DST began 1999-04-04, so **week 5 is EDT (UTC-4)**
and week 4 (Mar 29-Apr 2) is EST (UTC-5). This was verified: in the outside pcap, the labeled attacker/victim packets
start exactly at the label time + 4 h (for example, pod 08:39:52 EDT has its first packet at 12:39:52 UTC). The site says the
first packet is at 08:00:02 local, and the pcap's first packet is at 12:00:02 UTC.

**Clock gotcha:** the inside sniffer's clock lags the outside one by about 2-3 s at 12:40 UTC, and the lag grows to about
10 s by 00:17 UTC (pod: 12:39:50 inside vs 12:39:52 outside; neptune: 22:03:55 vs 22:04:04; selfping: 00:17:02 vs 00:17:12).
Label times follow the outside clock. When scoring inside-only attacks, pad windows by about 15 s. In the table below,
dict, ncftp and loadmodule start 7-16 s earlier in the inside pcap than their label times.

Attack intervals. Start/end = label start and start + duration. The "pkts out / in" columns count packets between the
labeled attacker and victim (either direction) within the window ±120 s, in the outside and inside pcaps. Use them to
decide which file to use for each attack.

| ID | Attack | Class | Start epoch | End epoch | UTC | EDT (label) | Attacker | Victim | pkts out / in |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 51.083800 | pod | dos | 923315992 | 923316002 | 12:39:52-12:40:02 | 08:39:52-08:40:02 | 202.77.162.213 | 172.16.112.50 | 186 / 186 |
| 51.084334 | portsweep | probe | 923316197 | 923316430 | 12:43:17-12:47:10 | 08:43:17-08:47:10 | 172.16.118.10 | 192.168.1.1 | 0 / 3 (barely visible) |
| 51.085000 | pod | dos | 923316513 | 923316544 | 12:48:33-12:49:04 | 08:48:33-08:49:04 | 202.77.162.213 | 172.16.114.50 | 91 / 91 |
| 51.085947 | warezclient | dos | 923317156 | 923317197 | 12:59:16-12:59:57 | 08:59:16-08:59:57 | 207.75.239.115 | 172.16.112.50 | 273 / 273 |
| 51.093123 | smurf | dos | 923319180 | 923319300 | 13:33:00-13:35:00 | 09:33:00-09:35:00 | many spoofed amplifiers ("login.session.x.x") | 172.16.112.50 | inside only: 6,000 ICMP from 1,531 srcs, 13:34:10-13:34:14 UTC (inside clock) |
| 51.094334 | portsweep | probe | 923319791 | 923320014 | 13:43:11-13:46:54 | 09:43:11-09:46:54 | 208.240.124.83 | 172.16.112.50 | 200 / 200 |
| 51.102700 | apache2 | dos | 923322562 | 923323619 | 14:29:22-14:46:59 | 10:29:22-10:46:59 | 202.77.162.213 | 172.16.114.50 | 87,572 / 91,059 |
| 51.105811 | guesstelnet | r2l (password guessing) | 923324294 | 923324494 | 14:58:14-15:01:34 | 10:58:14-11:01:34 | 192.5.41.239 | 172.16.118.80 | 1,200 / 1,200 |
| 51.114500 | dosnuke | dos | 923327127 | 923327220 | 15:45:27-15:47:00 | 11:45:27-11:47:00 | 172.16.115.234 | 172.16.112.100 | 0 / 19 |
| 51.120309 | loadmodule | u2r | 923328194 | 923328869 | 16:03:14-16:14:29 | 12:03:14-12:14:29 | 172.16.114.207 | 172.16.113.50 | 0 / 2,303 |
| 51.121101 | ffbconfig | u2r | 923328678 | 923329426 | 16:11:18-16:23:46 | 12:11:18-12:23:46 | 135.13.216.191 | 172.16.112.50 | 4,171 / 4,171 |
| 51.131803 | smurf | dos | 923332692 | 923332693 | 17:18:12-17:18:13 | 13:18:12-13:18:13 | 23.234.78.52 | 172.16.114.50 | 5 / 6 |
| 51.133019 | arppoison | probe | 923333414 | 923334291 | 17:30:14-17:44:51 | 13:30:14-13:44:51 | 152.169.215.104 | 172.16.112.100 | ARP only (no IP pair to count) |
| 51.140100 | apache2 | dos | 923335543 | 923336212 | 18:05:43-18:16:52 | 14:05:43-14:16:52 | 152.169.215.104 | 172.16.114.50 | 53,931 / 55,351 |
| 51.142100 | pod | dos | 923336550 | 923336551 | 18:22:30-18:22:31 | 14:22:30-14:22:31 | 10.11.22.33 | 172.16.113.50 | 135 / 135 |
| 51.144601 | imap | r2l | 923337979 | 923337989 | 18:46:19-18:46:29 | 14:46:19-14:46:29 | 172.16.117.103 | 172.16.114.50 | 0 / 15 |
| 51.150000 | ipsweep | probe | 923338816 | 923339737 | 19:00:16-19:15:37 | 15:00:16-15:15:37 | 128.223.199.68, 204.71.51.16, 207.114.237.57, 209.1.12.46 (+2 more listed) | 172.16.113.1, .3-.5, .50, 204.233.47.21 | very slow sweep: 4 ICMP outside, 0 inside |
| 51.163200 | dict | r2l (brute force) | 923344337 | 923345332 | 20:32:17-20:48:52 | 16:32:17-16:48:52 | 172.16.118.10 | 172.16.114.50 | 0 / 6,269 |
| 51.171917 | syslogd | dos | 923347150 | 923347151 | 21:19:10-21:19:11 | 17:19:10-17:19:11 | 172.5.3.5 (spoofed) | 172.16.112.50 | 1 / 1 |
| 51.180445 | neptune | dos (SYN flood) | 923349844 | 923350255 | 22:04:04-22:10:55 | 18:04:04-18:10:55 | 10.20.30.40 (spoofed) | 172.16.112.50 | 20,480 / 42,152 |
| 51.183623 | crashiis | dos | 923351771 | 923351778 | 22:36:11-22:36:18 | 18:36:11-18:36:18 | 202.72.1.77 | 172.16.112.100 | 7 / 7 |
| 51.185613 | ls | probe | 923353041 | 923353042 | 22:57:21-22:57:22 | 18:57:21-18:57:22 | 195.73.151.50 | 172.16.112.20 | 16 / 16 |
| 51.194715 | dosnuke | dos | 923356081 | 923356182 | 23:48:01-23:49:42 | 19:48:01-19:49:42 | 206.48.44.18 | 172.16.115.234 | 10 / 10 |
| 51.200037 | udpstorm | dos | 923356827 | 923357727 | 00:00:27-00:15:27 (+1 day) | 20:00:27-20:15:27 | 172.16.112.50 (spoofed echo/chargen loop) | 172.16.113.* | inside only: 200,772 UDP/7 pkts |
| 51.201715 | selfping | dos | 923357832 | 923357835 | 00:17:12-00:17:15 (+1 day) | 20:17:12-20:17:15 | 135.13.216.191 | 172.16.112.50 | 225 / 225 |
| 51.204631 | ncftp | r2l | 923359573 | 923359662 | 00:46:13-00:47:42 (+1 day) | 20:46:13-20:47:42 | 172.16.118.70 | 172.16.114.50 | 0 / 423 |

Attacks large enough to plausibly show in 5 s whole-network windows: apache2 (x2), neptune, udpstorm and smurf (inside),
dict (inside), guesstelnet, ffbconfig. Most of the others are only a few packets.

**Known labeling flaws and caveats:**
- The background traffic is synthetic. McHugh (ACM TISSEC 3(4), 2000) and Mahoney & Chan (RAID 2003) showed artifacts that
  make attacks easy to separate, such as TTL and source-address distributions that differ from the background, and
  background with no real-world noise. Results here will look better than they would on real traffic.
- Some entries list hostnames or wildcards instead of IPs (`login.session.x.x`, `172.016.113.*`). Some attacks appear only
  in the inside pcap.
- The ipsweep entry 51.150000 lists six "attackers", and the sweep is extremely slow. Treat it as low-signal.
- IPs in the truth file are zero-padded (`172.016.112.050`); normalize them before matching.

---

## 2. DARPA 2000 LLDOS 1.0 (Lincoln Laboratory Scenario DDoS 1.0), 2000-03-07

- **Citation:** MIT Lincoln Laboratory, "2000 DARPA Intrusion Detection Scenario Specific Data Sets: LLDOS 1.0," J. W. Haines
  et al., 2000.
- **Landing page / attack schedule:** https://archive.ll.mit.edu/ideval/data/2000/LLS_DDOS_1.0.html (saved as
  `LLS_DDOS_1.0.html` and as plain text in `LLS_DDOS_1.0.txt`)
- **License/terms:** same as DARPA 1999: public, no registration, no explicit license.
- **Scenario:** a novice attacker at 202.77.162.213 sweeps the base, probes for sadmind, and exploits three Solaris hosts:
  mill 172.16.115.20, pascal 172.16.112.50 and locke 172.16.112.10. The attacker installs mstream, then launches a 5 s DDoS
  with spoofed sources against 131.84.1.31.

| Local path | Direct download URL | Size (bytes) | SHA-256 | Packets | Span (UTC epoch) | Span (human) |
| --- | --- | --- | --- | --- | --- | --- |
| `darpa2000-lldos1.0/LLS_DDOS_1.0-inside.pcap` | https://archive.ll.mit.edu/ideval/data/2000/LLS_DDOS_1.0/data_and_labeling/tcpdump_inside/LLS_DDOS_1.0-inside.dump.gz | 122,082,178 | `9cc091e30b2827764f51deb96d619e5f9877c8fe21efd4c33735e25df60ab49b` | 649,787 | 952438896.48-952450548.48 (11,652 s) | 2000-03-07 14:21:36-17:35:48 UTC (09:21:36-12:35:48 EST) |
| `darpa2000-lldos1.0/LLS_DDOS_1.0-dmz.pcap` | https://archive.ll.mit.edu/ideval/data/2000/LLS_DDOS_1.0/data_and_labeling/tcpdump_dmz/LLS_DDOS_1.0-dmz.dump.gz | 89,444,394 | `3b7e8f63953c42105802863f44ea812436c548cfa2c878ba98dc1e2d36ed6db3` | 394,089 | 952438845.04-952450605.00 (11,760 s) | 14:20:45-17:36:45 UTC |
| `darpa2000-lldos1.0/{inside,dmz}-phase-{1..5}.list` (session labels, 1999 listfile format) | `.../data_and_labeling/tcpdump_{inside,dmz}/phase-N.list` | see below | see below | | | |
| `darpa2000-lldos1.0/{inside,dmz}-mid-level-phase-{1..5}.xml` (IDMEF alerts per session) | `.../data_and_labeling/tcpdump_{inside,dmz}/mid-level-phase-N.xml` | see below | see below | | | |

Archive SHA-256: `LLS_DDOS_1.0-inside.dump.gz` = `9f00c8872b1e84a2cf973ea2b706bb5d539b0c7a33d1b964e010f30c01089219` (50,142,969 B),
`LLS_DDOS_1.0-dmz.dump.gz` = `a32e6ac03f9f88783ef45159894dd4ec2b0ac7a1a3804535fce340872cb85dd8` (41,341,257 B).

<details><summary>Label file sizes and SHA-256</summary>

| File | Bytes | SHA-256 |
| --- | --- | --- |
| inside-phase-1.list | 3,472 | `a9c84c3bcf54518f9bcc67af935d37e30fdf96dbc70170078d4a5e64e04ce374` |
| inside-phase-2.list | 3,584 | `7567e06deb677f937c3e95aaf5a594f40061b2f23780a62ff6a4de0bfbbeb33b` |
| inside-phase-3.list | 3,920 | `b20b8bee9d0f35e48f44b2c07a7ac75a8adca3923db3d1ce1518e4ac96088f9a` |
| inside-phase-4.list | 2,464 | `89d14ea2a840f2b4216252e482f18deaf58d98a40c2db857a432fa1cb6ea6112` |
| inside-phase-5.list | 3,784,153 | `fb8db3581bd8f2fa0bead8e86640b334652bb10c1c627c5331b1d37f8fba58a9` |
| dmz-phase-1.list | 87,920 | `07a64c74ffd37ee3ae186c586c6b29a45d06ba597fa206a9f0f00ac1feda44d5` |
| dmz-phase-2.list | 2,800 | `5752b7fecad7b958fe05fd82b4e455a4362155599d292515fc1602d4ef845bef` |
| dmz-phase-3.list | 8,960 | `23580b116487793a3f832a1743c2779f9832e5735871412ac260bd5ef899e57f` |
| dmz-phase-4.list | 2,128 | `9ef6cd52b944946e5913dea867b362b57b5ffb8a88635fe9d756e4880e862766` |
| dmz-phase-5.list | 3,801,625 | `82c1f09bde73ac88896f331b9717f2da27103f5fe46dd9a1983b080463797e6c` |
| inside-mid-level-phase-1.xml | 18,661 | `8e1a8c1fc011417b38b169adaf454a8055e314f1e7737679b3cd05001563fcb2` |
| inside-mid-level-phase-2.xml | 19,895 | `02fc867008b7c6e027287a55b78c86b66ea1b2ac3c11e2646688b8d83d0545a5` |
| inside-mid-level-phase-3.xml | 22,145 | `37056b130f047bc337d16e43676841250c57801f978b90ef6d9323775fddff96` |
| inside-mid-level-phase-4.xml | 13,899 | `dd94be00f60f98fb01742fec9ab1766fbc5b4ce7a9aec5afc0adb9dcc6df1712` |
| inside-mid-level-phase-5.xml | 21,388,275 | `14580eef43ffc000e7b056c8d4e0c620bcae17f2428e58a678e4fc070c3028ea` |
| dmz-mid-level-phase-1.xml | 468,952 | `2afc838e03d9c57190bdeeb2f9edc3fd3457c447b5121aa26075d33a707d850a` |
| dmz-mid-level-phase-2.xml | 15,600 | `96734de629da80a320c243394b349604e1ef9d36e235026bf144151c7050f6f4` |
| dmz-mid-level-phase-3.xml | 49,988 | `6331f51335207fb90b4ccceff5986a1d42f14151306196baf4865b4adca39b8d` |
| dmz-mid-level-phase-4.xml | 11,880 | `7acc0728a116743807a278c5956ac4d1c5494105b440d8ed65f3cb72a4282444` |
| dmz-mid-level-phase-5.xml | 21,283,178 | `521542576bbbdf9b74bf6c49fbc49796b710aef3c64a3d319cb8f719fcec2e0f` |
| LLS_DDOS_1.0.html | 26,555 | `e5d6232cdb351394c470a7461bac1128d5a8a3e901bd4940e89760eae13458a2` |
| LLS_DDOS_1.0.txt (text rendering of the page, made locally) | 13,723 | `a704f07cbe5e9cd180f72928e4155e57673f8facbca70af1e937266be0a663f6` |
</details>

**Where the labels came from:** the per-phase `.list` session files, which give start time, duration, service, ports,
source and destination for every attack session. Intervals below are the min start and max (start + duration) per phase
across the inside and DMZ lists. The exact DDoS flood bounds were measured from the pcaps.

**Timezone:** label times are **EST (UTC-5)**, as the page says. This was verified: the first phase-1 echo request from
202.77.162.213 is at 952440696.14 = 14:51:36 UTC = the label's 09:51:36 EST. The inside and DMZ clocks agree to within
about 0.1 s.

| Phase | Start epoch | End epoch | UTC | EST (label) | Attacker -> victim | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 IPsweep (ICMP echo) | 952440696 | 952440723 | 14:51:36-14:52:03 | 09:51:36-09:52:03 | 202.77.162.213 -> 172.16.112-115.1-254 | 767 echo requests in the DMZ capture, 20 inside |
| 2 sadmind probe (sunrpc/portmap) | 952441627 | 952442285 | 15:07:07-15:18:05 | 10:07:07-10:18:05 | 202.77.162.213 -> live hosts | sparse, about 25-32 sessions |
| 3 sadmind exploit + telnet checks | 952443190 | 952443302 | 15:33:10-15:35:02 | 10:33:10-10:35:02 | 202.77.162.213 -> 172.16.115.20, 172.16.112.50, 172.16.112.10 (+ .114.10/.20/.30 in DMZ) | |
| 4 mstream install (telnet/rcp/rsh) | 952444201 | 952444255 | 15:50:01-15:50:55 | 10:50:01-10:50:55 | 202.77.162.213 <-> the 3 victims; servers register with the master (UDP 9325 broadcast) | |
| 5 DDoS launch (whole phase) | 952446375 | 952447280 | 16:26:15-16:41:20 | 11:26:15-11:41:20 | attacker telnets to the master; then a spoofed-source flood -> 131.84.1.31 | the phase includes control sessions after the flood (11:35-11:41) |
| 5 flood only (measured) | 952446471.15 | 952446477.01 | 16:27:51-16:27:57 | 11:27:51-11:27:57 | 3 mstream servers -> 131.84.1.31, ~33,750 spoofed sources | 73,439 pkts inside in about 6 s; in the DMZ capture the firewall answers with 33,909 RSTs "from" 131.84.1.31 |

**Caveats:** the background traffic is synthetic, with the same generator as 1999, so the DARPA 1999 critiques apply.
hume.eyrie.af.mil sends many spurious DNS queries because its mail server is misconfigured; the page says to ignore them. The
flood lasts only 5 s, which is about one 5 s window.

---

## 3. CTU-13 scenario 11 (CTU-Malware-Capture-Botnet-52): Rbot, ICMP DDoS, 2011-08-18

- **Citation:** S. Garcia, M. Grill, J. Stiborek, A. Zunino, "An empirical comparison of botnet detection methods,"
  *Computers & Security* 45:100-123, 2014.
- **Landing page:** https://www.stratosphereips.org/datasets-ctu13 ; files at https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/
- **License/terms (from the scenario README):** "You are free to use these files as long as you reference this project and
  the authors as follows: Garcia, Sebastian. Malware Capture Facility Project. Retrieved from https://stratosphereips.org".
  No registration.

| Local path | Direct download URL | Size (bytes) | SHA-256 | Packets | Span (UTC epoch) | Span (human) |
| --- | --- | --- | --- | --- | --- | --- |
| `ctu13-scenario11-rbot-icmp-ddos/capture20110818-2.truncated.pcapng` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/capture20110818-2.truncated.pcap.bz2 | 555,301,112 | `85616ecc9122053194ecdae6610f7ad73c620032b3fa6fff4063667c5c48036b` | 6,336,398 | 1313674775.09-1313675746.38 (971 s) | 2011-08-18 13:39:35-13:55:46 UTC (15:39:35-15:55:46 CEST) |
| `ctu13-scenario11-rbot-icmp-ddos/capture20110818-2.binetflow` (labels) | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow | 14,596,615 | `cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c` | | | |
| `ctu13-scenario11-rbot-icmp-ddos/README.md` (timeline) | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/README.md | 5,339 | `30c5d50675523038b49f812071d9940b27add56b953c4af92d19bd5aca7aa876` | | | |

Archive SHA-256: `capture20110818-2.truncated.pcap.bz2` = `19e6afad972e2598e404afe15e9ae4e67073f3bbca90ed12758f2955784fd6fd`
(84,319,605 B). The upstream file is named `.pcap` but is actually **pcapng**, so it was renamed locally.

**What the capture contains:** the *complete* university router capture, with background, normal and botnet traffic. It is
**truncated to headers**: TCP 54 B, UDP 42 B, ICMP 66 B per packet. Original lengths are preserved, so `frame.len` and
`ip.len` are still correct, but there is no payload, so payload-based service detection (HTTP fields, DNS names) won't work.

**Where the labels came from:** the bidirectional Argus `binetflow` (`Label` column). Botnet flows are labeled
`flow=From-Botnet-V52-<n>-...`. The README timeline gives the actions in CEST.

**Timezone:** binetflow `StartTime` and the README are **CEST (UTC+2)**. This was verified: the first flow is at
15:39:35.087798, which equals the first pcap packet at 1313674775.087798.

| Event | Start epoch | End epoch | UTC | CEST | Attacker -> victim | Source |
| --- | --- | --- | --- | --- | --- | --- |
| Infection + C2 bootstrap (DNS, IRC to tcp/6667) | 1313675277.98 | 1313675363.60 | 13:47:57-13:49:23 | 15:47:57-15:49:23 | 147.32.84.165, .191, .192 -> IRC C2 38.229.70.20, 216.155.130.130, 78.40.125.4:6667 | binetflow |
| IRC C2 sessions (long-lived) | 1313675323.35 | 1313675740.19 | 13:48:43-13:55:40 | 15:48:43-15:55:40 | same | binetflow |
| **ICMP DDoS, bot 1** | 1313675575.10 | 1313675676.11 | 13:52:55-13:54:36 | 15:52:55-15:54:36 | 147.32.84.191 -> 147.32.96.69 | binetflow label `From-Botnet-V52-2-ICMP`; pcap: 1,011,699 pkts, 1.06 GB |
| **ICMP DDoS, bot 2** | 1313675594.60 | 1313675695.60 | 13:53:14-13:54:55 | 15:53:14-15:54:55 | 147.32.84.165 -> 147.32.96.69 | label `From-Botnet-V52-1-ICMP`; pcap: 1,016,252 pkts, 1.07 GB |
| **DDoS combined** | 1313675575.10 | 1313675695.60 | 13:52:55-13:54:56 | 15:52:55-15:54:56 | 2 bots -> 147.32.96.69 | about 20,000 pps (about 21 MB/s) at peak vs about 4,400 pps average for everything else |

README timeline (CEST): 15:52:39 attack from saruman1, 15:52:58 from saruman, 15:54:44 "attack ended by timeout". These match
the flows to within a few seconds. The third bot (147.32.84.192) never flooded.

**Caveats / labeling flaws:**
- "Background" flows are *unlabeled* university traffic, not verified benign. Only a few hosts are labeled `Normal`.
- The README's normal-host labels ("Normal-V42-...") are copied from scenario 1.
- `To-Botnet` flows are not malicious in themselves.
- 147.32.84.164 (a "normal" host) pings the same victim 147.32.96.69 at about 7 pps throughout the capture, so filter by
  source to separate it from the flood.

---

## 4. CTU-13 scenario 5 (CTU-Malware-Capture-Botnet-46): Virut, 2011-08-15

- **Citation, landing page, terms:** as scenario 11. Files are at https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/

| Local path | Direct download URL | Size (bytes) | SHA-256 | Packets | Span (UTC epoch) | Span (human) |
| --- | --- | --- | --- | --- | --- | --- |
| `ctu13-scenario5-virut/capture20110815-2.truncated.pcapng` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/capture20110815-2.truncated.pcap.bz2 | 389,531,260 | `bb1161656c4c0183ed57fd787ca216e56d67a3c5b186e8dac5a5b5774e29f251` | 4,479,658 | 1313419400.93-1313421206.82 (1,806 s) | 2011-08-15 14:43:20-15:13:26 UTC (16:43:20-17:13:26 CEST) |
| `ctu13-scenario5-virut/capture20110815-2.binetflow` (labels) | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow | 17,766,203 | `ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c` | | | |
| `ctu13-scenario5-virut/README.md` | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/README.md | 4,580 | `ce95fb1e2127a3887acb2157ba74bef6ca82341089682739dda76cd0262f9458` | | | |

Archive SHA-256: `capture20110815-2.truncated.pcap.bz2` = `37dfc0b5b70cfe5678e839baf127c350387913debba30d7c1975b464f7a0ef95`
(76,934,117 B). The capture is pcapng (renamed) and header-truncated, the same as scenario 11. Timestamps are CEST (UTC+2), verified
the same way.

**Labels:** binetflow, infected host **147.32.84.165** (single bot). There is no sharp start/end. The bot is active from
infection until the capture stops, giving about 9.5 min of pre-infection baseline followed by about 20 min of low-rate
botnet activity.

| Event | Start epoch | End epoch | UTC | CEST | Attacker -> peers | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Pre-infection baseline (no bot flows) | 1313419400.93 | 1313419970.9 | 14:43:20-14:52:50 | 16:43:20-16:52:50 | n/a | the bot VM sends only a few packets before 14:52:50 |
| All botnet activity | 1313419970.95 | 1313421205.43 | 14:52:50-15:13:25 | 16:52:50-17:13:25 | 147.32.84.165 -> many | 31,391 pkts in pcap involve the bot (about 0.7% of the capture) |
| Binary downloads | 1313420028.17 | 1313420152.75 | 14:53:48-14:55:52 | 16:53:48-16:55:52 | -> 94.63.149.152, 195.88.191.59 :80 | `...HTTP-Binary-Download-*` |
| HTTP C2 (CC5/CC12/CC1) | 1313420076.93 | 1313421152.20 | 14:54:36-15:12:32 | 16:54:36-17:12:32 | -> 94.63.150.63:80, 91.220.0.52:80, IRC 184.106.213.57:6667 | beaconing |
| C2/proxy connection attempts | 1313420042.29 | 1313421174.61 | 14:54:02-15:12:54 | 16:54:02-17:12:54 | -> 46.4.36.120:443 (275), :6667, :3128 | `TCP-Attempt`, 422 flows |
| SMTP spam + private SMTP proxy | 1313420169.95 | 1313421205.43 | 14:56:09-15:13:25 | 16:56:09-17:13:25 | -> tcp/25, tcp/587, 212.117.171.138:65500 | `SPAM`, `SMTP-Private-Proxy` |
| Busiest bot period (pcap) | 1313420640 | 1313420820 | 15:04:00-15:07:00 | 17:04:00-17:07:00 | | about 5,000 bot pkts/min (vs about 150,000 pkts/min total) |

**Caveats:** the volume is small relative to the background, so this capture serves as a "hard/negative" case for
whole-network counts. The README has no traffic analysis section. The paper describes scenario 5 as including a port scan,
but no flows are labeled as a scan in this binetflow. The same Background/Normal caveats apply as for scenario 11.

---

## 5. IoT-23 scenario CTU-IoT-Malware-Capture-34-1: Mirai, 2018-12-21/22

- **Citation:** S. Garcia, A. Parmisano, M. J. Erquiaga, "IoT-23: A labeled dataset with malicious and benign IoT network
  traffic," Stratosphere Laboratory, 2020, doi:10.5281/zenodo.4743746. The README asks to cite "Stratosphere Laboratory. A
  labeled dataset with malicious and benign IoT network traffic. January 22th. Agustin Parmisano, Sebastian Garcia, Maria
  Jose Erquiaga. https://www.stratosphereips.org/datasets-iot23".
- **Landing page:** https://www.stratosphereips.org/datasets-iot23 ; files at https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/
- **License/terms: CONFLICTING.** The top-level IoT-23 README (`IoT-23-README.md`) says "The licence of the IoT-23 is
  CC-BY", linking to CC BY 2.0. The per-scenario `README.md` boilerplate says "You need authorization from the Stratosphere
  Lab to use these files." Resolve this before publishing results; it's probably fine for private experiments.

| Local path | Direct download URL | Size (bytes) | SHA-256 | Packets | Span (UTC epoch) | Span (human) |
| --- | --- | --- | --- | --- | --- | --- |
| `iot23-34-1-mirai/2018-12-21-15-50-14-192.168.1.195.pcap` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap | 126,317,980 | `92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699` (matches upstream `.capinfos`) | 233,865 | 1545403816.87-1545490213.94 (86,397 s) | 2018-12-21 14:50:16 to 12-22 14:50:13 UTC (15:50 to 15:50 CET) |
| `iot23-34-1-mirai/conn.log.labeled` (labels) | .../CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled | 2,926,718 | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` | | | |
| `iot23-34-1-mirai/README.md` | .../CTU-IoT-Malware-Capture-34-1/README.md | 1,596 | `940e8778cba292b4c9d2f8b7e10d77976c8eccfc8b6b8bfa79faa53230203f7f` | | | |
| `iot23-34-1-mirai/2018-12-21-15-50-14-192.168.1.195.capinfos` | .../CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.capinfos | 1,174 | `4afd8f2e42f77e45cd1520a5d01a7f06361a3be0c25a5cd00d28d1e6735c36eb` | | | |
| `iot23-34-1-mirai/IoT-23-README.md` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/README.md | 5,806 | `8c645afd906d2a22c8cc9fae1251e7a35c27b09ccb6ecadf268b768643a44ab2` | | | |

**What the capture contains:** only the infected Raspberry Pi 192.168.1.195 (gateway 192.168.1.1). There are no other LAN
hosts, so the "benign background" is just the device's own NTP and DNS traffic (1,923 Benign flows). Classic pcap, not
truncated.

**Where the labels came from:** the Zeek `conn.log.labeled` columns `label` and `detailed-label`, with epoch `ts`. The bursts
below are label flows clustered with a 60 s gap, and their packet counts were measured in the pcap. Times are epoch, so there
is no timezone ambiguity. Filenames and the README are CET (UTC+1).

| Label | Start epoch | End epoch | UTC | CET | Attacker -> victim | pcap pkts |
| --- | --- | --- | --- | --- | --- | --- |
| C&C (beaconing, whole capture) | 1545404132.35 | 1545490213.94 | 12-21 14:55:32 to 12-22 14:50:13 | 15:55:32 to 15:50:13 | 192.168.1.195 -> 185.244.25.235:6667 | 6,706 flows (5,065 S0 failed SYNs), about 8 flows/min with hourly bursts |
| "PartOfAHorizontalPortScan" | 1545426295.41 | 1545426316.00 | 12-21 21:04:55-21:05:16 | 22:04:55-22:05:16 | 192.168.1.195 -> 66.67.61.168:63798/tcp | 38,060 pkts in 21 s (behaves as a flood, see flaws) |
| DDoS burst 1 (TCP/80 flood) | 1545466958.99 | 1545466989.01 | 12-22 08:22:38-08:23:09 | 09:22:38-09:23:09 | 192.168.1.195 -> 123.59.209.185:80 | 28,431 pkts, 30.3 MB |
| DDoS burst 2 (UDP flood) | 1545474444.86 | 1545474468.99 | 12-22 10:27:24-10:27:48 | 11:27:24-11:27:48 | 192.168.1.195 -> 74.91.117.248 | 55,332 pkts, 76.8 MB |
| DDoS burst 3 (TCP flood) | 1545475806.97 | 1545475829.00 | 12-22 10:50:06-10:50:28 | 11:50:06-11:50:28 | 192.168.1.195 -> 71.61.66.148 | 40,568 pkts |

**Known labeling flaws:**
- The "horizontal port scan" label covers 121 flows to *one* destination IP and port, carrying 38k packets in 21 s. That is
  vertical/flood behaviour, not a horizontal scan. Treat it as an attack burst whose label type is unreliable.
- DDoS burst 1 is mostly Zeek `OTH` flows with `orig_pkts=0`, so packet counts from the conn.log are wrong (0). Use the pcap.
- The only labeled source is the single device.

---

## Tried and skipped

- **CIC-IDS2017** (UNB CIC, https://www.unb.ca/cic/datasets/ids-2017.html): skipped because it requires a form. The old
  file server http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/ now 301-redirects to `cicresearch.ca`, which redirects
  to the UNB datasets index. Per the UNB FAQ, downloads are behind "a download form". If you fill in the form yourself, note
  that the published attack schedule is in New Brunswick local time (ADT, UTC-3 in July 2017). The daily pcaps are 8-13 GB,
  so cut slices with `editcap -A/-B`.
- **UNSW-NB15** (https://research.unsw.edu.au/projects/unsw-nb15-dataset): skipped. Files, including the pcaps and
  `NUSW-NB15_GT.csv`, are only in UNSW SharePoint/OneDrive folders, which need interactive browser download, not a direct
  URL.
- **CTU-13 botnet-only pcaps** (`botnet-capture-*.pcap`): not used. They contain only the infected VM's traffic. The
  `*.truncated.pcap.bz2` full-router captures used above include the background.
- **Larger CTU-13 scenarios** (1/2/9 Neris with IRC C2, spam and port scan; 3 Rbot): their truncated captures are 1.1-2.5 GB
  bz2. They were left out to stay small. Scenario 9 (`CTU-Malware-Capture-Botnet-50/capture20110817.truncated.pcap.bz2`,
  1.7 GB) is the best next pick for a port scan in real background.
- **Exfiltration / worm:** no small, openly downloadable capture with timed ground truth was found among the benchmark
  sources. malware-traffic-analysis.net examples (for example, infostealer FTP/SMTP exfil) would be the fallback, but their
  only "labels" are blog prose, so none was fetched.
