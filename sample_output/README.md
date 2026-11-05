This directory contains a couple sample results files.

_File output format is subject to change._

- `Razi_15012021.csv` was regenerated with 5000 msec windows after ICMP and IP fragment detection was added. It has the six columns appended after `window_end_time` and covers the full capture: 112 windows, 573,523 packets.
- `CryLock_24012021.csv` predates those changes: it has no ICMP or fragment columns, and its IGMP counts include ICMPv6 packets.
