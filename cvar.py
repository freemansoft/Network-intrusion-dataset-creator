# MIT License

# Copyright (c) 2018 nrajasin

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# cvars should only be used from counts.py
# this was probably count vars in the original program
# every property in here should/will end up in the csv output.

from hoststats import WindowHosts


class windowcounts:

    # msec since the epoch
    window_start_time = 0
    # msec since the epoch
    window_end_time = 0

    # mostly used for human debugging
    window_index = 1

    # frame.len
    tcp_frame_length = 0
    # ip.len
    tcp_ip_length = 0
    # tcp.len
    tcp_length = 0

    # frame.len
    udp_frame_length = 0
    # ip.len
    udp_ip_length = 0
    # udp.length
    udp_length = 0

    # frame.len
    arp_frame_length = 0

    # TCP / UDP service counts for an individual window
    num_tls = 0
    num_http = 0
    num_ftp = 0
    num_ssh = 0
    num_dns = 0
    num_smtp = 0
    num_dhcp = 0
    num_nbns = 0
    num_smb = 0
    num_smb2 = 0
    num_pnrp = 0

    # derived from broadcast address and port
    num_wsdd = 0
    # derived from broadcast address and port
    num_ssdp = 0

    # protocol counts for an individual window
    num_tcp = 0
    num_udp = 0
    num_arp = 0
    num_igmp = 0

    # ICMP and ICMPv6 (frame.len, counts). Echo = echo request/reply, unreach = destination unreachable
    icmp_frame_length = 0
    num_icmp = 0
    num_icmp_echo = 0
    num_icmp_unreach = 0

    # fragment frames that carry no transport header of their own (frame.len, count).
    # The final fragment of a reassembled datagram is counted under its protocol instead.
    ip_fragment_frame_length = 0
    num_ip_fragments = 0

    # TCP flag counts: SYN without ACK, SYN+ACK, RST, FIN
    num_syn = 0
    num_synack = 0
    num_rst = 0
    num_fin = 0

    # fan-out and entropy, filled from host_window when the window is written (see hoststats.py)
    max_contacted_ports_per_src = 0
    top_src_by_contacted_ports = ""
    max_contacted_ips_per_src = 0
    top_src_by_contacted_ips = ""
    max_contacting_ips_per_dst = 0
    top_dst_by_contacting_ips = ""
    top_src_by_packets = ""
    top_dst_by_packets = ""
    entropy_src_ip = 0.0
    entropy_dst_ip = 0.0
    entropy_dst_port = 0.0

    # names of labeled attacks overlapping this window (--labels)
    label = ""

    # all the calculated src/dst combinations
    IDs = set()
    # all the ports in this window
    ports = set()

    # number of packets included in this window
    num_packets = 0

    # The class "constructor" - It's actually an initializer
    # Not sure why but non primitives must be initialized
    def __init__(self, window_start_time=None, window_index=0):
        self.num_packets = 0
        self.IDs = set()
        self.ports = set()
        # per-host state for this window; not written to windows.csv directly
        self.host_window = WindowHosts()
        self.window_start_time = window_start_time
        self.window_end_time = window_start_time
        self.window_index = window_index
