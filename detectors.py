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

# Protocol detectors

import transitkeys
import ipaddress
import time
from dvar import datasetSummary
from pairstats import pair_stats_tcp
from pairstats import pair_stats_udp
from pairstats import pair_stats_arp
import logging

# separate out tcp,udp and arp traffic

# Fields that detectors compare or use as addresses. tshark EK emits a list when a field repeats
# inside one layer; the first value is the one for this packet's own header.
ADDRESSING_FIELDS = (
    "ip.proto",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
)

# Layer-4 markers. A fragment frame carrying none of these has no transport header of its own.
L4_FIELDS = ("tcp.srcport", "udp.srcport", "icmp.type", "icmpv6.type")

TRUE_VALUES = (True, "1", "true", "True")


def normalize_addressing(packet_dict):
    for key in ADDRESSING_FIELDS:
        value = packet_dict.get(key)
        if isinstance(value, list):
            packet_dict[key] = value[0] if value else None
    return packet_dict


class PacketAnalyse:
    def __init__(self, name, inQ, outQ):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.inQ = inQ
        self.outQ = outQ

    def run(self):
        dvar = datasetSummary()
        start_timer = time.perf_counter()
        self.logger.info("Starting")
        try:
            while True:
                if not self.inQ.empty():
                    thePacket = self.inQ.get()
                    if not thePacket:
                        self.logger.debug(
                            "We're done - empty dictionary received on queue"
                        )
                        self.outQ.put([])
                        break
                    normalize_addressing(thePacket)
                    if not self.find_ip(thePacket, dvar):
                        self.find_non_ip(thePacket, dvar)
        except Exception:
            # Forward the end-of-stream sentinel so downstream stages exit instead of waiting forever
            self.logger.exception("Packet analysis failed")
            self.outQ.put([])
            raise
        end_timer = time.perf_counter()
        recognized_count = (
            dvar.tcp_count
            + dvar.udp_count
            + dvar.arp_count
            + dvar.igmp_count
            + dvar.icmp_count
            + dvar.ip_fragment_count
        )
        unrecognized_count = dvar.not_analyzed_ip_count + dvar.not_analyzed_not_ip_count
        coarse_pps = recognized_count / (end_timer - start_timer)
        dvar_dict = vars(dvar).copy()
        # TODO determine if we really want to remove the pairs from the output or output something
        # dvar_dict.pop("tcp")
        # dvar_dict.pop("udp")
        # dvar_dict.pop("arp")
        long_string = (
            f"recognized={recognized_count} unrecognized={unrecognized_count} pps={coarse_pps} "
            f"{dvar_dict}"
        )
        self.logger.info(long_string)
        self.logger.info("Exiting thread")

    # orders the src and dst before hashing
    # pass in strings that are the ip addresses from the packet
    def gen_src_dst_key(self, src, dst):
        if src < dst:
            return str(ipaddress.ip_address(src)) + "-" + str(ipaddress.ip_address(dst))
        else:
            return str(ipaddress.ip_address(dst)) + "-" + str(ipaddress.ip_address(src))

    # orders the src and dst before hashing
    # pass in strings that are the ip addresses from the packet
    def gen_ipv6_src_dst_key(self, src, dst):
        if src < dst:
            return (
                str(ipaddress.IPv6Address(src)) + "-" + str(ipaddress.IPv6Address(dst))
            )
        else:
            return (
                str(ipaddress.IPv6Address(dst)) + "-" + str(ipaddress.IPv6Address(src))
            )

    # tcp, ipand arp are separate in case they want to add custom properties like lists of port combos
    # we mutate a parameter. oh the horror!
    def gen_tcp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_tcp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    def gen_udp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_udp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    def gen_arp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_arp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    # The return code just says we categorized as non-ip not that we detected specific non-IP
    def find_non_ip(self, packet_dict, dvar):
        if not self.find_arp(packet_dict, dvar):
            # TODO probably should filter out any with ip.proto or an ipv6.<something> and return False
            dvar.not_analyzed_not_ip_count += 1
            # Could look for things like ipx for non IP
            self.logger.debug("Packet was not IP not ARP")
            # should this be debug() info() or warn() You could have a lot of these
            self.logger.debug(
                "Packet not analyzed: No detector for non IP %s", packet_dict
            )
        return True

    # Cover for all the IP based detectors
    # The return code says we categorized as IP - not that detected specific IP
    # ICMP and fragments are checked before TCP/UDP: an ICMP error quotes a TCP/UDP header, and a
    # non-final fragment has an IP protocol number but no transport header of its own.
    def find_ip(self, packet_dict, dvar):
        if self.find_icmp(packet_dict, dvar):
            return True
        if self.find_ip_fragment(packet_dict, dvar):
            return True
        if not self.find_tcp(packet_dict, dvar):
            if not self.find_udp(packet_dict, dvar):
                if not self.find_igmp(packet_dict, dvar):
                    # Can't filter on ip.proto at the top because of IPv6 picked up in the detectors
                    if "ip.proto" in packet_dict or "ipv6.nxt" in packet_dict:
                        dvar.not_analyzed_ip_count += 1
                        # ip.proto exists for IPv4, ipv6.nxt (next header) for IPv6
                        self.logger.debug("Packet was IP but not TCP, UDP, ICMP, IGMP")
                        packet_ip_proto = packet_dict.get(
                            "ip.proto", packet_dict.get("ipv6.nxt")
                        )
                        dvar.not_analyzed_ip.add(packet_ip_proto)
                        # should this be debug() info() or warn() You could have a lot of these
                        self.logger.debug(
                            "Packet not analyzed: no detector for IP protocol: %s",
                            packet_ip_proto,
                        )
                    else:
                        return False
        return True

    # ICMP (IPv4 protocol 1) and ICMPv6. Errors such as destination unreachable carry a quoted
    # IP + TCP/UDP header; that quoted header is not a TCP/UDP packet and must not be counted as one.
    def find_icmp(self, packet_dict, dvar):
        if (
            "icmp.type" in packet_dict
            and packet_dict.get("ip.proto") == "1"
            and "ip.src" in packet_dict
            and "ip.dst" in packet_dict
        ):
            packet_key = self.gen_src_dst_key(
                packet_dict["ip.src"], packet_dict["ip.dst"]
            )
        elif (
            "icmpv6.type" in packet_dict
            and "ipv6.src" in packet_dict
            and "ipv6.dst" in packet_dict
        ):
            packet_key = self.gen_ipv6_src_dst_key(
                packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
            )
        else:
            return False
        dvar.icmp_count += 1
        self.send(packet_key, packet_dict, "icmp")
        return True

    # A fragment frame with no transport header of its own. tshark reassembles fragments by default
    # and attaches the reassembled TCP/UDP/ICMP layer to the final fragment, which is counted under its
    # protocol as usual. The earlier fragments would otherwise be dropped, hiding most of a fragmented
    # flood. For IPv6, next header 44 is the fragment header; tshark nests that header, and
    # capture.unwrap names its offset field "ipv6_fraghdr.offset".
    def find_ip_fragment(self, packet_dict, dvar):
        if any(field in packet_dict for field in L4_FIELDS):
            return False
        ipv4_fragment = packet_dict.get("ip.flags.mf") in TRUE_VALUES or str(
            packet_dict.get("ip.frag_offset", "0")
        ) not in ("0", "")
        ipv6_fragment = (
            packet_dict.get("ipv6.nxt") == "44" or "ipv6_fraghdr.offset" in packet_dict
        )
        if ipv4_fragment and "ip.src" in packet_dict and "ip.dst" in packet_dict:
            packet_key = self.gen_src_dst_key(
                packet_dict["ip.src"], packet_dict["ip.dst"]
            )
        elif ipv6_fragment and "ipv6.src" in packet_dict and "ipv6.dst" in packet_dict:
            packet_key = self.gen_ipv6_src_dst_key(
                packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
            )
        else:
            return False
        dvar.ip_fragment_count += 1
        self.send(packet_key, packet_dict, "ipfrag")
        return True

    # Picks interested attributes from packets and saves them into a list
    def find_tcp(self, packet_dict, dvar):
        success = False
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "6"):
            return success

        try:
            if (
                "tcp.srcport" in packet_dict
                and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                in dvar.tcp.keys()
            ):
                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                status = dvar.tcp[packet_key]
                self.logger.debug("%s, %s", packet_key, status)
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            elif "ip.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    {}, packet_dict, "ip.src", "ip.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            else:
                success = False
        except KeyError:
            if (
                "tcp.srcport" in packet_dict
                and self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                in dvar.tcp.keys()
            ):

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.tcp[packet_key]
                self.logger.debug("{packet_key} {status}")
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            elif "ipv6.src" in packet_dict and "tcp.flags.syn" in packet_dict:

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.tcp[packet_key] = self.gen_tcp_stats(
                    {}, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.tcp_count += 1

                self.send(packet_key, packet_dict, "tcp")
                success = True
            else:
                success = False

        except AttributeError:
            self.logger.info("%s", packet_dict)
        return success

    def find_udp(self, packet_dict, dvar):
        success = False
        # filters out IPV4 non UDP - could still have IPv6 UDP
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "17"):
            return success

        try:

            if (
                "udp.srcport" in packet_dict
                and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                in dvar.udp.keys()
            ):

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                status = dvar.udp[packet_key]
                dvar.udp[packet_key] = self.gen_udp_stats(
                    status, packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                dvar.udp[packet_key] = self.gen_udp_stats(
                    {}, packet_dict, "ip.src", "ip.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            else:
                success = False
        except KeyError:

            if (
                "udp.srcport" in packet_dict
                and self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                in dvar.udp.keys()
            ):

                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                status = dvar.udp[packet_key]

                dvar.udp[packet_key] = self.gen_udp_stats(
                    status, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            elif "udp.srcport" in packet_dict:
                packet_key = self.gen_ipv6_src_dst_key(
                    packet_dict["ipv6.src"], packet_dict["ipv6.dst"]
                )
                dvar.udp[packet_key] = self.gen_udp_stats(
                    {}, packet_dict, "ipv6.src", "ipv6.dst"
                )
                dvar.udp_count += 1

                self.send(packet_key, packet_dict, "udp")
                success = True
            else:
                success = False
        return success

    def find_arp(self, packet_dict, dvar):

        success = False
        try:

            if (
                "arp.src.proto_ipv4" in packet_dict
                and self.gen_src_dst_key(
                    packet_dict["arp.dst.proto_ipv4"], packet_dict["arp.src.proto_ipv4"]
                )
                in dvar.arp.keys()
            ):
                packet_key = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"],
                    packet_dict["arp.dst.proto_ipv4"],
                )
                status = dvar.arp[packet_key]
                dvar.arp[packet_key] = self.gen_arp_stats(
                    status, packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(packet_key, packet_dict, "arp")
                success = True
            elif "arp.src.proto_ipv4" in packet_dict:

                packet_key = self.gen_src_dst_key(
                    packet_dict["arp.src.proto_ipv4"], packet_dict["arp.dst.proto_ipv4"]
                )

                dvar.arp[packet_key] = self.gen_arp_stats(
                    {}, packet_dict, "arp.src.proto_ipv4", "arp.dst.proto_ipv4"
                )
                dvar.arp_count += 1

                self.send(packet_key, packet_dict, "arp")
                success = True
            else:
                success = False

        except AttributeError:
            # traceback.self.logger.info_exc()
            self.logger.info("%s", packet_dict)
            success = False

        return success

    # only doing IGMP row counts until someone writes code here
    # IGMP is IPv4 only (protocol 2). Its IPv6 counterpart, MLD, is ICMPv6 and is counted by find_icmp.
    # This used to accept any IPv6 packet that reached it, which counted ICMPv6 as IGMP.
    def find_igmp(self, packet_dict, dvar):
        success = False
        if packet_dict.get("ip.proto") != "2":
            return success

        try:
            if "ip.src" in packet_dict and "ip.dst" in packet_dict:
                packet_key = self.gen_src_dst_key(
                    packet_dict["ip.src"], packet_dict["ip.dst"]
                )
                # I don't know anything about IGMP so just set the pack count to 1 all the time
                dvar.igmp_count += 1
                self.send(packet_key, packet_dict, "igmp")
                success = True
        except AttributeError:
            self.logger.info("attribute error %s", packet_dict)
            success = False
        return success

    def send(self, ID, PacketData, PacketProtocol):
        self.outQ.put(
            {
                transitkeys.key_id: ID,
                transitkeys.key_packet: PacketData,
                transitkeys.key_protocol: PacketProtocol,
            }
        )
