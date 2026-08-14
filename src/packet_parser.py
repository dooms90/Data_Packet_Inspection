"""
packet_parser.py
-----------------
Equivalent of include/packet_parser.h + src/packet_parser.cpp.

Purpose: Extract protocol fields (IP addresses, ports, protocol) from a raw
packet, and build the FiveTuple used to look up its Flow. Scapy has already
parsed the Ethernet/IP/TCP/UDP headers for us; this module just organizes
that into the same shape the C++ ParsedPacket struct used.
"""

from dataclasses import dataclass
from typing import Optional

from scapy.all import IP, TCP, UDP, Raw

from .types import FiveTuple


@dataclass
class ParsedPacket:
    has_ip: bool
    has_tcp: bool
    has_udp: bool
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None      # "TCP" or "UDP"
    payload: bytes = b""
    tuple: Optional[FiveTuple] = None


class PacketParser:
    @staticmethod
    def parse(pkt) -> ParsedPacket:
        """Parse one scapy packet into a ParsedPacket (mirrors PacketParser::parse)."""
        if IP not in pkt:
            return ParsedPacket(has_ip=False, has_tcp=False, has_udp=False)

        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        if TCP in pkt:
            layer = pkt[TCP]
            protocol = "TCP"
            has_tcp, has_udp = True, False
        elif UDP in pkt:
            layer = pkt[UDP]
            protocol = "UDP"
            has_tcp, has_udp = False, True
        else:
            return ParsedPacket(has_ip=True, has_tcp=False, has_udp=False,
                                 src_ip=src_ip, dst_ip=dst_ip)

        payload = bytes(pkt[Raw].load) if Raw in pkt else b""

        five_tuple = FiveTuple(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=layer.sport, dst_port=layer.dport,
            protocol=protocol,
        )

        return ParsedPacket(
            has_ip=True, has_tcp=has_tcp, has_udp=has_udp,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=layer.sport, dst_port=layer.dport,
            protocol=protocol, payload=payload, tuple=five_tuple,
        )
