"""
pcap_reader.py
--------------
Equivalent of include/pcap_reader.h + src/pcap_reader.cpp.

Purpose: Read network captures (.pcap files, e.g. from Wireshark) and write
filtered output back out. Scapy handles the low-level PCAP global header /
packet header parsing for us (the C++ version parses this by hand).
"""

from scapy.all import rdpcap, wrpcap


class PcapReader:
    """Reads all packets from a .pcap file."""

    def __init__(self):
        self.packets = []

    def open(self, filename: str):
        """Open and read a PCAP file into memory."""
        self.packets = rdpcap(filename)
        return self

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)


class PcapWriter:
    """Writes a list of packets out to a .pcap file."""

    @staticmethod
    def write(filename: str, packets: list):
        wrpcap(filename, packets)
