#!/usr/bin/env python3
"""
main_working.py
----------------
Equivalent of src/main_working.cpp -- the SIMPLE (single-threaded) version.

Reads a pcap, walks through each packet, extracts SNI, checks rules,
forwards or drops, then prints a report. Start here to understand the
project before looking at dpi_mt.py (multi-threaded version).
"""

import sys
import argparse
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw

sys.path.append("..")
from src.pcap_reader import PcapReader, PcapWriter
from src.packet_parser import PacketParser
from src.sni_extractor import SNIExtractor, HTTPHostExtractor
from src.types import sni_to_app_type
from src.rule_manager import RuleManager
from src.connection_tracker import ConnectionTracker


def run(input_pcap: str, output_pcap: str, rules: RuleManager):
    print("=" * 66)
    print("        DPI ENGINE v1.0 (Python - Simple/Single-threaded)")
    print("=" * 66)
    for a in rules.blocked_apps:
        print(f"[Rules] Blocked app: {a}")
    for ip in rules.blocked_ips:
        print(f"[Rules] Blocked IP: {ip}")
    for d in rules.blocked_domains:
        print(f"[Rules] Blocked domain: {d}")

    # ---- Step 1: Read PCAP file ----
    print(f"\n[Reader] Reading {input_pcap} ...")
    reader = PcapReader().open(input_pcap)
    print(f"[Reader] Done reading {len(reader)} packets")

    tracker = ConnectionTracker()
    forwarded_packets = []
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    forwarded = 0
    dropped = 0

    # ---- Step 2-7: process each packet ----
    for pkt in reader:
        total_bytes += len(pkt)

        # Step 3: Parse protocol headers
        parsed = PacketParser.parse(pkt)

        if not parsed.has_ip or parsed.tuple is None:
            forwarded_packets.append(pkt)
            forwarded += 1
            continue

        if parsed.has_tcp:
            tcp_count += 1
        elif parsed.has_udp:
            udp_count += 1

        # Step 4: Create five-tuple and look up flow
        flow = tracker.get_or_create(parsed.tuple)

        # Step 5: Extract SNI (deep packet inspection)
        if parsed.payload:
            if parsed.dst_port == 443 or parsed.src_port == 443:
                sni = SNIExtractor.extract(parsed.payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)
            elif parsed.dst_port == 80 or parsed.src_port == 80:
                host = HTTPHostExtractor.extract(parsed.payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

        # Step 6: Check blocking rules
        if not flow.blocked and rules.is_blocked(parsed.src_ip, flow.app_type, flow.sni):
            flow.blocked = True

        # Step 7: Forward or drop
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            forwarded_packets.append(pkt)

    # ---- Step 8: Generate report ----
    print(f"\n[Writer] Writing {forwarded} packets to {output_pcap} ...")
    PcapWriter.write(output_pcap, forwarded_packets)

    app_stats = defaultdict(int)
    for flow in tracker.all_flows():
        app_stats[flow.app_type] += 1

    print("\n" + "=" * 66)
    print("                     PROCESSING REPORT")
    print("=" * 66)
    print(f"Total Packets:      {len(reader)}")
    print(f"Total Bytes:        {total_bytes}")
    print(f"TCP Packets:        {tcp_count}")
    print(f"UDP Packets:        {udp_count}")
    print("-" * 66)
    print(f"Forwarded:          {forwarded}")
    print(f"Dropped:            {dropped}")
    print("-" * 66)
    print("APPLICATION BREAKDOWN (by flow)")
    total_flows = max(len(tracker), 1)
    for app, count in sorted(app_stats.items(), key=lambda x: -x[1]):
        pct = 100 * count / total_flows
        bar = "#" * int(pct // 5)
        tag = " (BLOCKED)" if app in rules.blocked_apps else ""
        print(f"  {app:<12} {count:>4}  {pct:5.1f}% {bar}{tag}")

    print("\n[Detected Domains/SNIs]")
    seen = set()
    for flow in tracker.all_flows():
        if flow.sni and flow.sni not in seen:
            seen.add(flow.sni)
            print(f"  - {flow.sni} -> {flow.app_type}")
    print("=" * 66)


def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Simple version (Python)")
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    args = parser.parse_args()

    rules = RuleManager()
    for a in args.block_app:
        rules.block_app(a)
    for ip in args.block_ip:
        rules.block_ip(ip)
    for d in args.block_domain:
        rules.block_domain(d)

    run(args.input_pcap, args.output_pcap, rules)


if __name__ == "__main__":
    main()
