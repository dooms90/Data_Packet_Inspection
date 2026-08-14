#!/usr/bin/env python3
"""
dpi_mt.py
---------
Equivalent of src/dpi_mt.cpp -- the MULTI-THREADED version.

Architecture (same as the C++ version):
    Reader Thread -> Load Balancer Threads -> Fast Path Threads -> Output Writer Thread

Note on Python threading: Python's Global Interpreter Lock (GIL) means CPU-bound
code doesn't truly run in parallel across threads the way it does in C++. This
version recreates the same *architecture* (queues, thread roles, consistent
hashing) faithfully, but for real parallel speed in Python you'd normally reach
for multiprocessing instead. Since packet parsing here is fast and mostly
about matching the original design, this is a faithful architectural port.
"""

import sys
import argparse
import threading
import queue
from collections import defaultdict

sys.path.append("..")
from src.pcap_reader import PcapReader, PcapWriter
from src.packet_parser import PacketParser
from src.sni_extractor import SNIExtractor, HTTPHostExtractor
from src.types import sni_to_app_type
from src.rule_manager import RuleManager


STOP = object()  # sentinel pushed into queues to signal "no more packets"


def hash_tuple(five_tuple) -> int:
    return hash(five_tuple)


class FastPath(threading.Thread):
    """Equivalent of FastPath::run() -- does the actual DPI processing for its packets."""

    def __init__(self, name, in_queue, out_queue, rules: RuleManager, stats: dict):
        super().__init__(name=name)
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.rules = rules
        self.flows = {}          # each FP has its own flow table, like the C++ version
        self.stats = stats
        self.stats[name] = 0

    def run(self):
        while True:
            item = self.in_queue.get()
            if item is STOP:
                self.out_queue.put(STOP)
                break

            pkt, parsed = item
            self.stats[self.name] += 1

            flow = self.flows.setdefault(parsed.tuple, _new_flow())

            if parsed.payload:
                if parsed.dst_port == 443 or parsed.src_port == 443:
                    sni = SNIExtractor.extract(parsed.payload)
                    if sni:
                        flow["sni"] = sni
                        flow["app_type"] = sni_to_app_type(sni)
                elif parsed.dst_port == 80 or parsed.src_port == 80:
                    host = HTTPHostExtractor.extract(parsed.payload)
                    if host:
                        flow["sni"] = host
                        flow["app_type"] = sni_to_app_type(host)

            if not flow["blocked"] and self.rules.is_blocked(parsed.src_ip, flow["app_type"], flow["sni"]):
                flow["blocked"] = True

            if flow["blocked"]:
                self.out_queue.put(("dropped", pkt, flow))
            else:
                self.out_queue.put(("forwarded", pkt, flow))


def _new_flow():
    return {"sni": None, "app_type": "Unknown", "blocked": False}


class LoadBalancer(threading.Thread):
    """Equivalent of LoadBalancer::run() -- distributes packets to Fast Path threads."""

    def __init__(self, name, in_queue, fast_paths, num_stopped_tracker):
        super().__init__(name=name)
        self.in_queue = in_queue
        self.fast_paths = fast_paths
        self.stopped = num_stopped_tracker

    def run(self):
        while True:
            item = self.in_queue.get()
            if item is STOP:
                for fp_q in self.fast_paths:
                    fp_q.put(STOP)
                break
            pkt, parsed = item
            fp_idx = hash_tuple(parsed.tuple) % len(self.fast_paths)
            self.fast_paths[fp_idx].put((pkt, parsed))


def run(input_pcap, output_pcap, rules: RuleManager, num_lbs=2, num_fps=4):
    print("=" * 66)
    print("        DPI ENGINE v2.0 (Python - Multi-threaded)")
    print("=" * 66)
    print(f"Load Balancers: {num_lbs}    Fast Paths: {num_fps}")
    for a in rules.blocked_apps:
        print(f"[Rules] Blocked app: {a}")
    for ip in rules.blocked_ips:
        print(f"[Rules] Blocked IP: {ip}")
    for d in rules.blocked_domains:
        print(f"[Rules] Blocked domain: {d}")

    print(f"\n[Reader] Reading {input_pcap} ...")
    reader = PcapReader().open(input_pcap)
    print(f"[Reader] Done reading {len(reader)} packets")

    # ---- Set up queues ----
    lb_queues = [queue.Queue() for _ in range(num_lbs)]
    fp_per_lb = max(1, num_fps // num_lbs)
    output_queue = queue.Queue()

    fp_stats = {}
    all_fps = []
    lb_to_fps = []
    for lb_i in range(num_lbs):
        fps_for_this_lb = []
        for fp_i in range(fp_per_lb):
            name = f"FP{lb_i * fp_per_lb + fp_i}"
            fp_queue = queue.Queue()
            fp = FastPath(name, fp_queue, output_queue, rules, fp_stats)
            fps_for_this_lb.append(fp_queue)
            all_fps.append(fp)
        lb_to_fps.append(fps_for_this_lb)

    lbs = [
        LoadBalancer(f"LB{i}", lb_queues[i], lb_to_fps[i], None)
        for i in range(num_lbs)
    ]

    for fp in all_fps:
        fp.start()
    for lb in lbs:
        lb.start()

    # ---- Reader thread: hash each packet to a load balancer ----
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    lb_dispatched = defaultdict(int)

    for pkt in reader:
        total_bytes += len(pkt)
        parsed = PacketParser.parse(pkt)
        if not parsed.has_ip or parsed.tuple is None:
            continue  # non-IP packets skipped in this simplified port
        if parsed.has_tcp:
            tcp_count += 1
        elif parsed.has_udp:
            udp_count += 1

        lb_idx = hash_tuple(parsed.tuple) % num_lbs
        lb_dispatched[f"LB{lb_idx}"] += 1
        lb_queues[lb_idx].put((pkt, parsed))

    for q in lb_queues:
        q.put(STOP)

    # ---- Output writer: collect results as they arrive ----
    forwarded_packets = []
    forwarded = 0
    dropped = 0
    app_stats = defaultdict(int)
    seen_sni = {}
    stop_count = 0

    while stop_count < num_fps:
        item = output_queue.get()
        if item is STOP:
            stop_count += 1
            continue
        status, pkt, flow = item
        app_stats[flow["app_type"]] += 1
        if flow["sni"] and flow["sni"] not in seen_sni:
            seen_sni[flow["sni"]] = flow["app_type"]
        if status == "forwarded":
            forwarded += 1
            forwarded_packets.append(pkt)
        else:
            dropped += 1

    for lb in lbs:
        lb.join()
    for fp in all_fps:
        fp.join()

    print(f"\n[Writer] Writing {forwarded} packets to {output_pcap} ...")
    PcapWriter.write(output_pcap, forwarded_packets)

    # ---- Report ----
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
    print("THREAD STATISTICS")
    for name, count in lb_dispatched.items():
        print(f"  {name} dispatched: {count}")
    for name, count in fp_stats.items():
        print(f"  {name} processed:  {count}")
    print("-" * 66)
    print("APPLICATION BREAKDOWN")
    total = max(sum(app_stats.values()), 1)
    for app, count in sorted(app_stats.items(), key=lambda x: -x[1]):
        pct = 100 * count / total
        bar = "#" * int(pct // 5)
        tag = " (BLOCKED)" if app in rules.blocked_apps else ""
        print(f"  {app:<12} {count:>4}  {pct:5.1f}% {bar}{tag}")

    print("\n[Detected Domains/SNIs]")
    for sni, app in seen_sni.items():
        print(f"  - {sni} -> {app}")
    print("=" * 66)


def main():
    parser = argparse.ArgumentParser(description="DPI Engine - Multi-threaded version (Python)")
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads")
    parser.add_argument("--fps", type=int, default=4, help="Number of fast path threads")
    args = parser.parse_args()

    rules = RuleManager()
    for a in args.block_app:
        rules.block_app(a)
    for ip in args.block_ip:
        rules.block_ip(ip)
    for d in args.block_domain:
        rules.block_domain(d)

    run(args.input_pcap, args.output_pcap, rules, num_lbs=args.lbs, num_fps=args.fps)


if __name__ == "__main__":
    main()
