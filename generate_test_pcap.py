#!/usr/bin/env python3
"""
Generates a small sample .pcap file (test_dpi.pcap) with a mix of traffic
so you can test dpi_engine.py without needing a real network capture.

Usage:
    python generate_test_pcap.py
"""

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def tls_client_hello(sni: str) -> bytes:
    """Build a minimal (fake but well-formed) TLS Client Hello with the given SNI."""
    server_name = sni.encode()
    sni_entry = b"\x00" + len(server_name).to_bytes(2, "big") + server_name          # type(host) + len + name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = (0x0000).to_bytes(2, "big") + len(sni_list).to_bytes(2, "big") + sni_list

    extensions = sni_ext
    ext_len = len(extensions).to_bytes(2, "big")

    session_id = b""
    ciphers = b"\x00\x02\x13\x01"          # 1 cipher suite
    comp = b"\x01\x00"                     # 1 compression method (null)

    hello_body = (
        b"\x03\x03"                        # client version TLS1.2
        + b"\x00" * 32                     # random
        + len(session_id).to_bytes(1, "big") + session_id
        + len(ciphers).to_bytes(2, "big") + ciphers
        + comp
        + ext_len + extensions
    )

    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body   # Client Hello
    record = b"\x16" + b"\x03\x01" + len(handshake).to_bytes(2, "big") + handshake  # TLS record
    return record


def main():
    packets = []

    domains = [
        "www.youtube.com",
        "www.facebook.com",
        "www.google.com",
        "github.com",
        "www.tiktok.com",
        "www.netflix.com",
    ]

    src_ip = "192.168.1.100"
    for i, domain in enumerate(domains):
        dst_ip = f"172.217.14.{200 + i}"
        sport = 50000 + i
        payload = tls_client_hello(domain)
        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=443, flags="PA")
            / Raw(load=payload)
        )
        packets.append(pkt)

    # A plain HTTP request too
    pkt = (
        Ether()
        / IP(src=src_ip, dst="93.184.216.34")
        / TCP(sport=51000, dport=80, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    packets.append(pkt)

    # A DNS-ish UDP packet (just to have UDP traffic in the mix)
    pkt = (
        Ether()
        / IP(src=src_ip, dst="8.8.8.8")
        / UDP(sport=52000, dport=53)
        / Raw(load=b"\x00" * 20)
    )
    packets.append(pkt)

    wrpcap("test_dpi.pcap", packets)
    print(f"Created test_dpi.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
