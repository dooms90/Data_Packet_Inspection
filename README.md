# Data Packet Inspection Engine (Python)

A **Deep Packet Inspection (DPI) engine** that reads network traffic captures (`.pcap` files), identifies which app or website each connection belongs to — even over encrypted HTTPS — and applies configurable blocking rules by IP, app, or domain.

Available in two modes: a simple single-threaded engine and a multi-threaded pipeline modeled after real-world traffic-shaping architectures (Reader → Load Balancer → Fast Path → Writer).

## Features

- **Inspects HTTPS traffic without decrypting it** — extracts the destination domain from the TLS *Client Hello* SNI field, which is sent in plaintext before encryption begins
- **Plain HTTP support** — also parses the `Host:` header for unencrypted traffic
- **App-aware classification** — automatically tags flows as YouTube, Facebook, Netflix, GitHub, TikTok, and more, based on the detected domain
- **Flexible blocking rules** — block traffic by source IP, by app name, or by domain substring
- **Two execution modes**:
  - `main_working.py` — simple, sequential, easy to read and step through
  - `dpi_mt.py` — multi-threaded, splits work across configurable Load Balancer and Fast Path threads using consistent hashing so a connection's packets always land on the same worker
- **Flow tracking** — groups packets into connections (5-tuple: src IP, dst IP, src port, dst port, protocol) so classification persists across a session
- **Detailed reporting** — per-run summary of total packets/bytes, forwarded vs. dropped counts, per-app traffic breakdown, and (in multi-threaded mode) per-thread load statistics
- **Built-in test data generator** — no need for a real capture to try it out; `generate_test_pcap.py` builds a sample `.pcap` with realistic TLS/HTTP traffic

## How it works

.pcap file -> Parse headers -> Match to flow -> Extract SNI/Host -> Check rules -> Forward or Drop -> output.pcap

Because modern web traffic is encrypted, this engine doesn't try to read message contents. Instead, it relies on the one piece of plaintext every HTTPS connection reveals up front: the **Server Name Indication (SNI)**, sent during the TLS handshake so the server knows which website's certificate to present. That's enough to identify *what* a connection is for, without ever decrypting it.


## Project Structure

```text
packet_analyzer_python/
├── src/
│   ├── types.py # FiveTuple, Flow, app-name signatures
│   ├── pcap_reader.py # Read/write .pcap files
│   ├── packet_parser.py # Extract IP/TCP/UDP fields
│   ├── sni_extractor.py # Extract SNI (TLS) / Host (HTTP)
│   ├── rule_manager.py # Blocking rules (IP / app / domain)
│   ├── connection_tracker.py # Flow table (5-tuple -> Flow)
│   ├── main_working.py # Simple (single-threaded) engine
│   └── dpi_mt.py # Multi-threaded engine
├── generate_test_pcap.py # Creates a sample test_dpi.pcap
├── requirements.txt
└── README.md


## Installation

```bash
pip install -r requirements.txt
```

## Usage

**1. Generate a sample capture** (skip this if you have your own `.pcap` file):

```bash
python generate_test_pcap.py
```

**2. Run the simple engine:**

```bash
python -m src.main_working test_dpi.pcap output.pcap --block-app YouTube --block-domain tiktok
```

**3. Run the multi-threaded engine:**

```bash
python -m src.dpi_mt test_dpi.pcap output.pcap --block-app YouTube --lbs 2 --fps 4
```

`--lbs` = number of Load Balancer threads, `--fps` = number of Fast Path threads.

### All options

| Flag              | Meaning                                  |
| ----------------- | ----------------------------------------- |
| `--block-app`     | Block a whole app by name (e.g. YouTube)  |
| `--block-ip`      | Block a specific source IP                |
| `--block-domain`  | Block any connection whose SNI contains this text |
| `--lbs`           | *(multi-threaded only)* number of Load Balancer threads |
| `--fps`           | *(multi-threaded only)* number of Fast Path threads |

Flags can be repeated to add multiple rules, e.g. `--block-app YouTube --block-app TikTok`.

============================================================
                    PROCESSING REPORT

Total Packets : 8
Total Bytes   : 612
TCP Packets   : 7
UDP Packets   : 1
Forwarded     : 6
Dropped       : 2


============================================================
              APPLICATION BREAKDOWN (by flow)

Facebook      : 1    16.7%
Google        : 1    16.7%
GitHub        : 1    16.7%
Netflix       : 1    16.7%
YouTube       : 1    16.7%
TikTok        : 1    16.7%   (BLOCKED)