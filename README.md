# DPI Engine Using Python
## Folder structure 

```
packet_analyzer_python/
├── src/
│   ├── types.py                # FiveTuple, Flow, app-name signatures
│   ├── pcap_reader.py          # Read/write .pcap files
│   ├── packet_parser.py        # Extract IP/TCP/UDP fields
│   ├── sni_extractor.py        # Extract SNI (TLS) / Host (HTTP)
│   ├── rule_manager.py         # Blocking rules (IP / app / domain)
│   ├── connection_tracker.py   # Flow table (5-tuple -> Flow)
│   ├── main_working.py         # ★ SIMPLE (single-threaded) version ★
│   └── dpi_mt.py                # ★ MULTI-THREADED version ★
├── generate_test_pcap.py       # Creates a sample test_dpi.pcap
└── README.md                   # This file
```

## Setup

```
pip install scapy
```

## 1. Generate a test capture

```
python generate_test_pcap.py
```

Creates `test_dpi.pcap` with sample TLS/HTTP/DNS-like traffic.

## 2. Run the Simple version

```
python -m src.main_working test_dpi.pcap output.pcap --block-app YouTube --block-domain tiktok
```

## 3. Run the Multi-threaded version

```
python -m src.dpi_mt test_dpi.pcap output.pcap --block-app YouTube --lbs 2 --fps 4
```

`--lbs` = number of Load Balancer threads, `--fps` = number of Fast Path threads
## All available options

| Flag              | Meaning                          |
| ----------------- | --------------------------------- |
| `--block-app`     | Block a whole app (e.g. YouTube)  |
| `--block-ip`      | Block a source IP                 |
| `--block-domain`  | Block any SNI containing this text|
| `--lbs`           | (mt version) number of LB threads |
| `--fps`           | (mt version) number of FP threads |

Example with everything:

```
python -m src.dpi_mt test_dpi.pcap output.pcap ^
    --block-app YouTube --block-app TikTok ^
    --block-ip 192.168.1.50 --block-domain facebook ^
    --lbs 2 --fps 4
```

(On Windows Command Prompt, use `^` for line continuation instead of `\`.)
