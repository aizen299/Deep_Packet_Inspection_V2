# Deep Packet Inspection (DPI) Engine

A high-performance offline Deep Packet Inspection (DPI) engine written in C++ for parsing, classifying, and filtering network traffic from PCAP files.

---

## Features

- Ethernet, IPv4, IPv6, TCP, and UDP parsing
- TLS SNI extraction (HTTPS domain identification)
- HTTP Host header inspection
- DNS query extraction
- Five-tuple based flow tracking
- Application-level classification
- Rule-based blocking (IP, domain, application)
- Multi-threaded packet processing pipeline
- Filtered PCAP output generation
- Optional JSON statistics output for frontend integration

---

## Architecture

### Processing Pipeline

PCAP → Reader → Parser → Flow Tracking → Classification → Rule Engine → Output

### Multi-threaded Mode

Reader → Load Balancers → Fast Path Workers → Output Writer

Key design principles:

- Consistent hashing ensures packets of the same flow are handled by the same worker
- Per-thread flow tables minimize locking contention
- LRU-based connection tracking prevents unbounded memory growth
- Strict bounds checking protects against malformed packets

---

## Build

### Single-threaded Version

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Multi-threaded Version

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

---

## Usage

### Basic

```bash
./dpi_engine input.pcap output.pcap
```

### With Blocking

```bash
./dpi_engine input.pcap output.pcap \
    --block-app YouTube \
    --block-domain facebook \
    --block-ip 192.168.1.50
```

### Configure Threads (Multi-threaded)

```bash
./dpi_engine input.pcap output.pcap --lbs 2 --fps 2
```

---

## Testing

Generate synthetic test traffic:

```bash
python3 generate_test_pcap.py
```

---

## JSON Output Mode

The engine can export processing statistics in JSON format for integration with web dashboards or external tools.

Example:

```bash
./dpi_engine input.pcap output.pcap --json stats.json
```

This generates a structured JSON file containing:

- Packet statistics
- Application breakdown
- Thread distribution
- Detected domains

---

## Web Dashboard (Optional Frontend)

The JSON output can be consumed by a web frontend (React, Vue, or plain HTML + Chart.js) to visualize:

- Application distribution charts
- Packet forwarding vs dropping
- Thread load balancing
- Detected domains table

Typical workflow:

PCAP → DPI Engine (--json) → stats.json → Web UI

This allows the DPI engine to function as a backend analytics component instead of a terminal-only tool.

---
