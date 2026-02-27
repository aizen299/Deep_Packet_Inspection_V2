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

## Web Dashboard 

The JSON output can be consumed by a web frontend (React, Vue, or plain HTML + Chart.js) to visualize:

- Application distribution charts
- Packet forwarding vs dropping
- Thread load balancing
- Detected domains table

Typical workflow:

PCAP → DPI Engine (--json) → stats.json → Web UI

This allows the DPI engine to function as a backend analytics component instead of a terminal-only tool.

---

# Deep Packet Inspection (DPI) System

A production-oriented Deep Packet Inspection (DPI) system built with:

- High-performance C++ multi-threaded engine  
- Node.js REST control plane  
- Next.js analytics dashboard  

This system processes PCAP files, classifies traffic at the application layer, applies filtering rules, and exposes structured analytics via an API for visualization.

---

# 🚀 System Overview

The DPI system operates as a three-layer architecture:

```
PCAP File
   │
   ▼
C++ DPI Engine (Multi-threaded)
   │
   ▼
Node.js Control Plane (REST API)
   │
   ▼
Next.js Dashboard (Analytics UI)
```

---

# 🧠 C++ DPI Engine

## Core Capabilities

- Ethernet, IPv4, IPv6 parsing
- TCP / UDP inspection
- TLS SNI extraction (HTTPS domain detection)
- HTTP Host header inspection
- DNS query extraction
- Five-tuple flow tracking
- Per-thread connection tables
- Rule-based filtering:
  - `--block-ip`
  - `--block-domain`
  - `--block-app`
- Consistent hashing for flow affinity
- Multi-threaded load balancer + fast path model
- Strict bounds checking against malformed packets
- Structured JSON output mode (`--json`)

---

## Processing Architecture

Reader → Load Balancers → Fast Path Workers → Output Writer

Design principles:

- Same flow handled by same worker
- Lock minimization via per-thread state
- LRU-based connection eviction
- Deterministic thread distribution

---

# 📊 JSON Output Mode

Run:

```
./dpi_engine input.pcap output.pcap --json
```

Example structured output:

```json
{
  "packet_stats": {
    "total_packets": 78,
    "tcp_packets": 74,
    "udp_packets": 4
  },
  "applications": {
    "Unknown": { "count": 21, "percentage": 47.73 },
    "DNS": { "count": 4, "percentage": 9.09 }
  },
  "filtering": {
    "forwarded": 78,
    "dropped": 0,
    "drop_rate": 0.00
  }
}
```

---

# 🌐 REST API (Node.js Control Plane)

Located in:

```
backend/api/
```

## Endpoints

### POST `/analyze`
Runs DPI engine on sample PCAP.

### POST `/upload`
Upload custom PCAP for analysis.

### GET `/stats`
Returns cached analysis result.

### GET `/health`
Returns engine status and last run metadata.

---

## API Example

```
curl -X POST http://localhost:4000/analyze
```

Response:

```json
{
  "success": true,
  "data": { ... structured stats ... }
}
```

---

# 🖥 Dashboard (Next.js)

Located in:

```
frontend/
```

Features:

- Glassmorphism UI
- Horizontal bar charts
- Top-N application ranking
- Percentage + count display
- Suspicious traffic highlighting
- PCAP upload interface
- Health status display
- Real-time fetch from backend

Run locally:

```
cd frontend
npm install
npm run dev
```

Open:

```
http://localhost:3000
```

---

# 🛠 Local Setup

## 1️⃣ Build Engine

```
cd backend
chmod +x build.sh
./build.sh
```

Test:

```
./build/bin/dpi_engine data/sample.pcap output/test.pcap --json
```

---

## 2️⃣ Start Control Plane

```
cd backend/api
npm install
node server.js
```

Test:

```
curl http://localhost:4000/health
```

---

## 3️⃣ Start Dashboard

```
cd frontend
npm install
npm run dev
```

---

# 📁 Project Structure

```
Packet_analyzer/
│
├── backend/
│   ├── build/
│   ├── data/
│   ├── output/
│   ├── include/
│   ├── src/
│   ├── api/
│   └── build.sh
│
├── frontend/
│
└── README.md
```

---

# 🔬 Advanced Capabilities

- Multi-threaded flow distribution
- Burst detection heuristic
- Suspicious traffic identification
- Application frequency analysis
- Structured API integration

Planned extensions:

- Real-time packet capture mode
- ML-based anomaly detection
- WebSocket live updates
- Redis caching
- Prometheus metrics
- Full Docker deployment

---

# 📌 Why This Project Matters

This project demonstrates:

- Systems programming in C++
- Concurrent architecture design
- Network protocol parsing
- Backend API orchestration
- Modern frontend analytics integration
- Full-stack systems thinking

---

# 🐳 Docker Support (Next Phase)

Upcoming:

- Engine container
- API container
- Dashboard container
- Unified `docker-compose` deployment

---

# License

Educational and research use.