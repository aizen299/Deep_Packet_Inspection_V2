# Deep Packet Inspection (DPI) System

A production-oriented Deep Packet Inspection (DPI) system built with:

- High-performance C++ multi-threaded engine  
- Node.js REST control plane  
- Next.js analytics dashboard  

This system processes PCAP files, classifies traffic at the application layer, applies filtering rules, and exposes structured analytics via an API for visualization.

---

# 🚀 System Architecture

```
PCAP File
   │
   ▼
C++ DPI Engine (Multi-threaded)
   │
   ▼
Node.js REST API (Control Plane)
   │
   ▼
Next.js Dashboard (Analytics UI)
```

---

# 🧠 C++ DPI Engine

## Capabilities

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
- Multi-threaded Load Balancer + Fast Path architecture  
- Strict bounds checking against malformed packets  
- Structured JSON output mode (`--json`)

---

## Processing Model

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
./build/bin/dpi_engine input.pcap output.pcap --json
```

Example output:

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

# 🌐 REST API (Node.js)

Located in:

```
backend/api/
```

## Endpoints

- `POST /analyze` — Run DPI engine on default sample
- `POST /upload` — Upload and analyze custom PCAP
- `GET /stats` — Retrieve last analysis result
- `GET /health` — Engine health + metadata

Example:

```
curl -X POST http://localhost:4000/analyze
```

---

# 🖥 Dashboard (Next.js)

Located in:

```
frontend/
```

Features:

- Glassmorphism analytics UI  
- Horizontal application distribution charts  
- Top‑N ranking with percentages  
- Suspicious traffic highlighting  
- PCAP upload interface  
- Health status indicator  
- Live backend integration  

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

## 2️⃣ Start API

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
├── LICENSE
│
└── README.md
```

---

# 🔬 Advanced Capabilities

- Multi-threaded flow distribution  
- Burst detection heuristics  
- Suspicious traffic identification  
- Application frequency analytics  
- Structured API integration  

Planned extensions:

- Real-time packet capture mode  
- ML-based anomaly detection  
- WebSocket live updates  
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
- Full-stack systems engineering  

---

# 🐳 Docker (Planned)

Future additions:

- Engine container  
- API container  
- Dashboard container  
- Unified `docker-compose` deployment  

---

# License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

See the LICENSE file for the full license text.