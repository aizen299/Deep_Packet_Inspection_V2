# Deep Packet Inspection Platform

A production-style DPI system built with:

- ⚡ C++ multi-threaded engine  
- 🌐 Node.js control plane  
- 🤖 FastAPI ML microservice  
- 📊 Next.js real-time dashboard  
- 🐳 Dockerized deployment  

---

## Architecture

PCAP → C++ DPI Engine → Node.js API → ML Service → Dashboard

All services run via Docker Compose.

---

## What It Does

- Parses Ethernet / IP / TCP / UDP
- Extracts HTTP, TLS (SNI), DNS metadata
- Classifies applications
- Tracks flows with consistent hashing
- Applies filtering rules
- Outputs structured JSON
- Performs ML-based anomaly scoring
- Streams results to dashboard via WebSocket

---

## Run Locally

### Build Engine

```
cd backend
./build.sh
```

### Start API

```
cd backend/api
node server.js
```

### Start ML Service

```
cd backend/ml
uvicorn server:app --port 5050
```

### Start Dashboard

```
cd dashboard
npm run dev
```

---

## Docker (Recommended)

From project root:

```
docker-compose up --build
```

Dashboard → http://localhost:3000  
API → http://localhost:4000  

---

## Why This Project Matters

- Systems-level C++ engineering
- Concurrent architecture design
- Real-time analytics pipeline
- ML inference microservice integration
- Full containerized deployment

---

## License

GNU General Public License v3.0 (GPL-3.0)
See LICENSE file for details.