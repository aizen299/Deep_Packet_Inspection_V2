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

## Configuration

All services share a single secret. Copy the example env file and set it:

```
cp .env.example .env
```

| Variable              | Used by      | Purpose                                              |
|-----------------------|--------------|------------------------------------------------------|
| `API_KEY`             | api, ml      | Required in the `x-api-key` header. Unset = no auth.  |
| `ML_SERVICE_URL`      | api          | Where to reach the scoring service.                   |
| `BIND_HOST`           | api          | Defaults to `127.0.0.1`; compose sets `0.0.0.0`.      |
| `ALLOWED_ORIGINS`     | api, ml      | CORS allowlist, comma separated.                      |
| `ENGINE_TIMEOUT_MS`   | api          | Engine subprocess timeout (default 120000).           |
| `MAX_UPLOAD_BYTES`    | api          | Upload size cap (default 100 MB).                     |
| `NEXT_PUBLIC_API_URL` | dashboard    | Inlined at **build** time; changing it needs a rebuild.|

Note that the dashboard is a browser app with no user login, so its key is not
secret from whoever runs the browser. It gates access from other hosts and
origins — do not expose these services to the internet.

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
npm ci
API_KEY=dev-key node server.js
```

### Start ML Service

```
cd backend/ml
pip install -r requirements.txt
API_KEY=dev-key uvicorn server:app --port 5050
```

### Start Dashboard

```
cd dashboard
npm ci
cp .env.example .env.local
npm run dev
```

### Run the engine directly

```
./backend/build/bin/dpi_engine capture.pcap filtered.pcap --json
```

---

## Docker (Recommended)

From project root:

```
cp .env.example .env
docker-compose up --build
```

Dashboard → http://localhost:3000  
API → http://localhost:4000  

The ML service is not published to the host; only the backend reaches it.

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