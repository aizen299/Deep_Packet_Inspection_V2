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
| `ML_TIMEOUT_MS`       | api          | ML request timeout (default 10000). Raise for cold starts.|
| `MAX_UPLOAD_BYTES`    | api          | Upload size cap (default 100 MB).                     |
| `NEXT_PUBLIC_API_URL` | dashboard    | Inlined at **build** time; changing it needs a rebuild.|
| `BASIC_AUTH_USER`     | dashboard    | Basic Auth wall. Blank = disabled.                    |
| `BASIC_AUTH_PASSWORD` | dashboard    | Basic Auth wall. Blank = disabled.                    |
| `ALLOW_UNAUTHENTICATED` | all        | Explicit opt-in to running with auth disabled.        |

**Missing credentials stop the service rather than disabling auth.** `api` and
`ml` exit at startup when `API_KEY` is unset; the dashboard serves 503 when a
production build has no `BASIC_AUTH_*`. Set `ALLOW_UNAUTHENTICATED=true` to run
open on purpose — `docker-compose.yml` does exactly that, since it binds to
localhost. The point is that an unauthenticated deployment is something you
state, not something you get by forgetting a variable.

Note that the dashboard is a browser app with no user login, so its key is not
secret from whoever runs the browser. It gates access from other hosts and
origins.

For anything reachable from the internet, set `BASIC_AUTH_USER` and
`BASIC_AUTH_PASSWORD`. The middleware in `dashboard/src/middleware.ts` gates
every path, `/_next/static` included — the client bundle carries the API key, so
the assets have to sit behind the same wall or the key is public. This is a
shared password, not per-user login; treat it as a lock on the front door rather
than real user authentication.

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

### Tests

Both suites use stdlib runners, so there is no test dependency to install:

```
cd backend/api && npm test
cd backend/ml  && python -m unittest discover -p 'test_*.py'
```

CI (`.github/workflows/ci.yml`) additionally builds the C++ engine, runs it
against a generated capture to check the JSON contract the API depends on, and
verifies both services refuse to start without `API_KEY`.

### Fuzzing the protocol extractors

The TLS/HTTP/DNS parsers walk attacker-controlled length fields, and a capture
file is untrusted input. Build with sanitizers and feed it malformed packets:

```
pip install -r requirements-dev.txt
cd backend && ./build.sh asan
python3 generate_fuzz_pcap.py
./backend/build-asan/bin/dpi_engine fuzz_corpus.pcap /tmp/out.pcap --json
```

The generator corrupts one length field at a time and leaves the rest valid, so
a crash points at a specific field. Cases are seeded — `--seed` reproduces one.
CI runs five seeds and checks the sanitizer traps a known overread first, since
a clean run from an uninstrumented binary would be a false all-clear.

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

## Deploying to Render

`render.yaml` is a Blueprint covering all three services as public web services
on the free tier.

1. Push this repo to GitHub.
2. In Render: **New → Blueprint**, select the repo, apply `render.yaml`.
3. Render prompts for the `sync: false` values. Use the same `API_KEY` for all
   three services, and that same value again for `NEXT_PUBLIC_API_KEY`.
4. The first deploy assigns URLs. Fill in the three cross-references, then
   **rebuild the dashboard**:
   - backend `ML_SERVICE_URL` → `https://dpi-ml.onrender.com`
   - backend `ALLOWED_ORIGINS` → `https://dpi-dashboard.onrender.com`
   - dashboard `NEXT_PUBLIC_API_URL` → `https://dpi-backend.onrender.com`

`NEXT_PUBLIC_*` values are inlined at build time, so changing either one
requires a **rebuild** of the dashboard, not just a restart.

Two things this topology gives up versus `docker-compose.yml`:

- **The ML scorer is internet-facing.** In compose it is unreachable except from
  the backend; here its `API_KEY` check is the only thing gating it. Switching
  it to `type: pserv` restores the private topology, but private services are
  not on the free tier.
- **Free instances suspend when idle** and cold-start on the next request. The
  Blueprint sets `ML_TIMEOUT_MS=60000` for this reason — at the 10s default a
  cold scorer times out, and the failure is silent: `ml` comes back `null` and
  the dashboard renders zeros.

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