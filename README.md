# Deep Packet Inspection Platform

A multi-threaded C++ engine parses PCAP files and classifies traffic by
application, a Node.js control plane drives it and enriches results with an ML
anomaly score, and a Next.js dashboard renders the output live over WebSocket.

Licensed under GPL-3.0.

---

## Architecture

Four pieces, wired together by `docker-compose.yml`:

| Service     | Path           | Port | Role                                             |
|-------------|----------------|------|--------------------------------------------------|
| `dashboard` | `dashboard/`   | 3000 | Next.js UI, Socket.IO client                     |
| `backend`   | `backend/api/` | 4000 | Express control plane + Socket.IO server         |
| `ml`        | `backend/ml/`  | 5050 | FastAPI IsolationForest anomaly scorer           |
| (engine)    | `backend/src/` | —    | C++ binary, invoked as a subprocess by `backend` |

The engine is **not** a service. `backend/api/server.js` executes
`backend/build/bin/dpi_engine` with `--json` and parses the JSON it prints on
stdout. That subprocess boundary is the main integration seam: a change to the
engine's output shape breaks the API and dashboard, and nothing type-checks
across it. CI asserts the contract on every push.

### Request flow

`POST /analyze` (fixed sample capture) or `POST /upload` (multipart `pcap`
field) runs the engine, derives a 10-feature vector, posts it to the scorer,
merges the verdict, caches it, and broadcasts `stats_update` and
`analysis_complete` over Socket.IO. `GET /stats` serves the last cached result
so a newly connected dashboard can backfill; `GET /health` reports engine state.

One engine run happens at a time, but callers queue rather than being rejected.
The queue is bounded twice — by depth (503 when full) and by wait time (504 on
timeout) — and a client that disconnects releases its slot and its upload
instead of holding both.

### Engine threading model

```
reader thread → LB threads → FP threads → output thread
                (num_load_balancers)  (fps_per_lb each)
```

Packets are routed by `FiveTupleHash` twice: `hash % num_lbs` selects the load
balancer, then `hash % num_fps` selects the fast-path thread. This gives **flow
affinity** — every packet of a given 5-tuple lands on the same FP thread, so
each `FastPathProcessor` owns a private `ConnectionTracker`.

That tracker is internally synchronised with a `shared_mutex`: every public
method takes it, exclusive for mutators and shared for readers, so reporting
threads can read connection state while packets are still being processed.
Verified with ThreadSanitizer across four thread configurations (see Testing).

Stages are decoupled by `ThreadSafeQueue<PacketJob>` (mutex + condition
variable).

### Classification

`FastPathProcessor::inspectPayload` tries TLS SNI, then HTTP `Host`, then DNS
query name, then falls back to port. Extractors live in `sni_extractor.cpp` and
parse attacker-controlled bytes, so bounds-checking there is security-relevant —
a capture file is the one input this system takes from an untrusted source.

Domain patterns match at label boundaries rather than as raw substrings. A plain
substring search for `x.com` matches inside `netflix.com`, which silently
reported every Netflix flow as Twitter/X until unit tests caught it.

### Cross-service JSON contract

The engine emits `packet_stats`, `filtering`, `load_balancer`, `fast_path`, and
`applications` (top 8, remainder collapsed into `Other`). The scorer consumes
exactly ten float features assembled in `server.js` and indexes them
positionally, so the order is a contract across two languages. It is defined
once in `backend/ml/features.py` and asserted by a test in `backend/api`.

---

## Quick start

```
cp .env.example .env      # set API_KEY to something non-default
docker-compose up --build
```

Dashboard → http://localhost:3000
API → http://localhost:4000

The ML service is not published to the host; only the backend reaches it.

---

## Configuration

| Variable                | Used by   | Purpose                                                    |
|-------------------------|-----------|------------------------------------------------------------|
| `API_KEY`               | api, ml   | Required in the `x-api-key` header. Unset = refuses to start |
| `ML_SERVICE_URL`        | api       | Where to reach the scorer; accepts bare `host:port`         |
| `BIND_HOST`             | api       | Defaults to `127.0.0.1`; compose sets `0.0.0.0`             |
| `ALLOWED_ORIGINS`       | api, ml   | CORS allowlist, comma separated                             |
| `ENGINE_TIMEOUT_MS`     | api       | Engine subprocess timeout (default 120000)                  |
| `ML_TIMEOUT_MS`         | api       | Scorer request timeout (default 10000)                      |
| `MAX_UPLOAD_BYTES`      | api       | Upload size cap (default 100 MB)                            |
| `MAX_QUEUE_DEPTH`       | api       | Callers waiting for the engine (default 10, then 503)       |
| `QUEUE_WAIT_MS`         | api       | Maximum wait in the queue (default 60000, then 504)         |
| `ML_HIGH_THRESHOLD`     | ml        | Risk percentile for High (default 0.99)                     |
| `ML_MEDIUM_THRESHOLD`   | ml        | Risk percentile for Medium (default 0.95)                   |
| `NEXT_PUBLIC_API_URL`   | dashboard | Inlined at **build** time; changing it needs a rebuild      |
| `BASIC_AUTH_USER`       | dashboard | HTTP Basic Auth wall                                        |
| `BASIC_AUTH_PASSWORD`   | dashboard | HTTP Basic Auth wall                                        |
| `ALLOW_UNAUTHENTICATED` | all       | Explicit opt-in to running with auth disabled               |

### Security model

**Missing credentials stop the service rather than disabling auth.** `api` and
`ml` exit at startup when `API_KEY` is unset, and the dashboard returns 503 when
a production build has no `BASIC_AUTH_*`. Set `ALLOW_UNAUTHENTICATED=true` to
run open deliberately — `docker-compose.yml` does exactly that, since it binds
to localhost. An unauthenticated deployment should be something you state, not
something you get by forgetting a variable. CI asserts both services refuse to
start without a key.

Know the limits of the auth that exists:

- The dashboard is a browser app with no user login, so `NEXT_PUBLIC_API_KEY` is
  compiled into the client bundle and is not secret from whoever runs the
  browser. It gates access from other hosts and origins, nothing more.
- The Basic Auth middleware covers every path including `/_next/static`, because
  the bundle carries that key — leaving asset paths open would publish it.
- This is a shared password, not per-user authentication. Treat it as a lock on
  the front door.

---

## Local development

Each service runs from its own directory.

```
cd backend        && ./build.sh                              # C++ engine
cd backend/api    && npm ci && API_KEY=dev-key node server.js
cd backend/ml     && pip install -r requirements.txt && API_KEY=dev-key uvicorn server:app --port 5050
cd dashboard      && npm ci && npm run dev
```

Run the engine directly to isolate an engine bug from the API:

```
./backend/build/bin/dpi_engine capture.pcap filtered.pcap --json
./backend/build/bin/dpi_engine capture.pcap filtered.pcap --block-app YouTube --verbose
```

Options: `--block-ip`, `--block-app`, `--block-domain` (supports
`*.example.com`), `--rules <file>`, `--lbs <n>`, `--fps <n>`, `--verbose`,
`--json`, `--help`. Rules files are INI-style with `[BLOCKED_IPS]`,
`[BLOCKED_APPS]`, `[BLOCKED_DOMAINS]` and `[BLOCKED_PORTS]` sections.

### Test fixtures

```
python3 generate_test_pcap.py      # test_dpi.pcap    — TLS SNI, HTTP, DNS, malformed
python3 generate_benign_pcap.py    # benign.pcap      — realistic sessions, the ML training shape
python3 generate_attack_pcap.py    # extreme_traffic.pcap — flood
python3 generate_fuzz_pcap.py      # fuzz_corpus.pcap — corrupted length fields
```

`generate_test_pcap.py` is stdlib-only; the others need `scapy` from
`requirements-dev.txt`.

---

## Testing

Three suites, all using stdlib runners — neither service carries a test
dependency.

```
cd backend     && ./build.sh && ./build/bin/dpi_tests   # extractors, classifier
cd backend/api && npm test                              # node:test
cd backend/ml  && python -m unittest discover -p 'test_*.py'
```

`backend/api/lib.js` exists so the pure helpers can be imported without
`server.js` opening sockets at import time. Its load-bearing assertion is that
`buildFeatureVector()` emits keys in the order the scorer indexes them.

CI (`.github/workflows/ci.yml`) runs all three, builds the engine and checks the
JSON contract the API depends on, verifies both services refuse to start
unauthenticated, and type-checks, lints and builds the dashboard.

### Fuzzing the protocol extractors

```
pip install -r requirements-dev.txt
cd backend && ./build.sh asan
python3 generate_fuzz_pcap.py
./backend/build-asan/bin/dpi_engine fuzz_corpus.pcap /tmp/out.pcap --json
```

The generator corrupts one TLS/DNS/HTTP length field at a time and leaves the
rest valid, so a crash is attributable to a specific field. Cases are seeded;
`--seed` reproduces one. CI runs five seeds and first verifies the sanitizer
traps a known overread, because a clean run from an uninstrumented binary would
be a false all-clear.

UBSan is enabled alongside ASan: in a parser the first symptom of a bad bounds
check is usually an overflowed offset rather than a wild read.

### Checking for data races

```
cd backend && ./build.sh tsan
./backend/build-tsan/bin/dpi_engine capture.pcap /tmp/out.pcap --lbs 4 --fps 4 --json
```

---

## The anomaly scorer

An IsolationForest fitted on **benign traffic only**, so the training corpus is
the definition of "normal".

`risk_score` is the percentile of the sample's score within the training-score
distribution — the fraction of known-benign traffic that looks less anomalous
than this capture. That makes it bounded and interpretable, and because the
percentile is uniform over benign traffic, **each threshold is its own false
positive rate**: High at 0.99 flags roughly one benign capture in a hundred.

The verdict is deliberately a hybrid. A model trained on benign data alone
measures *novelty*, not maliciousness — once the corpus honestly covered modern
QUIC-heavy browsing, a flood with thousands of one-packet connections was no
longer statistically unusual while remaining obviously scan-shaped. So the
score is combined with a structural override: under two packets per connection
across more than fifty connections is High regardless of score. Benign traffic
measured 8–156 packets per connection, so the rule has clearance, and a test
asserts it never fires on either corpus.

### Corpus

Every `.jsonl` under `backend/ml/corpus/` is loaded into training:

- `benign.jsonl` — 60 vectors from generated captures
- `real_traffic.jsonl` — 23 vectors captured from a real network with `tcpdump`

The second matters more than its size suggests. The synthetic ranges were
assumptions, and checking them against reality proved them wrong twice. The
larger correction: modern browsing is QUIC-dominated — measured medians were UDP
0.86, TCP 0.14, unknown 0.65, against an assumed TCP 0.94 and unknown 0.19 — so
every real capture scored 1.0000 (High). `synthesise_normal()` now samples both
regimes.

Regenerate after any change, and score `real_traffic.jsonl` against the result
before trusting it:

```
cd backend/ml && python train_model.py
```

`collect_corpus.mjs` imports `buildFeatureVector` from the control plane rather
than reimplementing it, so a corpus cannot drift from the vectors the scorer is
actually served at runtime.

### Adding your own captures

```
sudo tcpdump -i en0 -s 512 -w ~/cap1.pcap       # browse normally for a few minutes
tcpdump -r ~/cap1.pcap -w /tmp/chunk -C 1       # split for corpus spread
node backend/ml/collect_corpus.mjs --out backend/ml/corpus/real_traffic.jsonl /tmp/chunk*
cd backend/ml && python train_model.py
```

`-s 512` keeps message bodies off disk — only headers and the TLS ClientHello
are captured. The corpus stores ten aggregate numbers per capture: no hostnames,
addresses, or payloads. The `.pcap` files themselves do record DNS lookups and
TLS SNI, so delete them once converted.

Add only *ordinary* traffic. Anything unusual in the corpus teaches the scorer
that unusual is normal.

The corpus reflects one network at one point in time. Traffic mixes shift —
QUIC is exactly what invalidated the previous assumptions — so recapture if
verdicts start looking wrong.

## Repository layout

```
backend/
  src/, include/     C++ engine
  tests/             engine unit tests (dpi_tests target)
  api/               Express control plane; lib.js holds the testable helpers
  ml/                FastAPI scorer, training script, corpus
dashboard/src/       Next.js UI
.github/workflows/   CI
```

---

## License

GNU General Public License v3.0. See `LICENSE`.
