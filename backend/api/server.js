import express from "express"
import cors from "cors"
import { exec } from "child_process"
import multer from "multer"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"
import axios from "axios"

import http from "http"
import { Server } from "socket.io"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// ---- Configuration ----------------------------------------------------------

const PORT = Number(process.env.PORT || 4000)

// Bind to loopback by default so a dev run is not exposed to the local network.
// docker-compose overrides this to 0.0.0.0 so the published port works.
const BIND_HOST = process.env.BIND_HOST || "127.0.0.1"

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "http://localhost:3000")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean)

// Shared-secret access control. This is a browser dashboard with no user login,
// so a key shipped to the client is not a secret from whoever runs the browser.
// Its job is to stop unauthenticated access from other hosts and origins -- not
// to authenticate individual users. Do not expose this service to the internet.
const API_KEY = process.env.API_KEY || ""

// Key presented to the ML service. Defaults to API_KEY so a single shared
// secret configures the whole stack, but can be set separately.
const ML_API_KEY = process.env.ML_API_KEY || process.env.API_KEY || ""

const ENGINE_TIMEOUT_MS = Number(process.env.ENGINE_TIMEOUT_MS || 120000)
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 100 * 1024 * 1024)

if (!API_KEY) {
  console.warn(
    "[WARN] API_KEY is not set - all endpoints are unauthenticated. " +
      "Set API_KEY to require an x-api-key header."
  )
}

const app = express()
app.disable("x-powered-by")

const corsOptions = {
  origin(origin, callback) {
    // Same-origin/non-browser callers (curl, server-side) send no Origin header.
    if (!origin) return callback(null, true)
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true)
    return callback(new Error(`Origin not allowed: ${origin}`))
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "x-api-key"],
}

app.use(cors(corsOptions))
app.use(express.json({ limit: "1mb" }))

const server = http.createServer(app)

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    credentials: true,
  },
})

// ---- Access control ---------------------------------------------------------

function requireApiKey(req, res, next) {
  if (!API_KEY) return next()

  const provided = req.get("x-api-key")
  if (provided && provided === API_KEY) return next()

  return res.status(401).json({ success: false, message: "Unauthorized" })
}

io.use((socket, next) => {
  if (!API_KEY) return next()

  const provided = socket.handshake.auth?.apiKey || socket.handshake.headers["x-api-key"]
  if (provided === API_KEY) return next()

  next(new Error("Unauthorized"))
})

// Fixed-window limiter for the endpoints that spawn the engine. Keeps a single
// client from monopolising the one-run-at-a-time engine. Intentionally
// dependency-free and per-process.
const RATE_LIMIT_WINDOW_MS = 60000
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 20)
const rateBuckets = new Map()

function rateLimit(req, res, next) {
  const key = req.ip || "unknown"
  const now = Date.now()
  const bucket = rateBuckets.get(key)

  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    return next()
  }

  if (bucket.count >= RATE_LIMIT_MAX) {
    return res.status(429).json({ success: false, message: "Too many requests" })
  }

  bucket.count++
  next()
}

// Bound the bucket map so a spray of source IPs cannot grow it without limit.
setInterval(() => {
  const now = Date.now()
  for (const [key, bucket] of rateBuckets) {
    if (now > bucket.resetAt) rateBuckets.delete(key)
  }
}, RATE_LIMIT_WINDOW_MS).unref()

io.on("connection", (socket) => {
  console.log("Dashboard connected:", socket.id)
})

// ---- Upload handling --------------------------------------------------------

const UPLOAD_DIR = path.join(__dirname, "uploads")
fs.mkdirSync(UPLOAD_DIR, { recursive: true })

const upload = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
    files: 1,
    parts: 10,
  },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase()
    if (ext !== ".pcap" && ext !== ".pcapng") {
      return cb(new Error("Only .pcap and .pcapng files are accepted"))
    }
    cb(null, true)
  },
})

// libpcap and pcapng magic numbers, both endiannesses.
const CAPTURE_MAGICS = new Set([
  0xa1b2c3d4, 0xd4c3b2a1, // pcap, us resolution
  0xa1b23c4d, 0x4d3cb2a1, // pcap, ns resolution
  0x0a0d0d0a,             // pcapng section header block
])

function hasCaptureMagic(filePath) {
  let fd
  try {
    fd = fs.openSync(filePath, "r")
    const buf = Buffer.alloc(4)
    const read = fs.readSync(fd, buf, 0, 4, 0)
    if (read < 4) return false
    return CAPTURE_MAGICS.has(buf.readUInt32BE(0))
  } catch {
    return false
  } finally {
    if (fd !== undefined) fs.closeSync(fd)
  }
}

function safeUnlink(filePath) {
  if (!filePath) return
  fs.unlink(filePath, (err) => {
    if (err && err.code !== "ENOENT") {
      console.error("Failed to remove upload:", filePath, err.message)
    }
  })
}

// ---- Engine orchestration ---------------------------------------------------

let cachedStats = null
let engineBusy = false
let lastRunMeta = {
  timestamp: null,
  duration_ms: 0,
  input_file: null,
}

const ENGINE_PATH = path.join(__dirname, "../build/bin/dpi_engine")
const OUTPUT_DIR = path.join(__dirname, "../output")
fs.mkdirSync(OUTPUT_DIR, { recursive: true })

function detectSuspicious(data) {
  if (!data?.applications) return null

  let maxApp = null
  let maxCount = 0

  for (const [name, obj] of Object.entries(data.applications)) {
    if (obj.count > maxCount) {
      maxApp = name
      maxCount = obj.count
    }
  }

  return {
    top_app: maxApp,
    peak_packets: maxCount,
    flagged: maxCount > 40,
  }
}

function enrichStats(rawData, inputFile) {
  const suspicious = detectSuspicious(rawData)

  return {
    ...rawData,
    suspicious_activity: suspicious,
    meta: {
      timestamp: new Date().toISOString(),
      duration_ms: lastRunMeta.duration_ms,
      input_file: inputFile,
    },
  }
}

// The engine's JSON is an untyped cross-process contract; verify the fields we
// index before using them so a shape change reports as such instead of
// surfacing as a misleading "JSON parse failed".
function validateEngineReport(raw) {
  if (!raw || typeof raw !== "object") return "report is not an object"
  if (!raw.packet_stats || typeof raw.packet_stats !== "object") {
    return "missing packet_stats"
  }
  for (const field of ["total_packets", "total_bytes", "tcp_packets", "udp_packets"]) {
    if (typeof raw.packet_stats[field] !== "number") {
      return `packet_stats.${field} is not a number`
    }
  }
  return null
}

function buildFeatureVector(raw) {
  const totalPackets = raw.packet_stats.total_packets
  const tcpPackets = raw.packet_stats.tcp_packets
  const udpPackets = raw.packet_stats.udp_packets
  const apps = raw.applications || {}

  const tcpRatio = totalPackets > 0 ? tcpPackets / totalPackets : 0
  const udpRatio = totalPackets > 0 ? udpPackets / totalPackets : 0
  const unknownRatio = apps["Unknown"] ? apps["Unknown"].percentage / 100 : 0
  const dnsRatio = apps["DNS"] ? apps["DNS"].percentage / 100 : 0
  const uniqueAppCount = Object.keys(apps).length
  const activeConnections = raw.fast_path?.active_connections || 0
  const dropRate = raw.filtering?.drop_rate || 0
  const packetsPerConnection =
    activeConnections > 0 ? totalPackets / activeConnections : 0

  // NOTE: the ML service indexes these positionally -- do not reorder.
  return {
    total_packets: totalPackets,
    total_bytes: raw.packet_stats.total_bytes,
    tcp_ratio: tcpRatio,
    udp_ratio: udpRatio,
    unknown_ratio: unknownRatio,
    dns_ratio: dnsRatio,
    unique_app_count: uniqueAppCount,
    active_connections: activeConnections,
    drop_rate: dropRate,
    packets_per_connection: packetsPerConnection,
  }
}

function runEngine(inputPath, outputPath, inputLabel, res, onComplete = () => {}) {
  if (engineBusy) {
    onComplete()
    return res.status(409).json({
      success: false,
      message: "Engine is busy. Try again shortly.",
    })
  }

  engineBusy = true
  const start = Date.now()
  // Reset cached state to avoid stale dashboard data
  cachedStats = null

  const command = `"${ENGINE_PATH}" "${inputPath}" "${outputPath}" --json`

  exec(
    command,
    { timeout: ENGINE_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024, killSignal: "SIGKILL" },
    async (error, stdout, stderr) => {
      engineBusy = false
      const duration = Date.now() - start

      try {
        if (error) {
          // exec sets `killed` when the timeout fired.
          if (error.killed) {
            console.error(`Engine timed out after ${ENGINE_TIMEOUT_MS}ms`)
            return res.status(504).json({
              success: false,
              message: `Engine timed out after ${ENGINE_TIMEOUT_MS}ms`,
            })
          }
          console.error("Engine error:", error)
          console.error("stderr:", stderr)
          return res.status(500).json({
            success: false,
            message: "Engine execution failed",
          })
        }

        let raw
        try {
          raw = JSON.parse(stdout)
        } catch (parseErr) {
          console.error("JSON parse error:", parseErr)
          console.error("stdout:", stdout)
          return res.status(502).json({
            success: false,
            message: "Engine produced invalid JSON",
          })
        }

        const shapeError = validateEngineReport(raw)
        if (shapeError) {
          console.error("Engine report shape error:", shapeError)
          return res.status(502).json({
            success: false,
            message: `Unexpected engine report shape: ${shapeError}`,
          })
        }

        lastRunMeta = {
          timestamp: new Date().toISOString(),
          duration_ms: duration,
          input_file: inputLabel,
        }

        cachedStats = enrichStats(raw, inputLabel)

        let mlResult = null
        try {
          const ML_SERVICE_URL =
            process.env.ML_SERVICE_URL || "http://localhost:5050"

          const mlResponse = await axios.post(
            `${ML_SERVICE_URL}/predict`,
            buildFeatureVector(raw),
            {
              timeout: 10000,
              headers: ML_API_KEY ? { "x-api-key": ML_API_KEY } : {},
            }
          )
          mlResult = mlResponse.data
        } catch (mlErr) {
          console.error("ML service error:", mlErr.message)
        }

        const finalPayload = {
          ...cachedStats,
          ml: mlResult,
        }

        io.emit("stats_update", finalPayload)
        io.emit("analysis_complete", finalPayload)

        res.json({ success: true, data: finalPayload })
      } catch (e) {
        console.error("Unexpected failure handling engine result:", e)
        if (!res.headersSent) {
          res.status(500).json({ success: false, message: "Internal error" })
        }
      } finally {
        onComplete()
      }
    }
  )
}

// ---- Routes -----------------------------------------------------------------

app.post("/analyze", requireApiKey, rateLimit, (req, res) => {
  const input = path.join(__dirname, "../data/sample.pcap")
  const output = path.join(OUTPUT_DIR, "filtered.pcap")

  runEngine(input, output, "sample.pcap", res)
})

app.post("/upload", requireApiKey, rateLimit, upload.single("pcap"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "No file uploaded" })
  }

  const input = path.resolve(req.file.path)

  if (!hasCaptureMagic(input)) {
    safeUnlink(input)
    return res.status(400).json({
      success: false,
      message: "File is not a valid pcap/pcapng capture",
    })
  }

  const output = path.join(OUTPUT_DIR, "upload_filtered.pcap")

  // multer writes to a temp name; remove it once the engine is done with it.
  runEngine(input, output, req.file.originalname, res, () => safeUnlink(input))
})

app.get("/stats", requireApiKey, (req, res) => {
  res.json({ success: true, data: cachedStats })
})

app.get("/health", (req, res) => {
  res.json({
    status: engineBusy ? "running" : "idle",
    last_run: lastRunMeta,
  })
})

// Centralised error handler -- turns multer limit/filter rejections and CORS
// denials into JSON rather than an HTML stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err)

  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({
      success: false,
      message: `File exceeds the ${MAX_UPLOAD_BYTES} byte limit`,
    })
  }
  if (err?.message?.startsWith("Origin not allowed")) {
    return res.status(403).json({ success: false, message: "Origin not allowed" })
  }
  if (err) {
    return res.status(400).json({ success: false, message: err.message })
  }
  next()
})

server.listen(PORT, BIND_HOST, () => {
  console.log(`DPI Control Plane running on ${BIND_HOST}:${PORT} (WebSocket enabled)`)
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`)
  console.log(`Auth: ${API_KEY ? "x-api-key required" : "DISABLED"}`)
})
