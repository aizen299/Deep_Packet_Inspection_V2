import express from "express"
import cors from "cors"
import { exec } from "child_process"
import multer from "multer"
import path from "path"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(cors())
app.use(express.json())

const upload = multer({ dest: path.join(__dirname, "uploads") })

let cachedStats = null
let engineBusy = false
let lastRunMeta = {
  timestamp: null,
  duration_ms: 0,
  input_file: null,
}

const ENGINE_PATH = path.join(__dirname, "../build/bin/dpi_engine")

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

function runEngine(inputPath, outputPath, inputLabel, res) {
  if (engineBusy) {
    return res.json({
      success: false,
      message: "Engine is busy. Try again shortly.",
    })
  }

  engineBusy = true
  const start = Date.now()

  const command = `"${ENGINE_PATH}" "${inputPath}" "${outputPath}" --json`

  exec(command, (error, stdout, stderr) => {
    engineBusy = false
    const duration = Date.now() - start

    if (error) {
      console.error("Engine error:", error)
      console.error("stderr:", stderr)
      return res.json({
        success: false,
        message: "Engine execution failed",
      })
    }

    try {
      const raw = JSON.parse(stdout)

      lastRunMeta = {
        timestamp: new Date().toISOString(),
        duration_ms: duration,
        input_file: inputLabel,
      }

      cachedStats = enrichStats(raw, inputLabel)

      res.json({ success: true, data: cachedStats })
    } catch (e) {
      console.error("JSON parse error:", e)
      console.error("stdout:", stdout)
      res.json({
        success: false,
        message: "JSON parse failed",
      })
    }
  })
}

app.post("/analyze", (req, res) => {
  const input = path.join(__dirname, "../data/sample.pcap")
  const output = path.join(__dirname, "../output/filtered.pcap")

  runEngine(input, output, "sample.pcap", res)
})

app.post("/upload", upload.single("pcap"), (req, res) => {
  if (!req.file) {
    return res.json({ success: false, message: "No file uploaded" })
  }

  const input = path.resolve(req.file.path)
  const output = path.join(__dirname, "../output/upload_filtered.pcap")

  runEngine(input, output, req.file.originalname, res)
})

app.get("/stats", (req, res) => {
  res.json({ success: true, data: cachedStats })
})

app.get("/health", (req, res) => {
  res.json({
    status: engineBusy ? "running" : "idle",
    last_run: lastRunMeta,
  })
})

app.listen(4000, () => {
  console.log("DPI Control Plane running on port 4000")
})