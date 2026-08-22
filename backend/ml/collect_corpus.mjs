#!/usr/bin/env node
// Turn captures into a training corpus for train_model.py.
//
//   node collect_corpus.mjs --out captures.jsonl capture1.pcap capture2.pcap ...
//
// Runs the engine over each capture and emits one JSON object per line using
// the same feature layout the control plane POSTs to /predict.
//
// buildFeatureVector is imported from the API rather than reimplemented here.
// That is the whole point: a corpus built from a second, drifting copy of the
// feature logic would train the model on a layout the serving path never
// produces, and nothing would report the mismatch.

import { execFile } from "child_process"
import { promisify } from "util"
import fs from "fs"
import path from "path"
import { fileURLToPath } from "url"

import { FEATURE_NAMES, buildFeatureVector, validateEngineReport } from "../api/lib.js"

const execFileAsync = promisify(execFile)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

const DEFAULT_ENGINE = path.join(__dirname, "../build/bin/dpi_engine")

function parseArgs(argv) {
  const opts = { out: "captures.jsonl", engine: DEFAULT_ENGINE, files: [] }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") opts.out = argv[++i]
    else if (argv[i] === "--engine") opts.engine = argv[++i]
    else opts.files.push(argv[i])
  }
  return opts
}

async function featuresFor(enginePath, pcap) {
  const outPath = path.join(
    fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "corpus-")),
    "filtered.pcap"
  )
  try {
    const { stdout } = await execFileAsync(
      enginePath,
      [pcap, outPath, "--json"],
      { maxBuffer: 64 * 1024 * 1024 }
    )
    const raw = JSON.parse(stdout)
    const shapeError = validateEngineReport(raw)
    if (shapeError) throw new Error(`engine report: ${shapeError}`)
    return buildFeatureVector(raw)
  } finally {
    fs.rmSync(path.dirname(outPath), { recursive: true, force: true })
  }
}

const opts = parseArgs(process.argv.slice(2))

if (!opts.files.length) {
  console.error("usage: collect_corpus.mjs [--out FILE] [--engine PATH] capture.pcap ...")
  process.exit(2)
}
if (!fs.existsSync(opts.engine)) {
  console.error(`engine not found at ${opts.engine} -- build it with: cd backend && ./build.sh`)
  process.exit(1)
}

const lines = []
let failed = 0

for (const pcap of opts.files) {
  try {
    const vector = await featuresFor(opts.engine, pcap)
    // Emit in FEATURE_NAMES order. The loader keys by name so order is not
    // load-bearing, but a corpus that reads in the documented order is much
    // easier to eyeball against a /predict payload.
    const ordered = Object.fromEntries(FEATURE_NAMES.map((k) => [k, vector[k]]))
    lines.push(JSON.stringify(ordered))
    console.error(
      `  ${path.basename(pcap)}: ${vector.total_packets} packets, ` +
        `${vector.active_connections} conns, ` +
        `${vector.packets_per_connection.toFixed(1)} pkts/conn, ` +
        `unknown ${(vector.unknown_ratio * 100).toFixed(0)}%`
    )
  } catch (err) {
    failed++
    console.error(`  ${path.basename(pcap)}: FAILED -- ${err.message}`)
  }
}

if (!lines.length) {
  console.error("no captures produced a usable feature vector")
  process.exit(1)
}

fs.writeFileSync(opts.out, lines.join("\n") + "\n")
console.error(`wrote ${opts.out}: ${lines.length} vectors${failed ? `, ${failed} failed` : ""}`)
