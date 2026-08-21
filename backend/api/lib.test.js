// Run with: npm test   (node:test, no test dependency needed)

import { test, describe } from "node:test"
import assert from "node:assert/strict"
import fs from "fs"
import os from "os"
import path from "path"
import { fileURLToPath } from "url"

import {
  FEATURE_NAMES,
  buildFeatureVector,
  detectSuspicious,
  hasCaptureMagic,
  isCaptureMagic,
  normaliseServiceUrl,
  validateEngineReport,
} from "./lib.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/** A well-formed engine report, matching generateJsonReport()'s shape. */
function engineReport(overrides = {}) {
  return {
    packet_stats: {
      total_packets: 78,
      total_bytes: 5802,
      tcp_packets: 74,
      udp_packets: 4,
    },
    filtering: { forwarded: 78, dropped: 0, drop_rate: 0 },
    fast_path: { active_connections: 44 },
    applications: {
      Unknown: { count: 21, percentage: 47.73 },
      DNS: { count: 4, percentage: 9.09 },
    },
    ...overrides,
  }
}

describe("normaliseServiceUrl", () => {
  test("passes through explicit schemes", () => {
    assert.equal(normaliseServiceUrl("https://x.onrender.com"), "https://x.onrender.com")
    assert.equal(normaliseServiceUrl("http://localhost:5050"), "http://localhost:5050")
  })

  test("compose service names stay on http", () => {
    assert.equal(normaliseServiceUrl("ml:5050"), "http://ml:5050")
    assert.equal(normaliseServiceUrl("dpi-ml:5050"), "http://dpi-ml:5050")
  })

  test("loopback stays on http", () => {
    assert.equal(normaliseServiceUrl("localhost:5050"), "http://localhost:5050")
    assert.equal(normaliseServiceUrl("127.0.0.1:5050"), "http://127.0.0.1:5050")
  })

  test("public hostnames are forced to https", () => {
    // The request carries the shared API key; sending it in cleartext over the
    // public internet is the failure this guards.
    assert.equal(
      normaliseServiceUrl("dpi-ml.onrender.com"),
      "https://dpi-ml.onrender.com"
    )
  })

  test("empty and undefined fall back", () => {
    assert.equal(normaliseServiceUrl(""), "http://localhost:5050")
    assert.equal(normaliseServiceUrl(undefined), "http://localhost:5050")
  })
})

describe("buildFeatureVector", () => {
  test("emits exactly the keys the scorer indexes, in order", () => {
    // The ML service reads this vector positionally. This assertion is the
    // only thing standing between a reordered object literal here and a
    // silently rescored model on the other side of the process boundary.
    const keys = Object.keys(buildFeatureVector(engineReport()))
    assert.deepEqual(keys, FEATURE_NAMES)
  })

  test("derives ratios from packet counts", () => {
    const v = buildFeatureVector(engineReport())
    assert.equal(v.total_packets, 78)
    assert.ok(Math.abs(v.tcp_ratio - 74 / 78) < 1e-9)
    assert.ok(Math.abs(v.udp_ratio - 4 / 78) < 1e-9)
    assert.ok(Math.abs(v.unknown_ratio - 0.4773) < 1e-9)
    assert.ok(Math.abs(v.packets_per_connection - 78 / 44) < 1e-9)
  })

  test("an empty capture yields zeros rather than NaN", () => {
    // NaN would propagate into the model and poison the score silently.
    const v = buildFeatureVector(
      engineReport({
        packet_stats: { total_packets: 0, total_bytes: 0, tcp_packets: 0, udp_packets: 0 },
        fast_path: { active_connections: 0 },
        applications: {},
      })
    )
    for (const [key, value] of Object.entries(v)) {
      assert.ok(Number.isFinite(value), `${key} is not finite: ${value}`)
    }
  })

  test("tolerates missing optional sections", () => {
    const v = buildFeatureVector({
      packet_stats: { total_packets: 10, total_bytes: 100, tcp_packets: 10, udp_packets: 0 },
    })
    assert.equal(v.active_connections, 0)
    assert.equal(v.drop_rate, 0)
    assert.equal(v.unique_app_count, 0)
  })

  test("every value is numeric", () => {
    for (const value of Object.values(buildFeatureVector(engineReport()))) {
      assert.equal(typeof value, "number")
    }
  })
})

describe("validateEngineReport", () => {
  test("accepts a well-formed report", () => {
    assert.equal(validateEngineReport(engineReport()), null)
  })

  test("rejects non-objects", () => {
    assert.match(validateEngineReport(null), /not an object/)
    assert.match(validateEngineReport("{}"), /not an object/)
  })

  test("rejects a missing packet_stats", () => {
    assert.match(validateEngineReport({}), /missing packet_stats/)
  })

  test("names the offending field", () => {
    const bad = engineReport()
    bad.packet_stats.tcp_packets = "74"
    assert.match(validateEngineReport(bad), /tcp_packets is not a number/)
  })
})

describe("capture magic", () => {
  const magics = {
    "pcap LE": [0xd4, 0xc3, 0xb2, 0xa1],
    "pcap BE": [0xa1, 0xb2, 0xc3, 0xd4],
    "pcap ns": [0xa1, 0xb2, 0x3c, 0x4d],
    pcapng: [0x0a, 0x0d, 0x0d, 0x0a],
  }

  for (const [name, bytes] of Object.entries(magics)) {
    test(`accepts ${name}`, () => {
      assert.equal(isCaptureMagic(Buffer.from(bytes)), true)
    })
  }

  test("rejects arbitrary content", () => {
    assert.equal(isCaptureMagic(Buffer.from("not a capture")), false)
  })

  test("rejects a short read", () => {
    assert.equal(isCaptureMagic(Buffer.from([0xd4, 0xc3])), false)
  })

  test("rejects a missing file without throwing", () => {
    assert.equal(hasCaptureMagic(path.join(__dirname, "does-not-exist.pcap")), false)
  })

  test("accepts a real capture on disk", () => {
    const sample = path.join(__dirname, "../data/sample.pcap")
    if (!fs.existsSync(sample)) return // fixture not present in this checkout
    assert.equal(hasCaptureMagic(sample), true)
  })

  test("rejects a file that is merely named .pcap", () => {
    // The extension filter alone is attacker-controlled; the magic check is
    // what actually keeps non-captures away from the engine.
    const tmp = path.join(os.tmpdir(), `fake-${process.pid}.pcap`)
    fs.writeFileSync(tmp, "#!/bin/sh\necho not a capture\n")
    try {
      assert.equal(hasCaptureMagic(tmp), false)
    } finally {
      fs.unlinkSync(tmp)
    }
  })
})

describe("detectSuspicious", () => {
  test("returns null without applications", () => {
    assert.equal(detectSuspicious({}), null)
    assert.equal(detectSuspicious(null), null)
  })

  test("reports the busiest application", () => {
    const s = detectSuspicious(engineReport())
    assert.equal(s.top_app, "Unknown")
    assert.equal(s.peak_packets, 21)
  })

  test("flags only above the threshold", () => {
    assert.equal(detectSuspicious(engineReport()).flagged, false)
    const busy = engineReport({ applications: { HTTPS: { count: 41, percentage: 90 } } })
    assert.equal(detectSuspicious(busy).flagged, true)
  })
})
