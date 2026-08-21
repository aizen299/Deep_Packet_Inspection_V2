// Pure helpers shared by server.js and its tests.
//
// server.js opens listening sockets at import time, so anything that needs to
// be exercised in isolation lives here instead. These functions have no module
// state and touch the filesystem only where noted.

import fs from "fs"

/**
 * Feature layout POSTed to the ML service.
 *
 * The scorer indexes this vector positionally (see backend/ml/features.py), so
 * the order is a contract across two languages. Changing it here without
 * changing FEATURE_NAMES there silently rescores every capture.
 */
export const FEATURE_NAMES = [
  "total_packets",
  "total_bytes",
  "tcp_ratio",
  "udp_ratio",
  "unknown_ratio",
  "dns_ratio",
  "unique_app_count",
  "active_connections",
  "drop_rate",
  "packets_per_connection",
]

/**
 * Accepts a full URL, or the bare "host:port" that platform service discovery
 * (Render's `fromService: hostport`) produces, which axios rejects as relative.
 *
 * Remote hosts resolve to https: the request carries the shared API key and may
 * cross the public internet. Loopback and dot-less names -- Docker compose
 * service names, platform-internal hostnames -- stay on http.
 */
export function normaliseServiceUrl(raw, fallback = "http://localhost:5050") {
  const value = raw || fallback
  if (/^https?:\/\//.test(value)) return value

  const host = value.split(":")[0]
  const isLocal =
    host === "localhost" || host === "127.0.0.1" || !host.includes(".")
  return `${isLocal ? "http" : "https"}://${value}`
}

// libpcap and pcapng magic numbers, both endiannesses.
export const CAPTURE_MAGICS = new Set([
  0xa1b2c3d4, 0xd4c3b2a1, // pcap, us resolution
  0xa1b23c4d, 0x4d3cb2a1, // pcap, ns resolution
  0x0a0d0d0a,             // pcapng section header block
])

/** Magic-number check against an already-read header. */
export function isCaptureMagic(buf) {
  if (!buf || buf.length < 4) return false
  return CAPTURE_MAGICS.has(buf.readUInt32BE(0))
}

/** Reads the first four bytes of a file and applies isCaptureMagic. */
export function hasCaptureMagic(filePath) {
  let fd
  try {
    fd = fs.openSync(filePath, "r")
    const buf = Buffer.alloc(4)
    const read = fs.readSync(fd, buf, 0, 4, 0)
    if (read < 4) return false
    return isCaptureMagic(buf)
  } catch {
    return false
  } finally {
    if (fd !== undefined) fs.closeSync(fd)
  }
}

// The engine's JSON is an untyped cross-process contract; verify the fields we
// index before using them so a shape change reports as such instead of
// surfacing as a misleading "JSON parse failed".
export function validateEngineReport(raw) {
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

export function detectSuspicious(data) {
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

export function buildFeatureVector(raw) {
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

  // NOTE: the ML service indexes these positionally -- see FEATURE_NAMES.
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
