// Payload shapes coming off the engine -> API -> WebSocket pipeline.
//
// Everything here crosses an untyped process boundary (the C++ engine prints
// JSON on stdout, the API reshapes it, Socket.IO ships it), so nothing arriving
// at runtime is guaranteed to match. The normalise* helpers below coerce
// whatever shows up into a shape the UI can render without throwing.

export interface PacketStats {
  total_packets: number
  total_bytes: number
  tcp_packets: number
  udp_packets: number
}

export interface AppEntry {
  name: string
  count: number
  percentage: number
}

export interface MlVerdict {
  risk_score: number
  risk_level: RiskLevel
  confidence: number
  anomalies: string[]
}

export type RiskLevel = "Low" | "Medium" | "High"

export interface Snapshot {
  packets: PacketStats
  apps: AppEntry[]
  /**
   * null when the scorer could not be reached. Distinct from a genuine Low
   * verdict -- the API returns ml: null on any ML failure, and rendering that
   * as a score of zero reads as "analysed, nothing wrong" when nothing was
   * analysed at all.
   */
  ml: MlVerdict | null
  filtering: { forwarded: number; dropped: number; drop_rate: number }
  activeConnections: number
  inputFile: string | null
  durationMs: number
  timestamp: string
}

const RISK_LEVELS: RiskLevel[] = ["Low", "Medium", "High"]

function toNum(value: unknown, fallback = 0): number {
  const n = typeof value === "number" ? value : Number(value)
  return Number.isFinite(n) ? n : fallback
}

function toStr(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function normaliseApps(raw: unknown): AppEntry[] {
  if (!isRecord(raw)) return []

  return Object.entries(raw)
    .map(([name, value]) => ({
      name,
      count: isRecord(value) ? toNum(value.count) : 0,
      percentage: isRecord(value) ? toNum(value.percentage) : 0,
    }))
    .filter((a) => a.count > 0)
    .sort((a, b) => b.count - a.count)
}

function normaliseMl(raw: unknown): MlVerdict | null {
  // A missing verdict stays missing. Substituting a zeroed Low here is what
  // made an unreachable scorer look like a clean bill of health.
  if (!isRecord(raw)) return null

  const level = toStr(raw.risk_level, "Low") as RiskLevel

  return {
    risk_score: Math.min(1, Math.max(0, toNum(raw.risk_score))),
    risk_level: RISK_LEVELS.includes(level) ? level : "Low",
    confidence: toNum(raw.confidence),
    // Cap the list: these strings originate from packet-derived data and the
    // panel should not be able to grow without bound.
    anomalies: Array.isArray(raw.anomalies)
      ? raw.anomalies.filter((a): a is string => typeof a === "string").slice(0, 24)
      : [],
  }
}

/** Turns an arbitrary API/WebSocket payload into a renderable Snapshot. */
export function normaliseSnapshot(raw: unknown): Snapshot | null {
  if (!isRecord(raw)) return null

  const packetStats = isRecord(raw.packet_stats) ? raw.packet_stats : {}
  const filtering = isRecord(raw.filtering) ? raw.filtering : {}
  const fastPath = isRecord(raw.fast_path) ? raw.fast_path : {}
  const meta = isRecord(raw.meta) ? raw.meta : {}

  return {
    packets: {
      total_packets: toNum(packetStats.total_packets),
      total_bytes: toNum(packetStats.total_bytes),
      tcp_packets: toNum(packetStats.tcp_packets),
      udp_packets: toNum(packetStats.udp_packets),
    },
    apps: normaliseApps(raw.applications ?? raw.app_breakdown),
    ml: normaliseMl(raw.ml),
    filtering: {
      forwarded: toNum(filtering.forwarded),
      dropped: toNum(filtering.dropped),
      drop_rate: toNum(filtering.drop_rate),
    },
    activeConnections: toNum(fastPath.active_connections),
    inputFile: toStr(meta.input_file) || null,
    durationMs: toNum(meta.duration_ms),
    timestamp: toStr(meta.timestamp) || new Date().toISOString(),
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ["KB", "MB", "GB", "TB"]
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`
}
