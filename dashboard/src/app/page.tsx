"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useDpiStream } from "@/lib/useDpiStream"
import { usePointer } from "@/lib/usePointer"
import { formatBytes, type RiskLevel } from "@/lib/types"
import type { Theme } from "@/lib/theme"
import { PanelErrorBoundary } from "@/components/ErrorBoundary"
import { Ticker } from "@/components/Ticker"
import { StatSlab } from "@/components/StatSlab"
import { ApplicationChart, ProtocolChart } from "@/components/Charts"

const RISK_COLOR: Record<RiskLevel, string> = {
  Low: "var(--acid)",
  Medium: "var(--amber)",
  High: "var(--danger)",
}

export default function Home() {
  const { snapshot, connection, analysing, error, history, runAnalysis, uploadCapture } =
    useDpiStream()
  const parallax = usePointer(18)
  const [theme, setTheme] = useState<Theme>("dark")
  const fileInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  const exportJson = useCallback(() => {
    if (!snapshot) return
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], {
      type: "application/json",
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `dpi_snapshot_${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [snapshot])

  const tickerItems = useMemo(() => {
    if (!snapshot) return ["Awaiting first capture", "Engine idle", "DPI/OPS v1.0"]
    return [
      `${snapshot.packets.total_packets.toLocaleString()} packets`,
      `${formatBytes(snapshot.packets.total_bytes)} inspected`,
      `${snapshot.activeConnections.toLocaleString()} flows tracked`,
      snapshot.ml ? `Risk ${snapshot.ml.risk_level.toUpperCase()}` : "Risk unscored",
      `Drop rate ${snapshot.filtering.drop_rate.toFixed(2)}%`,
      `${snapshot.apps.length} applications classified`,
      `Run ${snapshot.durationMs} ms`,
      snapshot.inputFile ? `Source ${snapshot.inputFile}` : "Source sample.pcap",
    ]
  }, [snapshot])

  const packets = snapshot?.packets
  const risk = snapshot?.ml

  return (
    <main className="grid-paper relative min-h-screen">
      {/* ---- decorative field ---- */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
      >
        <div
          className="absolute -top-40 -left-40 h-[38rem] w-[38rem] rounded-full opacity-25 blur-[120px]"
          style={{
            background: "var(--violet)",
            transform: `translate3d(${parallax.x}px, ${parallax.y}px, 0)`,
          }}
        />
        <div
          className="absolute -right-40 top-1/3 h-[32rem] w-[32rem] rounded-full opacity-20 blur-[120px]"
          style={{
            background: "var(--magenta)",
            transform: `translate3d(${-parallax.x}px, ${-parallax.y}px, 0)`,
          }}
        />
      </div>

      <div className="relative z-10">
        {/* ================= NAV ================= */}
        <nav className="flex flex-wrap items-center justify-between gap-4 border-b-2 border-[var(--rule-hard)] bg-[var(--bg-sunken)] px-6 py-3">
          <div className="flex items-center gap-3">
            <span className="display bg-[var(--acid)] px-2 py-1 text-xl text-black">DPI</span>
            <span className="mono text-xs tracking-[0.3em] uppercase">/ OPS CONSOLE</span>
          </div>

          <div className="flex items-center gap-3">
            <StatusPill connection={connection} analysing={analysing} />
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="mono cursor-pointer border-2 border-[var(--rule-hard)] px-3 py-1.5 text-[11px] uppercase transition-colors hover:bg-[var(--ink)] hover:text-[var(--bg)]"
            >
              {theme === "dark" ? "Light" : "Dark"}
            </button>
          </div>
        </nav>

        <Ticker items={tickerItems} />

        {/* ================= HERO ================= */}
        <header className="border-b-2 border-[var(--rule-hard)] px-6 py-10">
          <div className="mx-auto max-w-[1600px]">
            <div className="flex flex-wrap items-end justify-between gap-8">
              <div>
                <p className="mono mb-3 text-[11px] tracking-[0.35em] uppercase text-[var(--ink-dim)]">
                  Deep Packet Inspection · Real-time telemetry
                </p>
                <h1 className="display text-[clamp(3rem,11vw,10rem)]">
                  <span className="block">Packet</span>
                  <span className="block outline-text">Intelligence</span>
                </h1>
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={runAnalysis}
                  disabled={analysing}
                  className="mono cursor-pointer border-2 border-[var(--rule-hard)] bg-[var(--acid)] px-5 py-3 text-xs font-bold uppercase text-black shadow-[5px_5px_0_var(--shadow)] transition-transform hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0_var(--shadow)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {analysing ? "Analysing…" : "Run analysis"}
                </button>

                <button
                  onClick={() => fileInput.current?.click()}
                  disabled={analysing}
                  className="mono cursor-pointer border-2 border-[var(--rule-hard)] bg-[var(--cyan)] px-5 py-3 text-xs font-bold uppercase text-black shadow-[5px_5px_0_var(--shadow)] transition-transform hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0_var(--shadow)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Upload PCAP
                </button>
                <input
                  ref={fileInput}
                  type="file"
                  accept=".pcap,.pcapng"
                  hidden
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) void uploadCapture(file)
                    e.target.value = ""
                  }}
                />

                <button
                  onClick={exportJson}
                  disabled={!snapshot}
                  className="mono cursor-pointer border-2 border-[var(--rule-hard)] px-5 py-3 text-xs font-bold uppercase shadow-[5px_5px_0_var(--shadow)] transition-transform hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0_var(--shadow)] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Export JSON
                </button>
              </div>
            </div>

            {error && (
              <div className="slab mt-8 border-[var(--danger)] p-4">
                <p className="mono text-xs uppercase text-[var(--danger)]">
                  ▲ {error}
                </p>
              </div>
            )}
          </div>
        </header>

        {/* ================= BODY ================= */}
        {!snapshot ? (
          <LoadingState connection={connection} />
        ) : (
          <div className="mx-auto max-w-[1600px] px-6 py-10">
            {/* ---- stat row ---- */}
            <section className="mb-10 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
              <StatSlab
                index={1}
                label="Total packets"
                value={packets!.total_packets.toLocaleString()}
                sub={`${snapshot.filtering.forwarded.toLocaleString()} forwarded · ${snapshot.filtering.dropped.toLocaleString()} dropped`}
                accent="var(--acid)"
              />
              <StatSlab
                index={2}
                label="Volume"
                value={formatBytes(packets!.total_bytes)}
                sub={`${packets!.total_bytes.toLocaleString()} bytes raw`}
                accent="var(--cyan)"
              />
              <StatSlab
                index={3}
                label="TCP"
                value={packets!.tcp_packets.toLocaleString()}
                sub={pct(packets!.tcp_packets, packets!.total_packets)}
                accent="var(--violet)"
              />
              <StatSlab
                index={4}
                label="UDP"
                value={packets!.udp_packets.toLocaleString()}
                sub={pct(packets!.udp_packets, packets!.total_packets)}
                accent="var(--magenta)"
              />
              <StatSlab
                index={5}
                label="Active flows"
                value={snapshot.activeConnections.toLocaleString()}
                sub={`${snapshot.apps.length} apps classified`}
                accent="var(--amber)"
              />
            </section>

            {/* ---- risk banner ---- */}
            <section className="slab mb-10 relative overflow-hidden p-8">
              <div
                className="absolute inset-y-0 left-0 w-2"
                style={{ background: risk ? RISK_COLOR[risk.risk_level] : "var(--ink-dim)" }}
              />
              <div className="flex flex-wrap items-center justify-between gap-8">
                <div>
                  <p className="mono text-[11px] tracking-[0.3em] uppercase text-[var(--ink-dim)]">
                    ML anomaly verdict
                  </p>
                  <p
                    className="display mt-2 text-7xl"
                    style={{ color: risk ? RISK_COLOR[risk.risk_level] : "var(--ink-dim)" }}
                  >
                    {risk ? `${risk.risk_level} risk` : "Unscored"}
                  </p>
                  {!risk && (
                    <p className="mono mt-2 text-[12px] text-[var(--ink-dim)]">
                      Scorer unreachable — packet analysis below is unaffected.
                    </p>
                  )}
                </div>

                <div className="flex gap-10">
                  <Metric label="Score" value={risk ? risk.risk_score.toFixed(3) : "—"} />
                  <Metric label="Confidence" value={risk ? risk.confidence.toFixed(3) : "—"} />
                  <Metric label="Drop rate" value={`${snapshot.filtering.drop_rate.toFixed(2)}%`} />
                </div>
              </div>

              {/* score meter -- an empty track when there is no score to draw */}
              <div className="mt-8 h-4 w-full border-2 border-[var(--rule-hard)] bg-[var(--bg-sunken)]">
                {risk && (
                  <div
                    className="h-full transition-[width] duration-700"
                    style={{
                      width: `${Math.round(risk.risk_score * 100)}%`,
                      background: RISK_COLOR[risk.risk_level],
                    }}
                  />
                )}
              </div>
            </section>

            {/* ---- charts + anomalies ---- */}
            <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <Panel title="Application distribution" span="xl:col-span-2">
                <PanelErrorBoundary label="Application distribution">
                  <div className="h-[520px]">
                    <ApplicationChart apps={snapshot.apps} theme={theme} />
                  </div>
                </PanelErrorBoundary>
              </Panel>

              <div className="flex flex-col gap-6">
                <Panel title="Protocol split">
                  <PanelErrorBoundary label="Protocol split">
                    <div className="h-[240px]">
                      <ProtocolChart packets={packets!} theme={theme} />
                    </div>
                  </PanelErrorBoundary>
                </Panel>

                <Panel title="Detected anomalies">
                  <div className="space-y-3">
                    {!risk ? (
                      <p className="mono text-xs text-[var(--ink-dim)]">
                        No verdict — the scorer did not respond.
                      </p>
                    ) : risk.anomalies.length === 0 ? (
                      <p className="mono text-xs text-[var(--ink-dim)]">
                        Nothing flagged in this capture.
                      </p>
                    ) : (
                      risk.anomalies.map((a, i) => (
                        <div
                          key={`${a}-${i}`}
                          className="flex items-start gap-3 border-l-4 border-[var(--danger)] bg-[var(--bg-sunken)] px-3 py-2"
                        >
                          <span className="mono text-[10px] text-[var(--danger)]">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <span className="mono text-xs">{a}</span>
                        </div>
                      ))
                    )}
                  </div>
                </Panel>
              </div>
            </section>

            {/* ---- run history ---- */}
            <section className="mt-6">
              <Panel title="Run history">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] border-collapse">
                    <thead>
                      <tr className="border-b-2 border-[var(--rule-hard)]">
                        {["#", "Timestamp", "Source", "Packets", "Risk"].map((h) => (
                          <th
                            key={h}
                            className="mono px-3 py-2 text-left text-[10px] tracking-[0.2em] uppercase text-[var(--ink-dim)]"
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((run, i) => (
                        <tr key={`${run.timestamp}-${i}`} className="border-b border-[var(--rule)]">
                          <td className="mono px-3 py-2 text-xs text-[var(--ink-dim)]">
                            {String(history.length - i).padStart(2, "0")}
                          </td>
                          <td className="mono px-3 py-2 text-xs">
                            {new Date(run.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="mono px-3 py-2 text-xs">{run.inputFile ?? "—"}</td>
                          <td className="mono px-3 py-2 text-xs">
                            {run.totalPackets.toLocaleString()}
                          </td>
                          <td className="mono px-3 py-2 text-xs">
                            <span
                              className="px-2 py-0.5 text-black"
                              style={{ background: RISK_COLOR[run.riskLevel as RiskLevel] ?? "var(--acid)" }}
                            >
                              {run.riskLevel}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            </section>
          </div>
        )}

        <footer className="mt-10 border-t-2 border-[var(--rule-hard)] bg-[var(--bg-sunken)] px-6 py-8">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4">
            <p className="display text-3xl">DPI/OPS</p>
            <p className="mono text-[11px] text-[var(--ink-dim)]">
              C++ engine · Node control plane · FastAPI scoring · GPL-3.0
            </p>
          </div>
        </footer>
      </div>
    </main>
  )
}

/* ---------------- small local pieces ---------------- */

function pct(part: number, total: number): string {
  if (total <= 0) return "0.0% of traffic"
  return `${((part / total) * 100).toFixed(1)}% of traffic`
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="mono text-[10px] tracking-[0.2em] uppercase text-[var(--ink-dim)]">
        {label}
      </p>
      <p className="mono mt-1 text-2xl">{value}</p>
    </div>
  )
}

function Panel({
  title,
  children,
  span = "",
}: {
  title: string
  children: React.ReactNode
  span?: string
}) {
  return (
    <div className={`slab p-6 ${span}`}>
      <div className="mb-5 flex items-center gap-3">
        <span className="h-2 w-8 bg-[var(--ink)]" />
        <h2 className="mono text-[11px] tracking-[0.25em] uppercase">{title}</h2>
      </div>
      {children}
    </div>
  )
}

function StatusPill({
  connection,
  analysing,
}: {
  connection: string
  analysing: boolean
}) {
  const map: Record<string, { text: string; color: string }> = {
    live: { text: "Live", color: "var(--acid)" },
    connecting: { text: "Connecting", color: "var(--amber)" },
    offline: { text: "Offline", color: "var(--danger)" },
  }
  const state = analysing
    ? { text: "Engine running", color: "var(--cyan)" }
    : map[connection] ?? map.offline

  return (
    <span className="mono flex items-center gap-2 border-2 border-[var(--rule-hard)] px-3 py-1.5 text-[11px] uppercase">
      <span
        className="blink h-2 w-2 rounded-full"
        style={{ background: state.color }}
      />
      {state.text}
    </span>
  )
}

function LoadingState({ connection }: { connection: string }) {
  return (
    <div className="flex min-h-[50vh] items-center justify-center px-6">
      <div className="slab relative overflow-hidden p-12 text-center">
        <div className="sweep absolute inset-x-0 h-24 bg-[var(--acid)] opacity-[0.07]" />
        <p className="display text-5xl">
          {connection === "offline" ? "No signal" : "Awaiting capture"}
        </p>
        <p className="mono mt-4 text-xs text-[var(--ink-dim)]">
          {connection === "offline"
            ? "Control plane unreachable — check the API on port 4000."
            : "Connecting to the control plane and requesting the first analysis…"}
        </p>
      </div>
    </div>
  )
}
