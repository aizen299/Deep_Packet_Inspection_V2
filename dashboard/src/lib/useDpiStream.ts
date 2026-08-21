"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { io, type Socket } from "socket.io-client"
import { normaliseSnapshot, type Snapshot } from "./types"

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000"
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || ""

// Bounded: every completed run appends here, so it needs a ceiling.
const MAX_HISTORY = 12

export type ConnectionState = "connecting" | "live" | "offline"

export interface RunHistoryEntry {
  timestamp: string
  totalPackets: number
  riskLevel: string
  inputFile: string | null
}

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return API_KEY ? { ...extra, "x-api-key": API_KEY } : extra
}

export function useDpiStream() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [connection, setConnection] = useState<ConnectionState>("connecting")
  const [analysing, setAnalysing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<RunHistoryEntry[]>([])

  // Guards the "kick off an analysis once we're connected" behaviour so that
  // socket.io's automatic reconnects do not re-trigger an expensive engine run
  // on every network blip.
  const autoAnalysisStarted = useRef(false)

  // The initial GET /stats and the WebSocket both push into the same state.
  // Whichever arrives second used to win; this ref makes live data authoritative
  // so a slow initial fetch can never clobber a fresher push.
  const liveDataReceived = useRef(false)

  const applySnapshot = useCallback((raw: unknown, fromSocket: boolean) => {
    const next = normaliseSnapshot(raw)
    if (!next) return

    if (fromSocket) liveDataReceived.current = true
    else if (liveDataReceived.current) return

    setSnapshot(next)
    setHistory((prev) =>
      [
        {
          timestamp: next.timestamp,
          totalPackets: next.packets.total_packets,
          riskLevel: next.ml.risk_level,
          inputFile: next.inputFile,
        },
        ...prev,
      ].slice(0, MAX_HISTORY)
    )
  }, [])

  const runAnalysis = useCallback(async () => {
    setAnalysing(true)
    setError(null)
    try {
      const res = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: authHeaders(),
      })
      const json = await res.json()
      if (!res.ok || !json.success) {
        setError(json.message || `Analysis failed (${res.status})`)
        return
      }
      applySnapshot(json.data, true)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis request failed")
    } finally {
      setAnalysing(false)
    }
  }, [applySnapshot])

  const uploadCapture = useCallback(
    async (file: File) => {
      setAnalysing(true)
      setError(null)
      try {
        const body = new FormData()
        body.append("pcap", file)

        const res = await fetch(`${API_URL}/upload`, {
          method: "POST",
          headers: authHeaders(),
          body,
        })
        const json = await res.json()
        if (!res.ok || !json.success) {
          setError(json.message || `Upload failed (${res.status})`)
          return
        }
        applySnapshot(json.data, true)
      } catch (err) {
        setError(err instanceof Error ? err.message : "Upload failed")
      } finally {
        setAnalysing(false)
      }
    },
    [applySnapshot]
  )

  useEffect(() => {
    const socket: Socket = io(API_URL, {
      auth: API_KEY ? { apiKey: API_KEY } : undefined,
    })

    const onConnect = () => {
      setConnection("live")
      setError(null)
      if (!autoAnalysisStarted.current) {
        autoAnalysisStarted.current = true
        void runAnalysis()
      }
    }
    const onDisconnect = () => setConnection("offline")
    const onConnectError = (err: Error) => {
      setConnection("offline")
      setError(err.message)
    }
    const onStats = (data: unknown) => applySnapshot(data, true)

    socket.on("connect", onConnect)
    socket.on("disconnect", onDisconnect)
    socket.on("connect_error", onConnectError)
    socket.on("stats_update", onStats)

    // Backfill from the cache so a late-joining dashboard is not blank.
    const controller = new AbortController()
    fetch(`${API_URL}/stats`, {
      headers: authHeaders(),
      signal: controller.signal,
    })
      .then((res) => res.json())
      .then((json) => {
        if (json?.success && json.data) applySnapshot(json.data, false)
      })
      .catch(() => {
        /* the socket is the primary source; a failed backfill is not fatal */
      })

    return () => {
      controller.abort()
      socket.off("connect", onConnect)
      socket.off("disconnect", onDisconnect)
      socket.off("connect_error", onConnectError)
      socket.off("stats_update", onStats)
      socket.disconnect()
    }
  }, [applySnapshot, runAnalysis])

  return {
    snapshot,
    connection,
    analysing,
    error,
    history,
    runAnalysis,
    uploadCapture,
  }
}
