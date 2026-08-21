"use client"

import { useEffect, useRef, useState } from "react"

/**
 * Smoothed pointer offset for parallax.
 *
 * The raw pointer position is kept in a ref rather than state: driving it
 * through state re-rendered the whole tree on every mousemove and, because the
 * animation effect depended on that state, tore down and restarted the
 * requestAnimationFrame loop roughly every frame. One loop is started here, on
 * mount, and it reads the ref.
 */
export function usePointer(strength = 30, smoothing = 0.08) {
  const target = useRef({ x: 0, y: 0 })
  const [offset, setOffset] = useState({ x: 0, y: 0 })

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      target.current = {
        x: (e.clientX / window.innerWidth - 0.5) * strength,
        y: (e.clientY / window.innerHeight - 0.5) * strength,
      }
    }

    const media = window.matchMedia("(prefers-reduced-motion: reduce)")
    if (media.matches) return

    window.addEventListener("mousemove", onMove, { passive: true })

    let frame = 0
    const lerp = (a: number, b: number, t: number) => a + (b - a) * t

    const tick = () => {
      setOffset((prev) => {
        const next = {
          x: lerp(prev.x, target.current.x, smoothing),
          y: lerp(prev.y, target.current.y, smoothing),
        }
        // Skip the state write once we are close enough to settle.
        if (Math.abs(next.x - prev.x) < 0.01 && Math.abs(next.y - prev.y) < 0.01) {
          return prev
        }
        return next
      })
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)

    return () => {
      window.removeEventListener("mousemove", onMove)
      cancelAnimationFrame(frame)
    }
  }, [strength, smoothing])

  return offset
}
