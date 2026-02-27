"use client"

import { useEffect, useRef, useState } from "react"
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js"
import { Bar, Pie } from "react-chartjs-2"
import { motion } from "framer-motion"
import * as THREE from "three"

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend)

export default function Home() {
  const [stats, setStats] = useState<any>(null)
  const [darkMode, setDarkMode] = useState(true)
  const [mouse, setMouse] = useState({ x: 0, y: 0 })
  const mouseRef = useRef({ x: 0, y: 0 })
  const [smooth, setSmooth] = useState({ x: 0, y: 0 })
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const runAnalysis = async () => {
      try {
        await fetch("http://localhost:4000/analyze", {
          method: "POST",
        })
      } catch (err) {
        console.error("Failed to start analysis:", err)
      }
    }

    const fetchStats = async () => {
      try {
        const res = await fetch("http://localhost:4000/stats")
        const json = await res.json()
        if (json.success) {
          setStats(json.data)
        } else {
          console.error("API error:", json.message)
        }
      } catch (err) {
        console.error("Backend unreachable:", err)
      }
    }

    // Run engine once on load
    runAnalysis().then(fetchStats)

    // Then poll only cached stats
    const interval = setInterval(fetchStats, 5000)

    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const handleMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 30
      const y = (e.clientY / window.innerHeight - 0.5) * 30
      setMouse({ x, y })
      mouseRef.current = { x, y }
    }
    window.addEventListener("mousemove", handleMove)
    return () => window.removeEventListener("mousemove", handleMove)
  }, [])

  useEffect(() => {
    let animationFrame: number
    const lerp = (start: number, end: number, factor: number) => start + (end - start) * factor

    const animate = () => {
      setSmooth(prev => ({
        x: lerp(prev.x, mouse.x, 0.08),
        y: lerp(prev.y, mouse.y, 0.08),
      }))
      animationFrame = requestAnimationFrame(animate)
    }
    animate()
    return () => cancelAnimationFrame(animationFrame)
  }, [mouse])

  useEffect(() => {
    const container = canvasRef.current as any
    if (!container) return

    const scene = new THREE.Scene()
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1)
    const renderer = new THREE.WebGLRenderer({ alpha: true })
    renderer.setSize(window.innerWidth, window.innerHeight)

    const handleResize = () => {
      renderer.setSize(window.innerWidth, window.innerHeight)
      uniforms.u_resolution.value.set(window.innerWidth, window.innerHeight)
    }

    window.addEventListener("resize", handleResize)

    container.appendChild(renderer.domElement)

    const uniforms = {
      u_time: { value: 0 },
      u_mouse: { value: new THREE.Vector2(0, 0) },
      u_resolution: { value: new THREE.Vector2(window.innerWidth, window.innerHeight) },
    }

    const material = new THREE.ShaderMaterial({
      uniforms,
      fragmentShader: `
        uniform float u_time;
        uniform vec2 u_mouse;
        uniform vec2 u_resolution;

        void main() {
          vec2 uv = gl_FragCoord.xy / u_resolution;
          float wave = sin(uv.y * 10.0 + u_time * 0.8) * 0.02;
          float dist = distance(uv, u_mouse);

          vec3 color = vec3(0.05, 0.1, 0.2);
          color += 0.3 * vec3(
            sin(u_time + uv.x * 5.0),
            cos(u_time + uv.y * 5.0),
            sin(u_time)
          );
          color += 0.4 * exp(-8.0 * dist);

          gl_FragColor = vec4(color + wave, 1.0);
        }
      `,
    })

    const geometry = new THREE.PlaneGeometry(2, 2)
    const mesh = new THREE.Mesh(geometry, material)
    scene.add(mesh)

    const animate = (time: number) => {
      uniforms.u_time.value = time * 0.001
      uniforms.u_mouse.value.set(
        (mouseRef.current.x / 60) + 0.5,
        (mouseRef.current.y / 60) + 0.5
      )
      renderer.render(scene, camera)
      requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)

    return () => {
      window.removeEventListener("resize", handleResize)
      renderer.dispose()
      container.removeChild(renderer.domElement)
    }
  }, [])

  if (!stats) return <div className="min-h-screen bg-black text-white flex items-center justify-center">Loading...</div>

  const summary = stats.packet_stats || {
    total_packets: 0,
    total_bytes: 0,
    tcp_packets: 0,
    udp_packets: 0
  }
  const apps = stats.applications || stats.app_breakdown || {}
  const sortedApps = Object.entries(apps).sort(
    (a, b) => ((b[1] as any)?.count ?? 0) - ((a[1] as any)?.count ?? 0)
  )

  const appLabels = sortedApps.map(([name, value]) => {
    const percent = (value as any)?.percentage ?? 0
    return `${name} (${percent}%)`
  })

  const appCounts = sortedApps.map(([, value]) =>
    (value as any)?.count ?? 0
  )

  const textColor = darkMode ? "#ffffff" : "#111111"
  const gridColor = darkMode
    ? "rgba(255,255,255,0.15)"
    : "rgba(0,0,0,0.15)"

  const barData = {
    labels: appLabels,
    datasets: [{
      data: appCounts,
      backgroundColor: (ctx: any) => {
        const chart = ctx.chart
        const { ctx: c } = chart
        const gradient = c.createLinearGradient(0, 0, chart.width, 0)
        if (darkMode) {
          gradient.addColorStop(0, "#00f5ff")
          gradient.addColorStop(0.5, "#7b61ff")
          gradient.addColorStop(1, "#ff3cac")
        } else {
          gradient.addColorStop(0, "#2563eb")
          gradient.addColorStop(1, "#9333ea")
        }
        return gradient
      },
      borderRadius: 12,
    }],
  }

  const barOptions = {
    indexAxis: "y" as const,
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: function(context: any) {
            const rawValue = context.raw
            const original = sortedApps[context.dataIndex]
            const percent = (original?.[1] as any)?.percentage ?? 0
            return ` ${rawValue} packets (${percent}%)`
          }
        }
      }
    },
    scales: {
      x: {
        ticks: { 
          color: textColor,
          font: { size: 12 }
        },
        grid: { color: gridColor },
      },
      y: {
        ticks: { 
          color: textColor,
          font: { size: 12 }
        },
        grid: { display: false },
      },
    },
  }

  const pieData = {
    labels: ["TCP", "UDP"],
    datasets: [{
      data: [summary.tcp_packets, summary.udp_packets],
      backgroundColor: darkMode
        ? ["#00f5ff", "#ff3cac"]
        : ["#2563eb", "#9333ea"],
      borderWidth: 0,
    }],
  }

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(stats, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "dpi_stats.json"
    a.click()
  }

  const handleUpload = async (file: File) => {
    const formData = new FormData()
    formData.append("pcap", file)

    try {
      const res = await fetch("http://localhost:4000/upload", {
        method: "POST",
        body: formData,
      })

      const json = await res.json()

      if (json.success) {
        setStats(json.data)
      } else {
        console.error("Upload API error:", json.message)
      }
    } catch (err) {
      console.error("Upload failed:", err)
    }
  }

  const glass = "relative backdrop-blur-3xl bg-white/15 dark:bg-white/10 border border-white/25 shadow-[0_25px_100px_rgba(0,0,0,0.65)] overflow-hidden transition-all duration-500"

  return (
    <main className={`relative min-h-screen overflow-hidden transition-all duration-700 ${darkMode ? "bg-black" : "bg-white"}`}>
      <div className="absolute inset-0 z-0 overflow-hidden">
        <div className="absolute inset-0 bg-cover bg-center animate-zoomBlur" 
             style={{
               backgroundImage: "url('/bg.jpg')",
               filter: "blur(15px) brightness(0.9)",
               transform: "scale(1.2)"
             }}
        />
      </div>

      <div className="absolute inset-0 pointer-events-none opacity-20 mix-blend-overlay" style={{ backgroundImage: "url('https://www.transparenttextures.com/patterns/noise.png')" }} />

      <div
        className="relative z-10 p-12 transition-transform duration-300"
        style={{ transform: `translate3d(${smooth.x}px, ${smooth.y}px, 0)` }}
      >
        <div className="flex justify-between items-center mb-12 relative z-20 isolate">
          <h1
            className="text-4xl font-semibold tracking-tight"
            style={{
              color: darkMode ? "#ffffff" : "#000000",
              WebkitTextStroke: darkMode ? "0px transparent" : "0px transparent",
              textShadow: darkMode
                ? "0 6px 40px rgba(0,0,0,0.9)"
                : "0 6px 40px rgba(255,255,255,0.9)",
              position: "relative",
              zIndex: 50
            }}
          >
            DEEP PACKET INSPECTION DASHBOARD
          </h1>
          <div className="flex gap-4 items-center">
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="px-5 py-2 rounded-full backdrop-blur-xl bg-white/20 border border-white/30 shadow-[0_10px_30px_rgba(0,0,0,0.25)] hover:bg-white/30 hover:scale-105 transition-all duration-300"
            >
              {darkMode ? "Light" : "Dark"}
            </button>
            <button
              onClick={exportJSON}
              className="px-5 py-2 rounded-full backdrop-blur-xl bg-gradient-to-r from-cyan-400/30 to-blue-500/30 border border-white/30 text-white shadow-[0_10px_30px_rgba(0,0,0,0.35)] hover:scale-105 hover:shadow-[0_0_40px_rgba(0,255,255,0.6)] transition-all duration-300"
            >
              Export JSON
            </button>
            <label className="px-5 py-2 rounded-full backdrop-blur-xl bg-gradient-to-r from-emerald-400/30 to-teal-500/30 border border-white/30 text-white shadow-[0_10px_30px_rgba(0,0,0,0.35)] hover:scale-105 hover:shadow-[0_0_40px_rgba(0,255,200,0.6)] transition-all duration-300 cursor-pointer">
              Upload PCAP
              <input
                type="file"
                accept=".pcap"
                hidden
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) handleUpload(file)
                }}
              />
            </label>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-14">
          {[["Packets", summary.total_packets], ["Bytes", summary.total_bytes], ["TCP", summary.tcp_packets], ["UDP", summary.udp_packets]].map(([label, value]) => (
            <motion.div
              key={label as string}
              className={`${glass} p-8 rounded-3xl`}
              whileHover={{
                scale: 1.05,
                rotateX: -mouse.y * 0.2,
                rotateY: mouse.x * 0.2,
                boxShadow: "0 0 60px rgba(255,255,255,0.25)"
              }}
              transition={{ type: "spring", stiffness: 200, damping: 15 }}
              style={{
                transformStyle: "preserve-3d",
                perspective: 1000,
                background: `radial-gradient(circle at ${50 + mouse.x}% ${50 + mouse.y}%, rgba(255,255,255,0.35), rgba(255,255,255,0.08))`,
                backdropFilter: "blur(30px)",
              }}
            >
              <div
                className="absolute inset-0 pointer-events-none opacity-30"
                style={{
                  background: `radial-gradient(circle at ${50 - mouse.x}% ${50 - mouse.y}%, rgba(255,255,255,0.4), transparent 60%)`
                }}
              />
              <p className="text-sm opacity-70">{label}</p>
              <p className="text-3xl font-bold mt-3">{Number(value).toLocaleString()}</p>
            </motion.div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
          <section className={`${glass} p-10 rounded-3xl col-span-2 hover:shadow-[0_0_80px_rgba(255,255,255,0.25)] transition-all duration-500`}>
            <h2 className="text-lg mb-6 opacity-80">Application Distribution</h2>
            <div className="h-[520px] bg-white/15 dark:bg-white/10 backdrop-blur-2xl rounded-2xl p-6 border border-white/20 shadow-inner">
              <Bar data={barData} options={barOptions} />
            </div>
          </section>

          <section className={`${glass} p-10 rounded-3xl hover:shadow-[0_0_80px_rgba(255,255,255,0.25)] transition-all duration-500`}>
            <h2 className="text-lg mb-6 opacity-80">Protocol Split</h2>
            <div className="h-[320px] bg-white/15 dark:bg-white/10 backdrop-blur-2xl rounded-2xl p-6 border border-white/20 shadow-inner flex items-center justify-center">
              <Pie data={pieData} />
            </div>
          </section>
        </div>
      </div>

      <style jsx global>{`
        @keyframes zoomBlur {
          0% {
            transform: scale(1.2);
          }
          50% {
            transform: scale(1.35);
          }
          100% {
            transform: scale(1.2);
          }
        }

        .animate-zoomBlur {
          animation: zoomBlur 25s ease-in-out infinite;
        }
      `}</style>
      <div className="pointer-events-none absolute inset-0 mix-blend-overlay opacity-20" style={{
        background: "radial-gradient(circle at center, transparent 60%, rgba(255,0,0,0.15) 100%)",
        filter: "blur(20px) "
      }} />
    </main>
  )
}