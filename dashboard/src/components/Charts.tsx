"use client"

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  type TooltipItem,
} from "chart.js"
import { Bar, Doughnut } from "react-chartjs-2"
import type { AppEntry, PacketStats } from "@/lib/types"
import { CHART_THEME, SERIES_COLORS, type Theme } from "@/lib/theme"

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend)

const MONO = "var(--font-mono), ui-monospace, monospace"

export function ApplicationChart({ apps, theme }: { apps: AppEntry[]; theme: Theme }) {
  const t = CHART_THEME[theme]

  if (apps.length === 0) {
    return <EmptyPanel message="No classified applications in this capture." />
  }

  const data = {
    labels: apps.map((a) => a.name),
    datasets: [
      {
        data: apps.map((a) => a.count),
        backgroundColor: apps.map((_, i) => SERIES_COLORS[i % SERIES_COLORS.length]),
        borderColor: t.ink,
        borderWidth: 2,
        borderRadius: 0,
      },
    ],
  }

  const options = {
    indexAxis: "y" as const,
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: t.tooltipBg,
        titleColor: t.ink,
        bodyColor: t.ink,
        borderColor: t.ink,
        borderWidth: 2,
        displayColors: false,
        titleFont: { family: MONO, size: 12 },
        bodyFont: { family: MONO, size: 12 },
        callbacks: {
          label(ctx: TooltipItem<"bar">) {
            const entry = apps[ctx.dataIndex]
            return ` ${entry.count} packets — ${entry.percentage.toFixed(2)}%`
          },
        },
      },
    },
    scales: {
      x: {
        ticks: { color: t.ink, font: { family: MONO, size: 11 } },
        grid: { color: t.rule },
        border: { color: t.ink, width: 2 },
      },
      y: {
        ticks: { color: t.ink, font: { family: MONO, size: 12 } },
        grid: { display: false },
        border: { color: t.ink, width: 2 },
      },
    },
  }

  return <Bar data={data} options={options} />
}

export function ProtocolChart({
  packets,
  theme,
}: {
  packets: PacketStats
  theme: Theme
}) {
  const t = CHART_THEME[theme]
  const total = packets.tcp_packets + packets.udp_packets

  if (total === 0) {
    return <EmptyPanel message="No TCP/UDP packets recorded." />
  }

  const data = {
    labels: ["TCP", "UDP"],
    datasets: [
      {
        data: [packets.tcp_packets, packets.udp_packets],
        backgroundColor: ["#00e5ff", "#ff2e88"],
        borderColor: t.ink,
        borderWidth: 3,
        cutout: "62%",
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "bottom" as const,
        labels: {
          color: t.ink,
          boxWidth: 14,
          font: { family: MONO, size: 12 },
        },
      },
      tooltip: {
        backgroundColor: t.tooltipBg,
        titleColor: t.ink,
        bodyColor: t.ink,
        borderColor: t.ink,
        borderWidth: 2,
        displayColors: false,
        bodyFont: { family: MONO, size: 12 },
        callbacks: {
          label(ctx: TooltipItem<"doughnut">) {
            const value = Number(ctx.raw) || 0
            return ` ${value} (${((value / total) * 100).toFixed(1)}%)`
          },
        },
      },
    },
  }

  return <Doughnut data={data} options={options} />
}

function EmptyPanel({ message }: { message: string }) {
  return (
    <div className="stripe flex h-full items-center justify-center border-2 border-dashed border-[var(--rule)]">
      <p className="mono bg-[var(--bg-raised)] px-3 py-1 text-xs text-[var(--ink-dim)]">
        {message}
      </p>
    </div>
  )
}
