"use client"

interface StatSlabProps {
  label: string
  value: string
  sub?: string
  accent: string
  index: number
}

export function StatSlab({ label, value, sub, accent, index }: StatSlabProps) {
  return (
    <div className="slab group relative overflow-hidden p-5">
      {/* Oversized index numeral bleeding out of the corner. */}
      <span
        className="display pointer-events-none absolute -right-3 -bottom-7 text-8xl opacity-[0.09] select-none"
        aria-hidden="true"
      >
        {String(index).padStart(2, "0")}
      </span>

      <div className="flex items-center gap-2">
        <span className="h-3 w-3 border-2 border-[var(--rule-hard)]" style={{ background: accent }} />
        <p className="mono text-[10px] tracking-[0.2em] uppercase text-[var(--ink-dim)]">
          {label}
        </p>
      </div>

      <p className="display mt-3 text-5xl break-all" style={{ color: accent }}>
        {value}
      </p>

      {sub && <p className="mono mt-2 text-[11px] text-[var(--ink-dim)]">{sub}</p>}

      <div
        className="absolute inset-x-0 bottom-0 h-1 origin-left scale-x-0 transition-transform duration-300 group-hover:scale-x-100"
        style={{ background: accent }}
      />
    </div>
  )
}
