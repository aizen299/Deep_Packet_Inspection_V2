"use client"

interface TickerProps {
  items: string[]
}

/** Duplicated track so the -50% translate loops seamlessly. */
export function Ticker({ items }: TickerProps) {
  if (items.length === 0) return null
  const doubled = [...items, ...items]

  return (
    <div className="relative overflow-hidden border-y-2 border-[var(--rule-hard)] bg-[var(--bg-sunken)] py-2">
      <div className="marquee-track flex w-max gap-8 whitespace-nowrap">
        {doubled.map((item, i) => (
          <span
            key={i}
            className="mono flex items-center gap-3 text-xs tracking-widest uppercase"
          >
            <span className="text-[var(--acid)]">◆</span>
            {item}
          </span>
        ))}
      </div>
    </div>
  )
}
