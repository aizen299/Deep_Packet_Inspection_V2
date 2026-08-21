"use client"

import React from "react"

interface Props {
  children: React.ReactNode
  label: string
}

interface State {
  error: Error | null
}

/**
 * Keeps one malformed payload from blanking the whole dashboard. Panels render
 * data that crossed several untyped process boundaries, so a render-time throw
 * is a realistic failure mode rather than a theoretical one.
 */
export class PanelErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error(`Panel "${this.props.label}" failed to render:`, error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="slab p-6">
          <p className="display text-2xl text-[var(--danger)]">Panel error</p>
          <p className="mono mt-2 text-xs text-[var(--ink-dim)]">
            {this.props.label} could not render this payload.
          </p>
          <p className="mono mt-3 break-words text-[10px] text-[var(--ink-dim)]">
            {this.state.error.message}
          </p>
        </div>
      )
    }
    return this.props.children
  }
}
