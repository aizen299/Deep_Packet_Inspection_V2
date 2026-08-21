export type Theme = "dark" | "light"

/**
 * Chart colours are resolved from this table rather than read back out of the
 * CSS custom properties with getComputedStyle.
 *
 * The `data-theme` attribute is applied in an effect, which runs *after* the
 * render that changed the theme -- so a chart reading computed styles during
 * render always saw the previous theme and drew, for example, near-white axis
 * labels onto the light background. Canvas cannot inherit CSS variables anyway,
 * so the palette is defined here and passed in explicitly.
 */
export const CHART_THEME: Record<Theme, {
  ink: string
  rule: string
  tooltipBg: string
}> = {
  dark: {
    ink: "#f7f7f2",
    rule: "rgba(247, 247, 242, 0.16)",
    tooltipBg: "#07070c",
  },
  light: {
    ink: "#0d0d12",
    rule: "rgba(13, 13, 18, 0.18)",
    tooltipBg: "#ffffff",
  },
}

/** Categorical series, ordered for maximum adjacent contrast. */
export const SERIES_COLORS = [
  "#ccff00",
  "#ff2e88",
  "#00e5ff",
  "#8b5cf6",
  "#ffb300",
  "#3ddc84",
  "#ff6b35",
  "#00c2a8",
  "#e879f9",
]
