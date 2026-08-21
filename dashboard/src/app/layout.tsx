import type { Metadata } from "next"
import { Anton, Space_Grotesk, JetBrains_Mono } from "next/font/google"
import "./globals.css"

const display = Anton({
  variable: "--font-display",
  subsets: ["latin"],
  weight: "400",
})

const sans = Space_Grotesk({
  variable: "--font-sans",
  subsets: ["latin"],
})

const mono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
})

export const metadata: Metadata = {
  title: "DPI/OPS — Deep Packet Inspection Control",
  description:
    "Real-time deep packet inspection: protocol breakdown, application classification and ML anomaly scoring.",
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className={`${display.variable} ${sans.variable} ${mono.variable} antialiased`}>
        {children}
      </body>
    </html>
  )
}
