import { NextRequest, NextResponse } from "next/server"

const USER = process.env.BASIC_AUTH_USER || ""
const PASSWORD = process.env.BASIC_AUTH_PASSWORD || ""

// Failing open on missing credentials is fine on a laptop and dangerous once
// deployed: the client bundle carries NEXT_PUBLIC_API_KEY, so an unset password
// publishes the backend key to anyone who loads the page. In production the
// unauthenticated state has to be asked for by name.
const IS_PRODUCTION = process.env.NODE_ENV === "production"
const ALLOW_UNAUTHENTICATED = process.env.ALLOW_UNAUTHENTICATED === "true"
const CONFIGURED = Boolean(USER && PASSWORD)

// Length-independent comparison so a wrong guess cannot be narrowed down by
// timing the response. Runs in the edge runtime, so no node:crypto here.
function safeEqual(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length)
  let diff = a.length ^ b.length
  for (let i = 0; i < len; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

function unauthorized() {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="DPI Console", charset="UTF-8"' },
  })
}

export function middleware(req: NextRequest) {
  if (!CONFIGURED) {
    if (IS_PRODUCTION && !ALLOW_UNAUTHENTICATED) {
      return new NextResponse(
        "Refusing to serve: BASIC_AUTH_USER and BASIC_AUTH_PASSWORD are unset " +
          "in a production build. Set both, or set ALLOW_UNAUTHENTICATED=true " +
          "to serve this dashboard publicly on purpose.",
        { status: 503 }
      )
    }
    return NextResponse.next()
  }

  const header = req.headers.get("authorization") || ""
  if (!header.startsWith("Basic ")) return unauthorized()

  let decoded: string
  try {
    decoded = atob(header.slice(6))
  } catch {
    return unauthorized()
  }

  const sep = decoded.indexOf(":")
  if (sep === -1) return unauthorized()

  const userOk = safeEqual(decoded.slice(0, sep), USER)
  const passOk = safeEqual(decoded.slice(sep + 1), PASSWORD)
  if (userOk && passOk) return NextResponse.next()

  return unauthorized()
}

// Deliberately covers /_next/static too: the client bundle carries
// NEXT_PUBLIC_API_KEY, so leaving asset paths unauthenticated would hand out the
// backend key to anyone who guesses a chunk URL.
export const config = {
  matcher: ["/((?!_next/image|favicon.ico).*)"],
}
