/**
 * CORS for the public proxy routes (`app/api/*`).
 *
 * When the API is deployed separately from the static frontend — GitHub Pages
 * serving the UI, this same app running in dynamic mode on Vercel serving
 * `/api/*` — the browser issues cross-origin requests and needs these headers.
 *
 * Set `ALLOWED_ORIGIN` (server-side env, comma-separated) to the frontend
 * origin(s), e.g. `https://you.github.io`.  Defaults to `*` if unset, which is
 * convenient for local testing but should be locked down in production.
 */

const ALLOWED = (process.env.ALLOWED_ORIGIN ?? '*')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

function allowOrigin(origin: string | null): string {
  if (ALLOWED.includes('*')) return '*'
  if (origin && ALLOWED.includes(origin)) return origin
  // Not an allowed origin — echo back the first configured one so the browser
  // cleanly blocks the response rather than the request silently succeeding.
  return ALLOWED[0] ?? '*'
}

export function corsHeaders(origin: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': allowOrigin(origin),
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    Vary: 'Origin',
  }
}

/** Attach CORS headers to a response (mutates and returns it). */
export function withCors<T extends Response>(res: T, origin: string | null): T {
  for (const [k, v] of Object.entries(corsHeaders(origin))) res.headers.set(k, v)
  return res
}

/** Standard CORS preflight handler for an `OPTIONS` request. */
export function preflight(request: Request): Response {
  return new Response(null, { status: 204, headers: corsHeaders(request.headers.get('origin')) })
}
