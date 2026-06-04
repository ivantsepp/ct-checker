/**
 * Transport layer for CT log fetches.
 *
 * Two modes, selected at build time via `NEXT_PUBLIC_STATIC_BUILD`:
 *
 *   - Proxy mode (default — `npm run dev` / `npm run build`):
 *     All log requests go through `/api/ct-proxy`, which validates the log
 *     URL against the trusted log list and forwards the request server-side.
 *     No CORS issues; the proxy can talk to logs that lack CORS headers.
 *
 *   - Static mode (`npm run build:static` → GitHub Pages):
 *     No server-side proxy is co-located.  Two sub-cases:
 *       • A remote proxy is configured (`NEXT_PUBLIC_PROXY_BASE`, e.g. this
 *         same app deployed in dynamic mode on Vercel): requests are prefixed
 *         with that base and hop through the remote `/api/*` routes.  This is
 *         the recommended GitHub Pages setup — full access, no CORS issues.
 *       • No proxy configured: requests go directly from the browser to each
 *         CT log.  Many logs do not serve `Access-Control-Allow-Origin: *`,
 *         so the browser blocks these as CORS errors (surfaced as `CORSError`).
 */

import { fromBase64 } from './sct-parser'

export const IS_STATIC_BUILD = process.env.NEXT_PUBLIC_STATIC_BUILD === '1'

/**
 * Base URL of the server-side proxy.  Empty in the dynamic build (the `/api/*`
 * routes are co-located, so same-origin relative URLs work).  In a static
 * build, point `NEXT_PUBLIC_PROXY_BASE` at a separately-deployed backend
 * (e.g. this same app running in dynamic mode on Vercel) and all `/api/*`
 * calls are prefixed with it.
 */
export const PROXY_BASE = (process.env.NEXT_PUBLIC_PROXY_BASE ?? '').replace(/\/+$/, '')

/**
 * Whether a server-side proxy is reachable.  True in the dynamic build, or in
 * a static build pointed at a remote proxy via `PROXY_BASE`.  When false
 * (static build, no proxy), log fetches go direct from the browser and domain
 * lookup is unavailable.
 */
export const HAS_PROXY = !IS_STATIC_BUILD || PROXY_BASE !== ''

/** Prefix an `/api/...` path with the proxy base (no-op when same-origin). */
export function apiUrl(path: string): string {
  return PROXY_BASE + path
}

/**
 * CT log origins (static build only) that failed a direct browser fetch with a
 * CORS/network error.  Once an origin is recorded here we skip the direct
 * attempt and go straight to the proxy, so the failed request isn't repeated on
 * every subsequent tile/endpoint fetch for that log.
 */
const corsBlockedOrigins = new Set<string>()

/**
 * Thrown when a direct cross-origin fetch fails with a `TypeError` —
 * the browser's signal for either a CORS rejection or an outright
 * network failure (they're indistinguishable from JS, by design).
 * In a static build, the cause is almost always missing CORS headers
 * on the CT log; we attribute it to that in the message.
 */
export class CORSError extends Error {
  constructor(public readonly logUrl: string, public readonly endpoint: string, cause?: unknown) {
    super(
      `Cannot reach ${logUrl} directly from the browser. This is a frontend-only ` +
      `build, so requests go straight to the CT log — and this log does not ` +
      `serve CORS headers (or is unreachable). Run a local dev server (` +
      `npm run dev) for full access via the server-side proxy.`,
    )
    this.name = 'CORSError'
    if (cause) (this as Error & { cause?: unknown }).cause = cause
  }
}

export interface CTResponse {
  json?: unknown
  text?: string
  bytes?: Uint8Array
}

type Shape = 'json' | 'text' | 'binary'

function endpointShape(endpoint: string): Shape {
  if (endpoint === 'checkpoint') return 'text'
  if (endpoint.startsWith('tile/')) return 'binary'
  return 'json'
}

/**
 * One captured CT-log HTTP exchange.  Surfaced in the UI so the user can see
 * the actual requests/responses (get-sth, get-proof-by-hash, checkpoint, tiles)
 * that built an inclusion proof.
 */
export interface ApiCall {
  /** Log endpoint path, e.g. `ct/v1/get-sth`, `checkpoint`, `tile/0/000`. */
  endpoint: string
  /** Query params sent (RFC 6962 endpoints only). */
  params?: Record<string, string>
  /** The URL actually fetched — proxied (`/api/ct-proxy?...`) or direct. */
  url: string
  /** How the request left the browser. */
  via: 'proxy' | 'direct'
  method: 'GET'
  shape: Shape
  ok: boolean
  /** Upstream status, when known (direct fetches only; proxy hides it). */
  status?: number
  /** Decoded JSON body (RFC 6962 endpoints). */
  json?: unknown
  /** Text body (checkpoint signed note). */
  text?: string
  /** Hex of a binary tile body, for a collapsible dump. */
  bytesHex?: string
  /** Byte length of a binary tile body. */
  byteLength?: number
  error?: string
  durationMs: number
}

/** Sink for captured calls; threaded through the CT fetch chain. */
export type ApiRecorder = (call: ApiCall) => void

function toHexLocal(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

/**
 * Fetch a CT-log endpoint.  Transport depends on the build:
 *
 *   - No proxy (static, unconfigured): fetch the log directly from the browser.
 *   - Dynamic build: hop through the same-origin `/api/ct-proxy`.
 *   - Static build with a remote proxy: try a direct browser fetch first (many
 *     logs serve CORS, so this avoids a cross-origin round trip to the proxy),
 *     and fall back to the proxy only when the log is CORS-blocked.  Blocked
 *     origins are remembered so the failed-direct attempt happens at most once.
 *
 * The return shape mirrors what the server proxy sends back:
 *   - `json`   for RFC 6962 `ct/v1/*`
 *   - `text`   for the RFC 9162 `checkpoint` signed note
 *   - `bytes`  for Sunlight binary tiles
 */
export async function ctFetch(
  logUrl: string,
  endpoint: string,
  params?: Record<string, string>,
  recorder?: ApiRecorder,
): Promise<CTResponse> {
  const shape = endpointShape(endpoint)
  const started = performance.now()

  // Build the base record up front; the response fields and `ok` are filled in
  // before each return/throw, then handed to the recorder (if any).
  const record = (
    extra: Partial<ApiCall> & { ok: boolean },
    url: string,
    via: 'proxy' | 'direct',
  ) => {
    if (!recorder) return
    recorder({
      endpoint,
      params,
      url,
      via,
      method: 'GET',
      shape,
      durationMs: performance.now() - started,
      ...extra,
    })
  }

  // Direct browser → CT log fetch.  Throws CORSError on network/CORS failure.
  const fetchDirect = async (): Promise<CTResponse> => {
    const base = logUrl.replace(/\/$/, '')
    const path = endpoint.replace(/^\//, '')
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    const target = `${base}/${path}${qs}`

    let res: Response
    try {
      res = await fetch(target, {
        headers: { Accept: shape === 'json' ? 'application/json' : '*/*' },
      })
    } catch (e) {
      // Browser fetch throws TypeError for both CORS rejection and network
      // unreachability — we cannot distinguish, so label as CORS.
      const err = e instanceof TypeError ? new CORSError(logUrl, endpoint, e) : e
      record({ ok: false, error: String(err) }, target, 'direct')
      throw err
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      record({ ok: false, status: res.status, error: body.slice(0, 200) }, target, 'direct')
      throw new Error(`Log ${logUrl} returned ${res.status}: ${body.slice(0, 200)}`)
    }

    if (shape === 'json') {
      const json = await res.json()
      record({ ok: true, status: res.status, json }, target, 'direct')
      return { json }
    }
    if (shape === 'text') {
      const text = await res.text()
      record({ ok: true, status: res.status, text }, target, 'direct')
      return { text }
    }
    const bytes = new Uint8Array(await res.arrayBuffer())
    record(
      { ok: true, status: res.status, bytesHex: toHexLocal(bytes), byteLength: bytes.length },
      target,
      'direct',
    )
    return { bytes }
  }

  // Hop through the server-side proxy (`/api/ct-proxy`).
  const fetchViaProxy = async (): Promise<CTResponse> => {
    const qs = params ? '&' + new URLSearchParams(params).toString() : ''
    const url = apiUrl(`/api/ct-proxy?logUrl=${encodeURIComponent(logUrl)}&endpoint=${encodeURIComponent(endpoint)}${qs}`)

    const res = await fetch(url)
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      record({ ok: false, status: res.status, error: body.slice(0, 200) }, url, 'proxy')
      throw new Error(`CT proxy ${res.status}: ${body.slice(0, 200)}`)
    }
    const data = (await res.json()) as { text?: string; bytes?: string; error?: string }
    if (data && typeof data === 'object' && 'error' in data && data.error) {
      record({ ok: false, error: String(data.error) }, url, 'proxy')
      throw new Error(String(data.error))
    }
    if (shape === 'json') {
      record({ ok: true, json: data }, url, 'proxy')
      return { json: data }
    }
    if (shape === 'text') {
      if (typeof data.text !== 'string') throw new Error('Proxy returned no text')
      record({ ok: true, text: data.text }, url, 'proxy')
      return { text: data.text }
    }
    if (typeof data.bytes !== 'string') throw new Error('Proxy returned no bytes')
    const bytes = fromBase64(data.bytes)
    record({ ok: true, bytesHex: toHexLocal(bytes), byteLength: bytes.length }, url, 'proxy')
    return { bytes }
  }

  // ── Pick a transport ──────────────────────────────────────────────────────
  // Static build, no proxy configured: direct is the only option.
  if (!HAS_PROXY) return fetchDirect()
  // Dynamic build: proxy is same-origin and free; a direct cross-origin fetch
  // would just CORS-fail, so go straight to the proxy.
  if (!IS_STATIC_BUILD) return fetchViaProxy()

  // Static build with a remote proxy: try direct first, fall back to the proxy
  // only on a CORS/network error — and remember the blocked origin so we don't
  // retry direct on every subsequent fetch for the same log.
  const key = logUrl.replace(/\/$/, '')
  if (!corsBlockedOrigins.has(key)) {
    try {
      return await fetchDirect()
    } catch (e) {
      if (!(e instanceof CORSError)) throw e // a real log error — don't mask it
      corsBlockedOrigins.add(key)
    }
  }
  return fetchViaProxy()
}
