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
 *     No server-side proxy exists.  Requests go directly from the browser to
 *     each CT log.  Many logs do not serve `Access-Control-Allow-Origin: *`,
 *     so the browser will block these as CORS errors.  We surface those to
 *     the UI as `CORSError`.
 */

import { fromBase64 } from './sct-parser'

export const IS_STATIC_BUILD = process.env.NEXT_PUBLIC_STATIC_BUILD === '1'

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
 * Fetch a CT-log endpoint.  In proxy mode, hops through `/api/ct-proxy`;
 * in static mode, fetches the log URL directly and converts network
 * failures into `CORSError`.
 *
 * The return shape mirrors what the server proxy used to send back:
 *   - `json`   for RFC 6962 `ct/v1/*`
 *   - `text`   for the RFC 9162 `checkpoint` signed note
 *   - `bytes`  for Sunlight binary tiles
 */
export async function ctFetch(
  logUrl: string,
  endpoint: string,
  params?: Record<string, string>,
): Promise<CTResponse> {
  const shape = endpointShape(endpoint)

  if (IS_STATIC_BUILD) {
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
      if (e instanceof TypeError) throw new CORSError(logUrl, endpoint, e)
      throw e
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`Log ${logUrl} returned ${res.status}: ${body.slice(0, 200)}`)
    }

    if (shape === 'json') return { json: await res.json() }
    if (shape === 'text') return { text: await res.text() }
    return { bytes: new Uint8Array(await res.arrayBuffer()) }
  }

  // ── Proxy mode ──────────────────────────────────────────────────────────
  const qs = params ? '&' + new URLSearchParams(params).toString() : ''
  const url = `/api/ct-proxy?logUrl=${encodeURIComponent(logUrl)}&endpoint=${encodeURIComponent(endpoint)}${qs}`

  const res = await fetch(url)
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`CT proxy ${res.status}: ${body.slice(0, 200)}`)
  }
  const data = (await res.json()) as { text?: string; bytes?: string; error?: string }
  if (data && typeof data === 'object' && 'error' in data && data.error) {
    throw new Error(String(data.error))
  }
  if (shape === 'json') return { json: data }
  if (shape === 'text') {
    if (typeof data.text !== 'string') throw new Error('Proxy returned no text')
    return { text: data.text }
  }
  if (typeof data.bytes !== 'string') throw new Error('Proxy returned no bytes')
  return { bytes: fromBase64(data.bytes) }
}
