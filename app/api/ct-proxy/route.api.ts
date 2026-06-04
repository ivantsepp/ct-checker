import { NextRequest, NextResponse } from 'next/server'
import { withCors, preflight } from '@/lib/cors'

const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
let knownLogUrls: Set<string> | null = null
let knownUrlsFetched = 0

async function getKnownLogUrls(): Promise<Set<string>> {
  if (knownLogUrls && Date.now() - knownUrlsFetched < 3_600_000) return knownLogUrls

  const res = await fetch(LOG_LIST_URL)
  const raw = (await res.json()) as {
    operators: Array<{
      logs?: Array<{ url: string }>
      tiled_logs?: Array<{ submission_url: string; monitoring_url: string }>
    }>
  }

  const urls: string[] = []
  for (const op of raw.operators) {
    // RFC 6962 logs
    for (const l of op.logs ?? []) {
      urls.push(l.url.replace(/\/$/, ''))
    }
    // Static CT API / Sunlight tiled logs — allow both the monitoring URL
    // (used for verification) and the submission URL (used by CAs)
    for (const l of op.tiled_logs ?? []) {
      urls.push(l.monitoring_url.replace(/\/$/, ''))
      urls.push(l.submission_url.replace(/\/$/, ''))
    }
  }

  knownLogUrls = new Set(urls)
  knownUrlsFetched = Date.now()
  return knownLogUrls
}

/**
 * Determine how to handle the response based on the endpoint path.
 *
 * - `checkpoint`   → RFC 9162 signed note (text/plain) → wrap in { text }
 * - `tile/...`       → Sunlight hash or data tile (binary) → encode as { bytes: base64 }
 * - anything else  → RFC 6962 JSON
 */
function endpointResponseType(path: string): 'text' | 'binary' | 'json' {
  if (path === 'checkpoint') return 'text'
  if (path.startsWith('tile/')) return 'binary'
  return 'json'
}

// CT responses are small (STHs, proofs, ≤256-entry tiles); cap the body we'll
// buffer so a hostile or misbehaving upstream can't OOM the function or
// amplify egress (base64 inflates by ~33%).
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024

/**
 * Read a response body into memory, aborting if it exceeds `max` bytes.
 * Streams and counts rather than trusting Content-Length (which a hostile
 * server can omit or lie about), but also rejects early when the declared
 * length is already over the limit.
 */
async function readBodyCapped(res: Response, max: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get('content-length') ?? '')
  if (Number.isFinite(declared) && declared > max) {
    throw new Error('upstream response too large')
  }
  const reader = res.body?.getReader()
  if (!reader) return new Uint8Array(0)
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (value) {
      total += value.length
      if (total > max) {
        await reader.cancel()
        throw new Error('upstream response too large')
      }
      chunks.push(value)
    }
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) { out.set(c, offset); offset += c.length }
  return out
}

export function OPTIONS(request: NextRequest) {
  return preflight(request)
}

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')
  // CORS-wrapped JSON response shorthand.
  const json = (body: unknown, init?: ResponseInit) =>
    withCors(NextResponse.json(body, init), origin)

  const params = request.nextUrl.searchParams
  const logUrl = params.get('logUrl')
  const endpoint = params.get('endpoint')

  if (!logUrl || !endpoint) {
    return json({ error: 'logUrl and endpoint required' }, { status: 400 })
  }

  // Validate the log URL is a known CT log (prevents open redirect)
  try {
    const known = await getKnownLogUrls()
    const norm = logUrl.replace(/\/$/, '')
    if (!known.has(norm)) {
      return json({ error: 'Unknown CT log URL' }, { status: 403 })
    }
  } catch {
    return json({ error: 'Could not validate log URL' }, { status: 500 })
  }

  // Build the target URL, forwarding only non-routing query params
  const forward = new URLSearchParams()
  for (const [k, v] of params) {
    if (k !== 'logUrl' && k !== 'endpoint') forward.set(k, v)
  }

  const base = logUrl.replace(/\/$/, '')
  const path = endpoint.replace(/^\//, '')
  const qs = forward.toString()
  const target = `${base}/${path}${qs ? '?' + qs : ''}`

  const responseType = endpointResponseType(path)

  try {
    const res = await fetch(target, {
      headers: {
        'User-Agent': 'CTVerifier/1.0',
        // For JSON endpoints request JSON explicitly; for others accept anything
        Accept: responseType === 'json' ? 'application/json' : '*/*',
      },
      // Don't follow redirects: a compromised/misbehaving (but allowlisted) log
      // could 302 us to an internal address (e.g. cloud metadata) → SSRF. CT
      // logs don't legitimately redirect these endpoints, so treat 3xx as error.
      redirect: 'manual',
      signal: AbortSignal.timeout(15_000),
    })

    if (!res.ok) {
      // Cap the error body too — a hostile upstream could stuff megabytes into
      // a 4xx/5xx response. 64 KiB is plenty for a diagnostic snippet.
      const body = await readBodyCapped(res, 64 * 1024)
        .then((b) => new TextDecoder().decode(b))
        .catch(() => '')
      return json(
        { error: `Log returned ${res.status}: ${body.slice(0, 200)}` },
        { status: res.status },
      )
    }

    let raw: Uint8Array
    try {
      raw = await readBodyCapped(res, MAX_RESPONSE_BYTES)
    } catch {
      return json({ error: 'Upstream response too large' }, { status: 502 })
    }

    // ── RFC 9162 checkpoint (plain-text signed note) ───────────────────────
    if (responseType === 'text') {
      return json({ text: new TextDecoder().decode(raw) })
    }

    // ── Sunlight hash/data tile (binary octet-stream) ─────────────────────
    if (responseType === 'binary') {
      return json({ bytes: Buffer.from(raw).toString('base64') })
    }

    // ── RFC 6962 JSON endpoint ─────────────────────────────────────────────
    const text = new TextDecoder().decode(raw)
    try {
      return json(JSON.parse(text))
    } catch {
      return json(
        { error: `Non-JSON response from log: ${text.slice(0, 200)}` },
        { status: 502 },
      )
    }
  } catch (e) {
    // Don't leak internal error detail (resolved IPs, hostnames) to callers.
    // `code` lets the client tell "the log is unreachable" (e.g. a retired log
    // whose server is gone) apart from a proxy outage — the proxy is fine here.
    console.error('ct-proxy: upstream fetch failed:', e)
    return json({ error: 'Upstream fetch failed', code: 'UPSTREAM_UNREACHABLE' }, { status: 502 })
  }
}
