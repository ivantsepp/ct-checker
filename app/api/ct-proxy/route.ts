import { NextRequest, NextResponse } from 'next/server'

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
 * - `tile/…`       → Sunlight hash or data tile (binary) → encode as { bytes: base64 }
 * - anything else  → RFC 6962 JSON
 */
function endpointResponseType(path: string): 'text' | 'binary' | 'json' {
  if (path === 'checkpoint') return 'text'
  if (path.startsWith('tile/')) return 'binary'
  return 'json'
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams
  const logUrl = params.get('logUrl')
  const endpoint = params.get('endpoint')

  if (!logUrl || !endpoint) {
    return NextResponse.json({ error: 'logUrl and endpoint required' }, { status: 400 })
  }

  // Validate the log URL is a known CT log (prevents open redirect)
  try {
    const known = await getKnownLogUrls()
    const norm = logUrl.replace(/\/$/, '')
    if (!known.has(norm)) {
      return NextResponse.json({ error: 'Unknown CT log URL' }, { status: 403 })
    }
  } catch {
    return NextResponse.json({ error: 'Could not validate log URL' }, { status: 500 })
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
      signal: AbortSignal.timeout(15_000),
    })

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      return NextResponse.json(
        { error: `Log returned ${res.status}: ${body}` },
        { status: res.status },
      )
    }

    // ── RFC 9162 checkpoint (plain-text signed note) ───────────────────────
    if (responseType === 'text') {
      const text = await res.text()
      return NextResponse.json({ text })
    }

    // ── Sunlight hash/data tile (binary octet-stream) ─────────────────────
    if (responseType === 'binary') {
      const buffer = await res.arrayBuffer()
      const bytes = Buffer.from(buffer).toString('base64')
      return NextResponse.json({ bytes })
    }

    // ── RFC 6962 JSON endpoint ─────────────────────────────────────────────
    try {
      return NextResponse.json(await res.json())
    } catch {
      const text = await res.text().catch(() => '(unreadable)')
      return NextResponse.json(
        { error: `Non-JSON response from log: ${text.slice(0, 200)}` },
        { status: 502 },
      )
    }
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 })
  }
}
