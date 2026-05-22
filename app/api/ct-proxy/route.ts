import { NextRequest, NextResponse } from 'next/server'

const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
let knownLogUrls: Set<string> | null = null
let knownUrlsFetched = 0

async function getKnownLogUrls(): Promise<Set<string>> {
  if (knownLogUrls && Date.now() - knownUrlsFetched < 3_600_000) return knownLogUrls

  const res = await fetch(LOG_LIST_URL)
  const raw = (await res.json()) as {
    operators: Array<{ logs: Array<{ url: string }> }>
  }

  knownLogUrls = new Set(
    raw.operators
      .flatMap((op) => op.logs ?? [])
      .map((l) => l.url.replace(/\/$/, '')),
  )
  knownUrlsFetched = Date.now()
  return knownLogUrls
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

  // Build the target URL forwarding only non-routing params
  const forward = new URLSearchParams()
  for (const [k, v] of params) {
    if (k !== 'logUrl' && k !== 'endpoint') forward.set(k, v)
  }

  const base = logUrl.replace(/\/$/, '')
  const path = endpoint.replace(/^\//, '')
  const qs = forward.toString()
  const target = `${base}/${path}${qs ? '?' + qs : ''}`

  try {
    const res = await fetch(target, {
      headers: { 'User-Agent': 'CTVerifier/1.0', Accept: 'application/json' },
      signal: AbortSignal.timeout(15_000),
    })

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      return NextResponse.json({ error: `Log returned ${res.status}: ${body}` }, { status: res.status })
    }

    return NextResponse.json(await res.json())
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 })
  }
}
