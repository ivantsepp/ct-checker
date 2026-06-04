import { NextRequest, NextResponse } from 'next/server'
import { LOG_LIST_URL, normalizeLogList } from '@/lib/log-list'
import { withCors, preflight } from '@/lib/cors'

let cache: { data: unknown; ts: number } | null = null

export function OPTIONS(request: NextRequest) {
  return preflight(request)
}

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')

  if (cache && Date.now() - cache.ts < 3_600_000) {
    return withCors(NextResponse.json(cache.data), origin)
  }

  const res = await fetch(LOG_LIST_URL, { next: { revalidate: 3600 } })
  if (!res.ok) {
    return withCors(
      NextResponse.json({ error: `Log list fetch failed: ${res.status}` }, { status: 502 }),
      origin,
    )
  }

  const raw = await res.json()
  const data = { logs: normalizeLogList(raw) }
  cache = { data, ts: Date.now() }
  return withCors(NextResponse.json(data), origin)
}
