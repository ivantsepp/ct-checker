import { NextResponse } from 'next/server'
import { LOG_LIST_URL, normalizeLogList } from '@/lib/log-list'

let cache: { data: unknown; ts: number } | null = null

export async function GET() {
  if (cache && Date.now() - cache.ts < 3_600_000) {
    return NextResponse.json(cache.data)
  }

  const res = await fetch(LOG_LIST_URL, { next: { revalidate: 3600 } })
  if (!res.ok) {
    return NextResponse.json({ error: `Log list fetch failed: ${res.status}` }, { status: 502 })
  }

  const raw = await res.json()
  const data = { logs: normalizeLogList(raw) }
  cache = { data, ts: Date.now() }
  return NextResponse.json(data)
}
