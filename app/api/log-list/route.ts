import { NextResponse } from 'next/server'

const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
let cache: { data: unknown; ts: number } | null = null

export async function GET() {
  if (cache && Date.now() - cache.ts < 3_600_000) {
    return NextResponse.json(cache.data)
  }

  const res = await fetch(LOG_LIST_URL, { next: { revalidate: 3600 } })
  if (!res.ok) {
    return NextResponse.json({ error: `Log list fetch failed: ${res.status}` }, { status: 502 })
  }

  const raw = (await res.json()) as {
    operators: Array<{
      name: string
      logs: Array<{
        description: string
        log_id: string
        key: string
        url: string
        state?: Record<string, { timestamp: string }>
        temporal_interval?: { start_inclusive: string; end_exclusive: string }
      }>
    }>
  }

  const logs = raw.operators.flatMap((op) =>
    (op.logs ?? []).map((log) => ({
      description: log.description,
      logId: log.log_id,
      key: log.key,
      url: log.url.endsWith('/') ? log.url : log.url + '/',
      state: log.state ?? {},
      temporalInterval: log.temporal_interval
        ? { startInclusive: log.temporal_interval.start_inclusive, endExclusive: log.temporal_interval.end_exclusive }
        : undefined,
      operator: op.name,
    })),
  )

  const data = { logs }
  cache = { data, ts: Date.now() }
  return NextResponse.json(data)
}
