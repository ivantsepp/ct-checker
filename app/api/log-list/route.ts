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
      // RFC 6962 logs
      logs?: Array<{
        description: string
        log_id: string
        key: string
        url: string
        state?: Record<string, { timestamp: string }>
        temporal_interval?: { start_inclusive: string; end_exclusive: string }
      }>
      // Static CT API / Sunlight tiled logs (RFC 9162)
      tiled_logs?: Array<{
        description: string
        log_id: string
        key: string
        /** URL used by CAs for certificate submission — not used for verification. */
        submission_url: string
        /** URL used for monitoring: checkpoint, tiles, and compat ct/v1/ endpoints. */
        monitoring_url: string
        state?: Record<string, { timestamp: string }>
        temporal_interval?: { start_inclusive: string; end_exclusive: string }
      }>
    }>
  }

  function normalizeUrl(u: string) {
    return u.endsWith('/') ? u : u + '/'
  }

  function normalizeInterval(iv?: { start_inclusive: string; end_exclusive: string }) {
    return iv
      ? { startInclusive: iv.start_inclusive, endExclusive: iv.end_exclusive }
      : undefined
  }

  const logs = raw.operators.flatMap((op) => {
    const rfc6962 = (op.logs ?? []).map((log) => ({
      description: log.description,
      logId: log.log_id,
      key: log.key,
      url: normalizeUrl(log.url),
      state: log.state ?? {},
      temporalInterval: normalizeInterval(log.temporal_interval),
      operator: op.name,
      logType: 'rfc6962' as const,
    }))

    const tiled = (op.tiled_logs ?? []).map((log) => ({
      description: log.description,
      logId: log.log_id,
      key: log.key,
      // Use monitoring_url as the canonical URL for verification
      // (checkpoint, tiles, and backward-compat ct/v1/ endpoints)
      url: normalizeUrl(log.monitoring_url),
      // Preserve submission_url for display purposes
      submissionUrl: normalizeUrl(log.submission_url),
      state: log.state ?? {},
      temporalInterval: normalizeInterval(log.temporal_interval),
      operator: op.name,
      logType: 'tiled' as const,
    }))

    return [...rfc6962, ...tiled]
  })

  const data = { logs }
  cache = { data, ts: Date.now() }
  return NextResponse.json(data)
}
