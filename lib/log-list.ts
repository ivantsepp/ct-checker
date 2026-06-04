import type { CTLog, ParsedSCT, SCT } from '@/types/ct'
import { toHex, toBase64, fromBase64, parseSCTExtensions } from './sct-parser'
import { HAS_PROXY, CORSError, apiUrl } from './transport'

let cachedLogs: CTLog[] | null = null
let cacheTime = 0
const CACHE_TTL = 3_600_000

export const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'

// ── Shared shape of the raw v3 log list ──────────────────────────────────────

interface RawLogListV3 {
  operators: Array<{
    name: string
    logs?: Array<{
      description: string
      log_id: string
      key: string
      url: string
      state?: Record<string, { timestamp: string }>
      temporal_interval?: { start_inclusive: string; end_exclusive: string }
    }>
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

function normalizeUrl(u: string): string {
  return u.endsWith('/') ? u : u + '/'
}

function normalizeInterval(
  iv?: { start_inclusive: string; end_exclusive: string },
): { startInclusive: string; endExclusive: string } | undefined {
  return iv
    ? { startInclusive: iv.start_inclusive, endExclusive: iv.end_exclusive }
    : undefined
}

/**
 * Normalize the raw Chrome v3 log list into our internal `CTLog[]` shape.
 * Used both by the server-side `/api/log-list` route and by the static-mode
 * client which fetches gstatic.com directly.
 */
export function normalizeLogList(raw: RawLogListV3): CTLog[] {
  return raw.operators.flatMap((op) => {
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
      // (checkpoint, tiles, and backward-compat ct/v1/ endpoints).
      url: normalizeUrl(log.monitoring_url),
      // Preserve submission_url for display purposes.
      submissionUrl: normalizeUrl(log.submission_url),
      state: log.state ?? {},
      temporalInterval: normalizeInterval(log.temporal_interval),
      operator: op.name,
      logType: 'tiled' as const,
    }))

    return [...rfc6962, ...tiled]
  })
}

export async function getLogList(): Promise<CTLog[]> {
  if (cachedLogs && Date.now() - cacheTime < CACHE_TTL) return cachedLogs

  let logs: CTLog[]

  if (!HAS_PROXY) {
    // No server proxy — fetch directly from gstatic. gstatic serves CORS
    // headers, so this works from any origin.
    let res: Response
    try {
      res = await fetch(LOG_LIST_URL)
    } catch (e) {
      if (e instanceof TypeError) throw new CORSError(LOG_LIST_URL, '', e)
      throw e
    }
    if (!res.ok) throw new Error(`Log list fetch failed: ${res.status}`)
    const raw = (await res.json()) as RawLogListV3
    logs = normalizeLogList(raw)
  } else {
    const res = await fetch(apiUrl('/api/log-list'))
    if (!res.ok) throw new Error('Failed to fetch log list')
    const data = (await res.json()) as { logs: CTLog[] }
    logs = data.logs
  }

  cachedLogs = logs
  cacheTime = Date.now()
  return cachedLogs
}

export function findLogById(logId: Uint8Array, logs: CTLog[]): CTLog | null {
  const needle = btoa(String.fromCharCode(...logId))
  return logs.find((l) => l.logId === needle) ?? null
}

export function logState(log: CTLog): string {
  if ('usable' in log.state) return 'usable'
  if ('qualified' in log.state) return 'qualified'
  if ('readonly' in log.state) return 'read-only'
  if ('retired' in log.state) return 'retired'
  if ('pending' in log.state) return 'pending'
  if ('rejected' in log.state) return 'rejected'
  return 'unknown'
}

export function enrichSCT(sct: SCT, logs: CTLog[]): ParsedSCT {
  const log = findLogById(sct.logId, logs)
  return {
    ...sct,
    log,
    logIdHex: toHex(sct.logId),
    logIdBase64: toBase64(sct.logId),
    timestampDate: new Date(Number(sct.timestamp)),
    parsedExtensions: parseSCTExtensions(sct.extensions),
  }
}

export { fromBase64 }
