import type { CTLog, ParsedSCT, SCT } from '@/types/ct'
import { toHex, toBase64, fromBase64, parseSCTExtensions } from './sct-parser'
import { HAS_PROXY, IS_STATIC_BUILD, CORSError, apiUrl } from './transport'

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
 * CT logs we trust that are NOT in the Chrome v3 log list.
 *
 * Chrome's list only covers logs in scope for its TLS-server-cert CT policy.
 * BIMI / VMC (Verified Mark Certificate) SCTs are logged to a separate set of
 * CT logs operated by the Mark Verifying Authorities. The canonical list is
 * published by the AuthIndicators Working Group via crt.sh:
 *   https://github.com/crtsh/ctloglists — files/bimi/v3/approved_logs_list.json
 *
 * As of mid-2026 the only BIMI log operator is DigiCert ("Gorgon"). Pinning the
 * key here lets gorgon SCT signatures verify and inclusion proofs resolve just
 * like any Chrome-listed RFC 6962 log. (Independently confirmed: this key's
 * SHA-256 matches the log_id, and it is one of the two ECDSA candidates
 * recovered from the live /ct/v1/get-sth signature.)
 */
export const EXTRA_LOGS: CTLog[] = [
  {
    description: 'DigiCert Gorgon',
    logId: 'VVlTrjCWAIBs0utSCKbJnpMYKKwQVrRCHFU2FUxfdaw=',
    key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbEiWluJDIqWi8JbeCSfR3V2k/a5s9XtZv+HU5u/gU9NSYnWGwEoEW6IK7n6LehfrJL3znCUAC0ayEaeiFQuibA==',
    url: 'https://gorgon.ct.digicert.com/log/',
    state: { usable: { timestamp: '2021-07-09T00:00:00Z' } },
    operator: 'DigiCert',
    logType: 'rfc6962',
  },
]

/**
 * Normalize the raw Chrome v3 log list into our internal `CTLog[]` shape.
 * Used both by the server-side `/api/log-list` route and by the static-mode
 * client which fetches gstatic.com directly.
 */
export function normalizeLogList(raw: RawLogListV3): CTLog[] {
  const fromChrome = raw.operators.flatMap((op) => {
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

  // Append trusted non-Chrome logs (e.g. BIMI/VMC), skipping any that Chrome
  // happens to also list so a future migration doesn't create duplicates.
  const seen = new Set(fromChrome.map((l) => l.logId))
  return [...fromChrome, ...EXTRA_LOGS.filter((l) => !seen.has(l.logId))]
}

export async function getLogList(): Promise<CTLog[]> {
  if (cachedLogs && Date.now() - cacheTime < CACHE_TTL) return cachedLogs

  let logs: CTLog[]

  // gstatic serves CORS headers, so in the browser we fetch the log list
  // directly from it; only fall back to the proxy if that's somehow blocked.
  const fetchDirect = async (): Promise<CTLog[]> => {
    let res: Response
    try {
      res = await fetch(LOG_LIST_URL)
    } catch (e) {
      if (e instanceof TypeError) throw new CORSError(LOG_LIST_URL, '', e)
      throw e
    }
    if (!res.ok) throw new Error(`Log list fetch failed: ${res.status}`)
    return normalizeLogList((await res.json()) as RawLogListV3)
  }
  const fetchViaProxy = async (): Promise<CTLog[]> => {
    const res = await fetch(apiUrl('/api/log-list'))
    if (!res.ok) throw new Error('Failed to fetch log list')
    return ((await res.json()) as { logs: CTLog[] }).logs
  }

  if (!IS_STATIC_BUILD) {
    // Dynamic build: proxy is same-origin and free.
    logs = await fetchViaProxy()
  } else if (!HAS_PROXY) {
    // Static build, no proxy: direct is the only option.
    logs = await fetchDirect()
  } else {
    // Static build with a remote proxy: prefer direct, fall back on CORS.
    try {
      logs = await fetchDirect()
    } catch (e) {
      if (!(e instanceof CORSError)) throw e
      logs = await fetchViaProxy()
    }
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
