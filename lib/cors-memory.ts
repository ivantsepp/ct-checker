/**
 * Per-operator CORS memory for the live feed (static / frontend-only builds).
 *
 * In a static build the browser fetches CT logs directly, and many logs don't
 * serve `Access-Control-Allow-Origin` — those fail with a CORSError.  CORS
 * support is a property of the operator's serving infrastructure, not the
 * individual log, so if one Cloudflare log is blocked we assume all of theirs
 * are (and vice-versa for a log that works).  We remember the verdict per
 * operator in localStorage so a reload starts by prioritizing the operators
 * we've already seen work, instead of re-discovering the same failures.
 *
 * This is advisory only: it just orders the default log selection. A log that
 * later starts/stops serving CORS will be re-recorded on its next poll.
 */

export type CorsStatus = 'ok' | 'blocked'

const STORAGE_KEY = 'ct-feed:operator-cors'

let cache: Record<string, CorsStatus> | null = null

function load(): Record<string, CorsStatus> {
  if (cache) return cache
  cache = {}
  if (typeof window === 'undefined') return cache
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (raw) cache = JSON.parse(raw) as Record<string, CorsStatus>
  } catch {
    // ignore malformed / unavailable storage
  }
  return cache
}

/** Known CORS verdict for an operator, or undefined if we haven't seen one. */
export function getOperatorCors(operator?: string): CorsStatus | undefined {
  if (!operator) return undefined
  return load()[operator]
}

/** Record (and persist) an operator's CORS verdict. No-op if unchanged. */
export function recordOperatorCors(operator: string | undefined, status: CorsStatus): void {
  if (!operator) return
  const mem = load()
  if (mem[operator] === status) return
  mem[operator] = status
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(mem))
  } catch {
    // ignore quota / private-mode failures
  }
}
