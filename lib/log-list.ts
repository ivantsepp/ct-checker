import type { CTLog, ParsedSCT, SCT } from '@/types/ct'
import { toHex, fromBase64 } from './sct-parser'

let cachedLogs: CTLog[] | null = null
let cacheTime = 0
const CACHE_TTL = 3_600_000

export async function getLogList(): Promise<CTLog[]> {
  if (cachedLogs && Date.now() - cacheTime < CACHE_TTL) return cachedLogs

  const res = await fetch('/api/log-list')
  if (!res.ok) throw new Error('Failed to fetch log list')

  const data = await res.json()
  cachedLogs = data.logs as CTLog[]
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
    timestampDate: new Date(Number(sct.timestamp)),
  }
}

export { fromBase64 }
