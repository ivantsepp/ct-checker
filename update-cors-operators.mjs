#!/usr/bin/env node
/**
 * Regenerate the OPERATOR_CORS verdict table in lib/cors-operators.ts.
 *
 *   node update-cors-operators.mjs
 *
 * For each operator in the Chrome v3 CT log list, this probes a representative
 * usable log's read endpoint (RFC 6962 `ct/v1/get-sth` or Sunlight
 * `/checkpoint`) with an `Origin` header and inspects the response's
 * `Access-Control-Allow-Origin`.  CORS support is an operator-infrastructure
 * property, so one verdict is recorded per operator:
 *
 *   - "ok"      → at least one of the operator's logs returned a usable ACAO
 *                 (`*` or our origin), so a browser can read it directly.
 *   - "blocked" → logs responded but none sent a usable ACAO.
 *   - (omitted) → no log responded (network error / all unreachable) → unknown.
 *
 * Only the block between the `cors-operators:begin/end` markers is rewritten;
 * the rest of lib/cors-operators.ts (and its accessor) is left untouched.
 *
 * Run it from time to time as logs/operators come and go, and commit the diff.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
const ORIGIN = 'https://example.com'
const TIMEOUT_MS = 8000
const MAX_PROBES_PER_OPERATOR = 4

const HERE = dirname(fileURLToPath(import.meta.url))
const TARGET = join(HERE, 'lib', 'cors-operators.ts')

const trailingSlash = (u) => (u.endsWith('/') ? u : u + '/')

function isUsable(log) {
  if (!log.state || !('usable' in log.state)) return false
  const iv = log.temporal_interval
  if (!iv) return true
  const now = Date.now()
  const start = Date.parse(iv.start_inclusive)
  const end = Date.parse(iv.end_exclusive)
  return (!Number.isFinite(start) || now >= start) && (!Number.isFinite(end) || now < end)
}

/** Fetch a read endpoint with an Origin header; true if it serves a usable ACAO. */
async function servesCors(url) {
  const res = await fetch(url, {
    headers: { Origin: ORIGIN, 'User-Agent': 'ct-checker-cors-probe/1.0' },
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  })
  const acao = res.headers.get('access-control-allow-origin')
  return acao === '*' || acao === ORIGIN
}

/** Probe an operator's logs until one is CORS-ok, else 'blocked' / undefined. */
async function probeOperator(name, endpoints) {
  let anyResponded = false
  for (const url of endpoints.slice(0, MAX_PROBES_PER_OPERATOR)) {
    try {
      const ok = await servesCors(url)
      anyResponded = true
      if (ok) return 'ok'
    } catch {
      // network error / timeout — try the next log
    }
  }
  return anyResponded ? 'blocked' : undefined
}

function renderBlock(verdicts) {
  const entries = Object.keys(verdicts)
    .sort((a, b) => a.localeCompare(b))
    .map((op) => `  ${JSON.stringify(op)}: ${JSON.stringify(verdicts[op])},\n`)
    .join('')
  return `export const OPERATOR_CORS: Record<string, CorsStatus> = {\n${entries}}`
}

async function main() {
  console.log(`Fetching log list: ${LOG_LIST_URL}`)
  const res = await fetch(LOG_LIST_URL)
  if (!res.ok) throw new Error(`log list fetch failed: ${res.status}`)
  const list = await res.json()

  // operator name → list of read-endpoint URLs (one per usable log)
  const endpointsByOperator = new Map()
  const add = (op, url) => {
    if (!endpointsByOperator.has(op)) endpointsByOperator.set(op, [])
    endpointsByOperator.get(op).push(url)
  }
  for (const op of list.operators) {
    for (const log of op.logs ?? []) {
      if (isUsable(log)) add(op.name, trailingSlash(log.url) + 'ct/v1/get-sth')
    }
    for (const log of op.tiled_logs ?? []) {
      if (isUsable(log)) add(op.name, trailingSlash(log.monitoring_url) + 'checkpoint')
    }
  }

  console.log(`Probing ${endpointsByOperator.size} operators (origin: ${ORIGIN})…\n`)
  const verdicts = {}
  await Promise.all(
    [...endpointsByOperator].map(async ([name, endpoints]) => {
      const verdict = await probeOperator(name, endpoints)
      if (verdict) verdicts[name] = verdict
      const mark = verdict === 'ok' ? '✓ ok' : verdict === 'blocked' ? '✗ blocked' : '· unknown (skipped)'
      console.log(`  ${name.padEnd(20)} ${mark}`)
    }),
  )

  const src = readFileSync(TARGET, 'utf8')
  const re = /(\/\/ cors-operators:begin[^\n]*\n)[\s\S]*?(\n\/\/ cors-operators:end)/
  if (!re.test(src)) throw new Error(`markers not found in ${TARGET}`)
  const updated = src.replace(re, (_m, begin, end) => `${begin}${renderBlock(verdicts)}${end}`)
  writeFileSync(TARGET, updated)

  const ok = Object.values(verdicts).filter((v) => v === 'ok').length
  const blocked = Object.values(verdicts).filter((v) => v === 'blocked').length
  console.log(`\nWrote ${TARGET}: ${ok} ok, ${blocked} blocked, ${Object.keys(verdicts).length} total.`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
