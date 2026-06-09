#!/usr/bin/env node
/**
 * Regenerate the OPERATOR_CORS verdict table in lib/cors-operators.ts.
 *
 *   node update-cors-operators.mjs
 *
 * For each operator in the Chrome v3 CT log list, this probes a usable log's
 * read endpoints with an `Origin` header and inspects each response's
 * `Access-Control-Allow-Origin`.  CORS can differ PER ENDPOINT on the same log
 * (e.g. DigiCert serves CORS on `ct/v1/get-sth` but NOT on `ct/v1/get-entries`),
 * so we test the endpoints the feed actually depends on to read entries and
 * require ALL of them to serve CORS:
 *
 *   - RFC 6962 logs:  `ct/v1/get-sth` AND `ct/v1/get-entries`
 *   - Sunlight logs:  `checkpoint`   AND `tile/data/000`
 *
 * CORS support is otherwise an operator-infrastructure property, so one verdict
 * is recorded per operator:
 *
 *   - "ok"      → at least one of the operator's logs serves CORS on ALL its
 *                 required read endpoints, so a browser can run the feed on it.
 *   - "blocked" → logs responded but none served CORS on every endpoint.
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

/** Fetch one endpoint with an Origin header; true if it serves a usable ACAO. */
async function servesCors(url) {
  const res = await fetch(url, {
    headers: { Origin: ORIGIN, 'User-Agent': 'ct-checker-cors-probe/1.0 (ivan.tse1@gmail.com)' },
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  })
  const acao = res.headers.get('access-control-allow-origin')
  return acao === '*' || acao === ORIGIN
}

/**
 * Probe a single log across all the endpoints the feed needs.
 *   'ok'          → every endpoint responded with a usable ACAO
 *   'blocked'     → some endpoint responded without CORS
 *   'unreachable' → an endpoint errored, so we can't confirm full support
 */
async function probeLog(endpoints) {
  let responded = false
  for (const url of endpoints) {
    let cors
    try {
      cors = await servesCors(url)
    } catch {
      return 'unreachable'
    }
    responded = true
    if (!cors) return 'blocked' // CORS missing on a required endpoint
  }
  return responded ? 'ok' : 'unreachable'
}

/** Probe an operator's logs until one is fully CORS-ok, else 'blocked' / undefined. */
async function probeOperator(name, logs) {
  let anyResponded = false
  for (const endpoints of logs.slice(0, MAX_PROBES_PER_OPERATOR)) {
    const result = await probeLog(endpoints)
    if (result === 'ok') return 'ok'
    if (result === 'blocked') anyResponded = true
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

  // operator name → list of logs, each a list of the read endpoints the feed
  // depends on (all must serve CORS for the log to be usable in the browser).
  const logsByOperator = new Map()
  const addLog = (op, endpoints) => {
    if (!logsByOperator.has(op)) logsByOperator.set(op, [])
    logsByOperator.get(op).push(endpoints)
  }
  for (const op of list.operators) {
    for (const log of op.logs ?? []) {
      if (!isUsable(log)) continue
      const base = trailingSlash(log.url)
      addLog(op.name, [base + 'ct/v1/get-sth', base + 'ct/v1/get-entries?start=0&end=0'])
    }
    for (const log of op.tiled_logs ?? []) {
      if (!isUsable(log)) continue
      const base = trailingSlash(log.monitoring_url)
      addLog(op.name, [base + 'checkpoint', base + 'tile/data/000'])
    }
  }

  console.log(`Probing ${logsByOperator.size} operators (origin: ${ORIGIN})…\n`)
  const verdicts = {}
  await Promise.all(
    [...logsByOperator].map(async ([name, logs]) => {
      const verdict = await probeOperator(name, logs)
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
