/**
 * Live CT feed: poll monitored logs for newly appended entries.
 *
 * This is the "watch certificates enter the logs" counterpart to the verifier.
 * It reuses the same transport (`ctFetch` → `/api/ct-proxy`, with the static
 * build's direct-fetch fallback) and the same protocol split as the verifier:
 * RFC 6962 logs serve `ct/v1/get-entries`; Sunlight / RFC 9162 (tiled) logs
 * serve binary data tiles.  Per CLAUDE.md, the protocol is known up front from
 * `log.logType` — there is no runtime probing.
 *
 * `streamLog` runs one self-contained loop per log: it seeds near the tree head,
 * drains forward to the head (paginating by the server's per-response cap), then
 * waits `pollInterval` before re-checking the head.  The signed tree head is
 * fetched ONLY when the cursor has caught up to the last-known size — while a
 * backlog remains we keep pulling entries without a redundant STH round-trip.
 * If the log grows faster than we can drain (`treeSize - cursor > maxLag`), the
 * cursor jumps to the head and the skipped count is reported, keeping the feed
 * pinned to the live edge instead of falling ever further behind.
 */

import type { CTLog } from '@/types/ct'
import { fromBase64 } from './sct-parser'
import { getSTH } from './ct-api'
import { getSTHFromCheckpoint, dataTilePath } from './ct-static-api'
import { ctFetch, IS_STATIC_BUILD } from './transport'
import { parseLeafCertFields } from './feed-cert'
import { getOperatorCors } from './cors-operators'

// ── Tuning ──────────────────────────────────────────────────────────────────

/**
 * RFC 6962 entries requested per `get-entries` call.  Logs cap how many they
 * actually return (Google ≈ 32, others higher), so we request a wide window and
 * advance the cursor by however many come back — extracting full throughput on
 * high-cap logs while degrading gracefully on Google's.
 */
const REQUEST_WINDOW = 256
/** Data-tile width (Sunlight): one tile = up to 256 entries. */
const TILE_WIDTH = 256
/** Entries kept when seeding at, or jumping to, the tree head. */
const EDGE_WINDOW = 32
/** Drain at most this many entries behind the head before jumping to it. */
const DEFAULT_MAX_LAG = 256
/**
 * Wait between head checks once caught up (ms).  Static deployments fetch logs
 * directly from many browsers (or through a shared remote proxy), so they poll
 * slowly to avoid 429 rate-limiting; the same-origin dev/dynamic proxy can
 * afford a snappier cadence.
 */
const DEFAULT_POLL_INTERVAL = IS_STATIC_BUILD ? 30_000 : 5_000

// ── Types ─────────────────────────────────────────────────────────────────────

export interface FeedCert {
  /** Stable key for React lists: `${logName}:${index}`. */
  id: string
  logName: string
  /** Leaf index within the log. */
  index: number
  /** Entry timestamp (ms since epoch). */
  ts: number
  isPrecert: boolean
  domains: string[]
  subjectCN: string
  issuer: string
  notBefore: Date | null
  notAfter: Date | null
  /**
   * Full leaf certificate DER for x509 entries (carries the embedded SCTs, so
   * it can be re-verified).  Absent for precert entries, whose log payload is a
   * bare TBSCertificate with no SCT list.
   */
  certDER?: Uint8Array
  /**
   * Issuer certificate DER, when available (RFC 6962 `get-entries` returns the
   * chain in `extra_data`).  Passing it into the verifier lets the embedded-SCT
   * signature check reconstruct the precertificate without an AIA fetch.
   */
  issuerDER?: Uint8Array
}

export type FeedStatus = 'poll' | 'ok' | 'err'

export interface LogStreamOptions {
  /** New certificates decoded this step (oldest-first). */
  onCerts: (certs: FeedCert[]) => void
  /** Poll lifecycle, for status dots. */
  onStatus?: (status: FeedStatus) => void
  /** A poll failed — receives the thrown error (e.g. CORSError) for diagnosis. */
  onError?: (err: unknown) => void
  /** Entries skipped because the log outran us (flood guard). */
  onSkip?: (skipped: number) => void
  /** Loop idles (no fetches) while this returns true. */
  isPaused?: () => boolean
  /** Wait between head checks once caught up (ms). */
  pollInterval?: number
  /** Drain at most this many entries behind the head before jumping to it. */
  maxLag?: number
}

export interface LogStreamController {
  /** Stop the loop permanently. */
  stop: () => void
  /** Re-seed at the current tree head on the next poll (no skip reported). */
  reset: () => void
}

/** Result of fetching one batch from a log, given a known tree size. */
interface BatchResult {
  certs: FeedCert[]
  /** Cursor after consuming this batch. */
  cursor: number
}

// ── Binary helpers (big-endian) ────────────────────────────────────────────────

const u16 = (b: Uint8Array, p: number) => (b[p] << 8) | b[p + 1]
const u24 = (b: Uint8Array, p: number) => (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]

function u64ms(b: Uint8Array, p: number): number {
  // CT timestamps are ms since epoch — safely within Number range.
  const hi = (b[p] * 0x1000000 + b[p + 1] * 0x10000 + b[p + 2] * 0x100 + b[p + 3]) * 0x100000000
  const lo = b[p + 4] * 0x1000000 + b[p + 5] * 0x10000 + b[p + 6] * 0x100 + b[p + 7]
  return hi + lo
}

// ── RFC 6962 MerkleTreeLeaf parsing ────────────────────────────────────────────

interface RawLeaf {
  ts: number
  der: Uint8Array
  isPrecert: boolean
}

/** Parse a `leaf_input` (MerkleTreeLeaf) into timestamp + cert/TBS DER. */
function parseMerkleLeaf(b: Uint8Array): RawLeaf | null {
  if (b.length < 12) return null
  // b[0] = version(0), b[1] = leaf_type(0 = timestamped_entry)
  const ts = u64ms(b, 2)
  const entryType = u16(b, 10)
  let p = 12

  if (entryType === 0) {
    // x509_entry: uint24 cert_len + cert DER
    const len = u24(b, p)
    p += 3
    return { ts, der: b.subarray(p, p + len), isPrecert: false }
  }
  if (entryType === 1) {
    // precert_entry: issuer_key_hash(32) + uint24 tbs_len + TBSCertificate
    p += 32
    const len = u24(b, p)
    p += 3
    return { ts, der: b.subarray(p, p + len), isPrecert: true }
  }
  return null
}

// ── Sunlight data-tile parsing (feed variant) ──────────────────────────────────

/**
 * Parse a Static CT API data tile into timestamp + cert/TBS DER per entry.
 *
 * Mirrors `parseDataTile` in `ct-static-api.ts` but keeps the certificate bytes
 * (which the verifier's variant discards — it only needs the leaf-hash input).
 * TileLeaf framing: TimestampedEntry, then for precerts the original
 * pre-certificate, then a chain of SHA-256 fingerprints.
 */
function parseDataTileFeed(tile: Uint8Array, tileStart: number, logSize: number): Array<RawLeaf & { index: number }> {
  const out: Array<RawLeaf & { index: number }> = []
  let pos = 0
  let idx = tileStart

  while (pos < tile.length && idx < logSize) {
    if (pos + 10 > tile.length) break

    const ts = u64ms(tile, pos)
    pos += 8
    const etype = u16(tile, pos)
    pos += 2

    let der: Uint8Array
    let isPrecert: boolean
    if (etype === 0) {
      const clen = u24(tile, pos)
      pos += 3
      if (pos + clen > tile.length) break
      der = tile.subarray(pos, pos + clen)
      pos += clen
      isPrecert = false
    } else if (etype === 1) {
      pos += 32 // issuer_key_hash
      const tlen = u24(tile, pos)
      pos += 3
      if (pos + tlen > tile.length) break
      der = tile.subarray(pos, pos + tlen)
      pos += tlen
      isPrecert = true
    } else {
      break // unknown type — can't advance safely
    }

    // CtExtensions
    if (pos + 2 > tile.length) break
    const extLen = u16(tile, pos)
    pos += 2 + extLen

    // precert: skip the additional full pre-certificate
    if (etype === 1) {
      if (pos + 3 > tile.length) break
      const pcLen = u24(tile, pos)
      pos += 3 + pcLen
    }

    // chain fingerprints
    if (pos + 2 > tile.length) break
    const fpLen = u16(tile, pos)
    pos += 2 + fpLen

    out.push({ ts, der, isPrecert, index: idx })
    idx++
  }
  return out
}

// ── Cert → FeedCert ─────────────────────────────────────────────────────────

function toFeedCert(
  logName: string,
  index: number,
  leaf: RawLeaf,
  issuerDER?: Uint8Array,
): FeedCert | null {
  const fields = parseLeafCertFields(leaf.der, leaf.isPrecert)
  if (!fields) return null
  return {
    id: `${logName}:${index}`,
    logName,
    index,
    ts: leaf.ts,
    isPrecert: leaf.isPrecert,
    domains: fields.domains,
    subjectCN: fields.subjectCN,
    issuer: fields.issuer,
    notBefore: fields.notBefore,
    notAfter: fields.notAfter,
    // Only x509 entries carry the full (SCT-bearing) cert; keep its DER so the
    // row can deep-link into the verifier.  Copy out of the tile subarray.
    certDER: leaf.isPrecert ? undefined : leaf.der.slice(),
    issuerDER: leaf.isPrecert ? undefined : issuerDER,
  }
}

/**
 * Extract the first certificate (the leaf's issuer) from an RFC 6962
 * `get-entries` `extra_data` blob.  For an x509 entry this is a TLS
 * `ASN.1Cert certificate_chain<0..2^24-1>`: a uint24 total length followed by
 * `uint24 cert_len + cert_DER` entries, issuer first.  Returns null if absent.
 */
function issuerFromExtraData(extraData: Uint8Array): Uint8Array | undefined {
  if (extraData.length < 6) return undefined
  // Skip the outer uint24 chain length; read the first cert entry.
  let p = 3
  const certLen = u24(extraData, p)
  p += 3
  if (certLen <= 0 || p + certLen > extraData.length) return undefined
  return extraData.slice(p, p + certLen)
}

// ── Tree head ─────────────────────────────────────────────────────────────────

/** Current tree size, via the protocol the log speaks. */
async function fetchTreeSize(log: CTLog): Promise<number> {
  const sth = log.logType === 'tiled'
    ? await getSTHFromCheckpoint(log.url)
    : await getSTH(log.url)
  return sth.treeSize
}

// ── Batch fetch (one network step, given a known tree size) ─────────────────────

/**
 * Fetch one `get-entries` window from an RFC 6962 log starting at `cursor`.
 * Advances the cursor by however many entries the log actually returned (it may
 * cap below the requested window); returns the cursor unchanged on an empty
 * response so the caller can detect lack of progress and back off.
 */
async function fetchBatchRFC6962(
  log: CTLog,
  cursor: number,
  treeSize: number,
): Promise<BatchResult> {
  const end = Math.min(cursor + REQUEST_WINDOW - 1, treeSize - 1)
  const { json } = await ctFetch(log.url, 'ct/v1/get-entries', {
    start: String(cursor),
    end: String(end),
  })
  const entries =
    (json as { entries?: Array<{ leaf_input: string; extra_data?: string }> }).entries ?? []

  const certs: FeedCert[] = []
  let idx = cursor
  for (const entry of entries) {
    const leaf = parseMerkleLeaf(fromBase64(entry.leaf_input))
    if (leaf) {
      // For x509 entries the chain in extra_data starts with the issuer cert;
      // pass it through so the verifier can check the embedded SCT signature.
      const issuerDER =
        !leaf.isPrecert && entry.extra_data
          ? issuerFromExtraData(fromBase64(entry.extra_data))
          : undefined
      const fc = toFeedCert(log.description, idx, leaf, issuerDER)
      if (fc) certs.push(fc)
    }
    idx++
  }
  return { certs, cursor: entries.length > 0 ? cursor + entries.length : cursor }
}

/**
 * Fetch the data tile containing `cursor` from a Sunlight / tiled log and emit
 * the entries at or after `cursor`.  Advances to the next tile boundary (or the
 * head, for the last partial tile).
 */
async function fetchBatchTiled(
  log: CTLog,
  cursor: number,
  treeSize: number,
): Promise<BatchResult> {
  const tileIdx = Math.floor(cursor / TILE_WIDTH)
  const tileStart = tileIdx * TILE_WIDTH
  const entriesInTile = Math.min(TILE_WIDTH, treeSize - tileStart)
  const isPartial = entriesInTile < TILE_WIDTH

  let bytes: Uint8Array | undefined
  try {
    bytes = (await ctFetch(log.url, dataTilePath(tileIdx, isPartial ? entriesInTile : undefined)))
      .bytes
  } catch (e) {
    // Some logs serve partial tiles at the full-tile URL too — retry without .p
    if (!isPartial) throw e
    bytes = (await ctFetch(log.url, dataTilePath(tileIdx))).bytes
  }
  if (!bytes) return { certs: [], cursor }

  const raw = parseDataTileFeed(bytes, tileStart, treeSize)
  const certs: FeedCert[] = []
  for (const e of raw) {
    if (e.index < cursor || e.index >= treeSize) continue
    const fc = toFeedCert(log.description, e.index, e)
    if (fc) certs.push(fc)
  }
  return { certs, cursor: tileStart + entriesInTile }
}

function fetchBatch(log: CTLog, cursor: number, treeSize: number): Promise<BatchResult> {
  return log.logType === 'tiled'
    ? fetchBatchTiled(log, cursor, treeSize)
    : fetchBatchRFC6962(log, cursor, treeSize)
}

// ── Per-log stream loop ─────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/**
 * Run a self-contained polling loop for one log until `stop()` is called.
 * See the module header for the drain-to-head / flood-guard strategy.
 */
export function streamLog(log: CTLog, opts: LogStreamOptions): LogStreamController {
  const pollInterval = opts.pollInterval ?? DEFAULT_POLL_INTERVAL
  const maxLag = opts.maxLag ?? DEFAULT_MAX_LAG
  const isPaused = opts.isPaused ?? (() => false)

  let cancelled = false
  let reseed = false
  let cursor: number | null = null
  let knownTreeSize: number | undefined

  ;(async () => {
    while (!cancelled) {
      if (isPaused()) {
        await sleep(250)
        continue
      }
      if (reseed) {
        cursor = null
        knownTreeSize = undefined
        reseed = false
      }

      opts.onStatus?.('poll')
      try {
        // Fetch the signed tree head ONLY when we've drained the known backlog.
        if (cursor === null || knownTreeSize === undefined || cursor >= knownTreeSize) {
          knownTreeSize = await fetchTreeSize(log)
        }
        if (cancelled) return
        const treeSize = knownTreeSize

        // First poll: seed a small recent window rather than the whole log.
        if (cursor === null) cursor = Math.max(0, treeSize - EDGE_WINDOW)

        // Flood guard: too far behind the head → jump to it and report the gap.
        if (treeSize - cursor > maxLag) {
          const target = Math.max(0, treeSize - EDGE_WINDOW)
          if (target > cursor) {
            opts.onSkip?.(target - cursor)
            cursor = target
          }
        }

        const before = cursor
        if (cursor < treeSize) {
          const res = await fetchBatch(log, cursor, treeSize)
          if (cancelled) return
          cursor = res.cursor
          if (res.certs.length) opts.onCerts(res.certs)
        }
        opts.onStatus?.('ok')

        // Made progress and still behind → keep draining without re-checking the
        // head (no STH fetch, since cursor < knownTreeSize) and without waiting.
        if (cursor > before && cursor < knownTreeSize) continue
      } catch (err) {
        if (cancelled) return
        opts.onStatus?.('err')
        opts.onError?.(err)
      }
      await sleep(pollInterval)
    }
  })()

  return {
    stop() {
      cancelled = true
    },
    reset() {
      reseed = true
    },
  }
}

// ── Log selection ───────────────────────────────────────────────────────────

function isUsableNow(log: CTLog): boolean {
  if (!('usable' in log.state)) return false
  const iv = log.temporalInterval
  if (!iv) return true
  const now = Date.now()
  const start = Date.parse(iv.startInclusive)
  const end = Date.parse(iv.endExclusive)
  return (!Number.isFinite(start) || now >= start) && (!Number.isFinite(end) || now < end)
}

/** CORS preference: operators we've seen work first, unknown next, blocked last. */
function corsRank(log: CTLog): number {
  const status = getOperatorCors(log.operator)
  return status === 'ok' ? 0 : status === undefined ? 1 : 2
}

/**
 * All currently-usable logs, ordered by CORS preference then description — the
 * candidate list for the "add a log" picker.
 */
export function listUsableLogs(logs: CTLog[]): CTLog[] {
  return logs
    .filter(isUsableNow)
    .sort((a, b) => corsRank(a) - corsRank(b) || a.description.localeCompare(b.description))
}

/**
 * The default starting set: one RFC 6962 log and one Sunlight (tiled) log, each
 * the best CORS-ranked of its kind, so the feed demonstrates both protocols out
 * of the box.  Users add more via the picker.  Ordered RFC-first.
 */
export function selectFeedLogs(logs: CTLog[]): CTLog[] {
  const ranked = listUsableLogs(logs) // already CORS-ordered
  const rfc = ranked.find((l) => l.logType !== 'tiled')
  const tiled = ranked.find((l) => l.logType === 'tiled')
  return [rfc, tiled].filter((l): l is CTLog => l !== undefined)
}

// ── Verifier hand-off ─────────────────────────────────────────────────────────

/** Wrap DER bytes as a PEM CERTIFICATE block. */
export function derToPem(der: Uint8Array): string {
  let bin = ''
  for (const b of der) bin += String.fromCharCode(b)
  const b64 = btoa(bin)
  const lines = b64.match(/.{1,64}/g) ?? [b64]
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`
}

/** Build the `/verify?cert=…` href for an x509 feed entry (null for precerts). */
export function verifyHref(cert: FeedCert): string | null {
  if (!cert.certDER) return null
  // Include the issuer (when we have it) as a PEM chain so the verifier can
  // check the embedded SCT signature without an AIA round-trip.
  const pem = cert.issuerDER
    ? `${derToPem(cert.certDER)}\n${derToPem(cert.issuerDER)}`
    : derToPem(cert.certDER)
  return `/verify?cert=${encodeURIComponent(btoa(pem))}`
}
