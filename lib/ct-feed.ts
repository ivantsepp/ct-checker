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
 * Each `pollOnce` advances a per-log cursor by one batch and returns the certs
 * it decoded; the UI owns the loop, cursors, pause and per-log enable state.
 */

import type { CTLog } from '@/types/ct'
import { fromBase64 } from './sct-parser'
import { getSTH } from './ct-api'
import { getSTHFromCheckpoint, dataTilePath } from './ct-static-api'
import { ctFetch } from './transport'
import { parseLeafCertFields } from './feed-cert'

// ── Tuning ──────────────────────────────────────────────────────────────────

/** RFC 6962 entries fetched per poll. */
export const RFC6962_BATCH = 32
/** Data-tile width (Sunlight): one tile = up to 256 entries. */
const TILE_WIDTH = 256

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

export interface PollResult {
  certs: FeedCert[]
  /** Next cursor (leaf index to resume from). */
  cursor: number
  /** Current tree size reported by the log's STH / checkpoint. */
  treeSize: number
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

// ── Polling ───────────────────────────────────────────────────────────────────

/**
 * Fetch one batch of new entries from an RFC 6962 log.
 * `cursor === null` starts near the current tree head.
 */
async function pollRFC6962(log: CTLog, cursor: number | null): Promise<PollResult> {
  const sth = await getSTH(log.url)
  const treeSize = sth.treeSize
  let start = cursor === null ? Math.max(0, treeSize - RFC6962_BATCH) : cursor
  if (start >= treeSize) return { certs: [], cursor: start, treeSize }

  const end = Math.min(start + RFC6962_BATCH - 1, treeSize - 1)
  const { json } = await ctFetch(log.url, 'ct/v1/get-entries', {
    start: String(start),
    end: String(end),
  })
  const entries =
    (json as { entries?: Array<{ leaf_input: string; extra_data?: string }> }).entries ?? []

  const certs: FeedCert[] = []
  for (const entry of entries) {
    const leaf = parseMerkleLeaf(fromBase64(entry.leaf_input))
    if (leaf) {
      // For x509 entries the chain in extra_data starts with the issuer cert;
      // pass it through so the verifier can check the embedded SCT signature.
      const issuerDER =
        !leaf.isPrecert && entry.extra_data
          ? issuerFromExtraData(fromBase64(entry.extra_data))
          : undefined
      const fc = toFeedCert(log.description, start, leaf, issuerDER)
      if (fc) certs.push(fc)
    }
    start++
  }
  return { certs, cursor: start, treeSize }
}

/**
 * Fetch one tile of new entries from a Sunlight / tiled log.
 * `cursor === null` starts near the current tree head.
 */
async function pollTiled(log: CTLog, cursor: number | null): Promise<PollResult> {
  const sth = await getSTHFromCheckpoint(log.url)
  const treeSize = sth.treeSize
  const start = cursor === null ? Math.max(0, treeSize - 16) : cursor
  if (start >= treeSize) return { certs: [], cursor: start, treeSize }

  const tileIdx = Math.floor(start / TILE_WIDTH)
  const tileStart = tileIdx * TILE_WIDTH
  const entriesInTile = Math.min(TILE_WIDTH, treeSize - tileStart)
  const isPartial = entriesInTile < TILE_WIDTH
  const path = dataTilePath(tileIdx, isPartial ? entriesInTile : undefined)

  const { bytes } = await ctFetch(log.url, path)
  if (!bytes) return { certs: [], cursor: start, treeSize }

  const raw = parseDataTileFeed(bytes, tileStart, treeSize)
  const certs: FeedCert[] = []
  for (const e of raw) {
    if (e.index < start || e.index >= treeSize) continue
    const fc = toFeedCert(log.description, e.index, e)
    if (fc) certs.push(fc)
  }
  // Advance to the next unseen entry (next tile if we consumed this one).
  const next = certs.length ? certs[certs.length - 1].index + 1 : tileStart + entriesInTile
  return { certs, cursor: Math.max(start, next), treeSize }
}

/** Poll one batch from a log, dispatching on its declared protocol. */
export function pollOnce(log: CTLog, cursor: number | null): Promise<PollResult> {
  return log.logType === 'tiled' ? pollTiled(log, cursor) : pollRFC6962(log, cursor)
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

/**
 * Choose a manageable set of currently-usable logs to monitor.  Prefers RFC
 * 6962 logs first (Google's serve CORS, so they also work in the static build)
 * and includes a couple of tiled logs for protocol variety, capped so the feed
 * isn't hammering dozens of endpoints.
 */
export function selectFeedLogs(logs: CTLog[], max = 6): CTLog[] {
  const usable = logs.filter(isUsableNow)
  const rfc = usable.filter((l) => l.logType !== 'tiled')
  const tiled = usable.filter((l) => l.logType === 'tiled')
  const tiledQuota = Math.min(2, tiled.length)
  return [...rfc.slice(0, max - tiledQuota), ...tiled.slice(0, tiledQuota)]
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
