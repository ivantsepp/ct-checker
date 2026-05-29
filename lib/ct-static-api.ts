/**
 * RFC 9162 (Static CT / Sunlight / Tiled) log support.
 *
 * Sunlight tile structure (TileHeight=8, TileWidth=256):
 *   - Tile level 0: 256 leaf hashes (binary Merkle tree level 0)
 *   - Tile level 1: 256 roots of 256-leaf subtrees (binary tree level 8)
 *   - Tile level L: 256 roots of (256^L)-leaf subtrees (binary tree level L*8)
 *
 * To get a hash at any binary tree level, we fetch the right tile and
 * reconstruct intermediate levels with local SHA-256 computations.
 *
 * Signed-note checkpoint format (RFC 9162 §3.1 / C2SP sunlight.md):
 *   <log origin>           ← first line (log identifier / URL)
 *   <decimal tree size>
 *   <standard-base64 root hash>
 *   [Timestamp: <ms>]      ← optional extension
 *
 *   — <key name> <base64url signature>
 */

import type { STH } from './ct-api'
import { concat, fromBase64 } from './sct-parser'
import { ctFetch } from './transport'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Checkpoint {
  logName: string
  treeSize: number
  rootHash: Uint8Array
  timestamp?: number
  raw: string
}

// ── Checkpoint parsing ────────────────────────────────────────────────────────

/**
 * Parse a Sunlight / RFC 9162 signed-note checkpoint.
 */
export function parseCheckpoint(text: string): Checkpoint {
  // Split on newlines; signed notes separate the body from signature(s) with
  // a blank line followed by lines starting with "— ".
  const allLines = text.split('\n')

  // Find the blank line that precedes signatures
  const sepIdx = allLines.findIndex(
    (l, i) => l === '' && i + 1 < allLines.length && allLines[i + 1].startsWith('— '),
  )
  const bodyLines = (sepIdx >= 0 ? allLines.slice(0, sepIdx) : allLines).filter((l) => l !== '')

  if (bodyLines.length < 3) {
    throw new Error(`Checkpoint has fewer than 3 body lines: ${text.slice(0, 120)}`)
  }

  const logName = bodyLines[0]

  const treeSize = parseInt(bodyLines[1], 10)
  if (!Number.isFinite(treeSize) || treeSize < 0) {
    throw new Error(`Invalid tree size in checkpoint: "${bodyLines[1]}"`)
  }

  // Some implementations order the fields as: name, size, hash
  // Others may swap size and hash; try both by detecting which looks like base64
  let rootHash: Uint8Array
  try {
    rootHash = fromBase64(bodyLines[2])
    if (rootHash.length !== 32) throw new Error('Not 32 bytes')
  } catch {
    throw new Error(`Cannot decode root hash from checkpoint line: "${bodyLines[2]}"`)
  }

  // Optional Timestamp extension
  let timestamp: number | undefined
  for (const line of bodyLines.slice(3)) {
    if (line.startsWith('Timestamp:')) {
      const ms = parseInt(line.replace('Timestamp:', '').trim(), 10)
      if (Number.isFinite(ms)) timestamp = ms
    }
  }

  return { logName, treeSize, rootHash, timestamp, raw: text }
}

/**
 * Convert a Checkpoint into the common STH format.
 */
export function checkpointToSTH(cp: Checkpoint): STH & { apiType: 'sunlight' } {
  return {
    treeSize: cp.treeSize,
    timestamp: cp.timestamp !== undefined ? BigInt(cp.timestamp) : 0n,
    sha256RootHash: cp.rootHash,
    apiType: 'sunlight',
  }
}

// ── Tile path utilities ───────────────────────────────────────────────────────

const TILE_HEIGHT = 8          // binary levels per Sunlight level
const TILE_WIDTH = 1 << TILE_HEIGHT  // 256 hashes per tile

/**
 * Format a tile index per the Static CT API spec:
 * split into 3-digit groups, prefix all but the last group with "x".
 *
 *   0       → "000"
 *   9       → "009"
 *   999     → "999"
 *   1000    → "x001/000"
 *   1234    → "x001/234"
 *   1234567 → "x001/x234/567"
 *
 * (Spec: "All but the last path element MUST begin with an `x`.")
 */
export function formatTileIndex(n: number): string {
  const segs: string[] = []
  segs.push(String(n % 1000).padStart(3, '0'))  // last segment — no x
  n = Math.floor(n / 1000)
  while (n > 0) {
    segs.unshift('x' + String(n % 1000).padStart(3, '0'))  // non-last — prefix x
    n = Math.floor(n / 1000)
  }
  return segs.join('/')
}

/**
 * Build the URL path for a hash tile.
 * level: Sunlight tile level (0 = leaves, 1 = 256-leaf subtree roots, …)
 * n:     tile index
 * width: number of entries (< 256 for partial tiles)
 */
export function hashTilePath(level: number, n: number, width = TILE_WIDTH): string {
  const base = `tile/${level}/${formatTileIndex(n)}`
  return width < TILE_WIDTH ? `${base}.p/${width}` : base
}

/**
 * Build the URL path for a data tile (leaf entry data).
 */
export function dataTilePath(n: number, width?: number): string {
  const base = `tile/data/${formatTileIndex(n)}`
  return width !== undefined && width < TILE_WIDTH ? `${base}.p/${width}` : base
}

// ── Log endpoint fetches ──────────────────────────────────────────────────────

/**
 * Fetch the signed-note checkpoint for a Sunlight log.
 */
export async function getCheckpoint(logUrl: string): Promise<Checkpoint> {
  const { text } = await ctFetch(logUrl, 'checkpoint')
  if (!text) throw new Error('No text in checkpoint response')
  return parseCheckpoint(text)
}

/**
 * Fetch the STH-equivalent from a Sunlight checkpoint.
 */
export async function getSTHFromCheckpoint(logUrl: string): Promise<STH & { apiType: 'sunlight' }> {
  const cp = await getCheckpoint(logUrl)
  return checkpointToSTH(cp)
}

/**
 * Fetch raw bytes from a tile endpoint (hash or data tile).
 */
export async function fetchTileBytes(logUrl: string, tilePath: string): Promise<Uint8Array> {
  const { bytes } = await ctFetch(logUrl, tilePath)
  if (!bytes) throw new Error(`No bytes in tile response for ${tilePath}`)
  return bytes
}

/**
 * Parse a tile of 32-byte hash values.
 */
export function parseHashTile(tileBytes: Uint8Array): Uint8Array[] {
  const hashes: Uint8Array[] = []
  for (let i = 0; i + 32 <= tileBytes.length; i += 32) {
    hashes.push(tileBytes.slice(i, i + 32))
  }
  return hashes
}

// ── Tile fetching with caching ────────────────────────────────────────────────

type TileCache = Map<string, Uint8Array[]>

/**
 * Compute how many entries are stored at Sunlight tile level `tileLevel`
 * for a tree of `treeSize` leaves.
 *
 * Sunlight tiles only store hashes of *complete* subtrees of 2^(L*8) leaves;
 * the rightmost incomplete subtree (if any) is NOT represented at level L>0.
 * (At L=0, every leaf is its own complete 1-leaf subtree, so all leaves count.)
 *
 *   entries at level L = floor(treeSize / 2^(L*8))
 */
function entriesAtTileLevel(treeSize: number, tileLevel: number): number {
  const leavesPerEntry = Math.pow(2, tileLevel * TILE_HEIGHT)
  return Math.floor(treeSize / leavesPerEntry)
}

/**
 * Fetch a Sunlight hash tile and return the array of 32-byte hashes.
 * Automatically determines if the tile is full (256 entries) or partial.
 * Uses an in-memory cache to avoid re-fetching.
 */
export async function getHashTile(
  logUrl: string,
  tileLevel: number,
  tileIdx: number,
  treeSize: number,
  cache: TileCache = new Map(),
): Promise<Uint8Array[]> {
  const key = `${tileLevel}:${tileIdx}`
  if (cache.has(key)) return cache.get(key)!

  const totalEntries = entriesAtTileLevel(treeSize, tileLevel)
  const fullTileCount = Math.floor(totalEntries / TILE_WIDTH)
  const lastTileWidth = totalEntries % TILE_WIDTH

  const isLastPartialTile = tileIdx === fullTileCount && lastTileWidth > 0
  const width = isLastPartialTile ? lastTileWidth : TILE_WIDTH

  const path = hashTilePath(tileLevel, tileIdx, width)
  let bytes: Uint8Array

  try {
    bytes = await fetchTileBytes(logUrl, path)
  } catch {
    // Some logs serve partial tiles at the full-tile URL too — try without the .p suffix
    if (isLastPartialTile) {
      bytes = await fetchTileBytes(logUrl, hashTilePath(tileLevel, tileIdx))
    } else {
      throw new Error(`Failed to fetch tile ${path}`)
    }
  }

  const hashes = parseHashTile(bytes)
  cache.set(key, hashes)
  return hashes
}

// ── Hash at arbitrary binary-tree level ──────────────────────────────────────

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', concat(new Uint8Array([0x01]), left, right).slice()),
  )
}

/**
 * Get the hash of the subtree rooted at (binaryLevel, index) — i.e.
 * the Merkle Tree Hash of leaves [index*2^binaryLevel, min((index+1)*2^binaryLevel, treeSize)).
 *
 * Complete subtrees are looked up from Sunlight hash tiles (directly when
 * binaryLevel is a multiple of TILE_HEIGHT, otherwise by combining adjacent
 * tile entries).  Partial right-edge subtrees — whose hashes are NOT stored
 * in any tile — are computed via the RFC 6962 §2.1 recursive split.
 */
export async function getHashAtBinaryLevel(
  logUrl: string,
  binaryLevel: number,
  index: number,
  treeSize: number,
  cache: TileCache,
): Promise<Uint8Array> {
  const subtreeFull = Math.pow(2, binaryLevel)
  const subtreeStart = index * subtreeFull
  if (subtreeStart >= treeSize) {
    throw new Error(
      `Subtree (binaryLevel=${binaryLevel}, index=${index}) starts beyond treeSize=${treeSize}`,
    )
  }
  const n = Math.min(subtreeFull, treeSize - subtreeStart)
  return subtreeHash(logUrl, subtreeStart, n, treeSize, cache)
}

/**
 * RFC 6962 Merkle Tree Hash of `n` consecutive leaves starting at index `start`.
 *
 * When the range is a complete, power-of-2, aligned subtree, its hash is
 * served (directly or indirectly) by Sunlight hash tiles.  Otherwise we
 * split at the largest power of 2 less than `n` (the RFC 6962 rule) and
 * recurse — the left half is always complete, the right half may itself
 * be partial.
 */
async function subtreeHash(
  logUrl: string,
  start: number,
  n: number,
  treeSize: number,
  cache: TileCache,
): Promise<Uint8Array> {
  const isPow2 = n > 0 && (n & (n - 1)) === 0
  const isAligned = isPow2 && start % n === 0
  if (isAligned && start + n <= treeSize) {
    // Complete, aligned subtree → tile lookup.
    return getCompleteSubtreeHash(logUrl, Math.log2(n), start / n, treeSize, cache)
  }

  // Partial → RFC 6962 split: k = largest power of 2 with k < n.
  let k = 1
  while (k * 2 < n) k *= 2
  const left = await subtreeHash(logUrl, start, k, treeSize, cache)
  const right = await subtreeHash(logUrl, start + k, n - k, treeSize, cache)
  return nodeHash(left, right)
}

/**
 * Hash of a complete 2^binaryLevel-leaf subtree at the given index.
 * Caller MUST guarantee the subtree is fully within the tree.
 */
async function getCompleteSubtreeHash(
  logUrl: string,
  binaryLevel: number,
  index: number,
  treeSize: number,
  cache: TileCache,
): Promise<Uint8Array> {
  const tileLevel = Math.floor(binaryLevel / TILE_HEIGHT)
  const withinTile = binaryLevel % TILE_HEIGHT  // 0–7

  if (withinTile === 0) {
    // Stored directly in a Sunlight tile.
    const tileIdx = Math.floor(index / TILE_WIDTH)
    const offset = index % TILE_WIDTH
    const hashes = await getHashTile(logUrl, tileLevel, tileIdx, treeSize, cache)
    if (offset >= hashes.length) {
      throw new Error(
        `Complete subtree (binaryLevel=${binaryLevel}, index=${index}) missing ` +
        `from tile ${tileLevel}/${tileIdx} (got ${hashes.length} entries)`,
      )
    }
    return hashes[offset]
  }

  // Combine 2^withinTile adjacent complete tile-level entries (binary level
  // tileLevel*8).  Since the subtree is complete, all entries are stored.
  const count = 1 << withinTile
  const tileEntryStart = index * count
  const lowerHashes: Uint8Array[] = []
  for (let j = 0; j < count; j++) {
    const lowerIdx = tileEntryStart + j
    const tileIdx = Math.floor(lowerIdx / TILE_WIDTH)
    const offset = lowerIdx % TILE_WIDTH
    const hashes = await getHashTile(logUrl, tileLevel, tileIdx, treeSize, cache)
    if (offset >= hashes.length) {
      throw new Error(
        `Complete subtree at (binaryLevel=${binaryLevel}, index=${index}) needs ` +
        `${count} tile-${tileLevel} entries from ${tileEntryStart}, but ` +
        `tile/${tileLevel}/${tileIdx} has only ${hashes.length}`,
      )
    }
    lowerHashes.push(hashes[offset])
  }

  // Pair-hash up `withinTile` levels — every level halves exactly.
  let current = lowerHashes
  for (let step = 0; step < withinTile; step++) {
    const next: Uint8Array[] = []
    for (let k = 0; k < current.length; k += 2) {
      next.push(await nodeHash(current[k], current[k + 1]))
    }
    current = next
  }
  return current[0]
}

// ── Data tile parsing ─────────────────────────────────────────────────────────

export interface DataTileEntry {
  timestamp: bigint
  entryType: 0 | 1          // 0 = x509_entry, 1 = precert_entry
  /**
   * Raw TimestampedEntry bytes only (from timestamp through extensions).
   * This is the input to the leaf-hash function — does NOT include the
   * per-chain fingerprints or the pre_certificate that follows in the tile.
   */
  timestampedEntryBytes: Uint8Array
}

function readUint16BE(buf: Uint8Array, off: number): number {
  return (buf[off] << 8) | buf[off + 1]
}

function readUint24BE(buf: Uint8Array, off: number): number {
  return (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]
}

function readUint64BEbig(buf: Uint8Array, off: number): bigint {
  let v = 0n
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(buf[off + i])
  return v
}

/**
 * Parse a Static CT API data tile into an array of entries.
 *
 * Each entry is a `TileLeaf` (c2sp.org/static-ct-api §"Log entries"):
 *
 *   TimestampedEntry timestamped_entry
 *     timestamp     uint64 BE   (8 bytes)
 *     entry_type    uint16 BE   (2 bytes): 0 = x509, 1 = precert
 *     [x509]        uint24 cert_len + cert_bytes          (signed_entry)
 *     [precert]     32-byte issuer_key_hash + uint24 tbs_len + tbs_bytes
 *     ext_len       uint16 BE + extension bytes           (CtExtensions)
 *   ── end of TimestampedEntry ──────────────────────────────────────────────
 *   [precert only]  uint24 pre_cert_len + pre_cert_bytes  (ASN.1Cert)
 *   Fingerprint certificate_chain<0..2^16-1>              (uint16 total + N×32 SHA-256 hashes)
 *
 * The leaf hash is computed only over the `TimestampedEntry` bytes, matching
 * what RFC 6962 defines for `MerkleTreeLeaf`.
 */
export function parseDataTile(bytes: Uint8Array): DataTileEntry[] {
  const entries: DataTileEntry[] = []
  let off = 0

  while (off < bytes.length) {
    if (off + 10 > bytes.length) break  // need at least timestamp(8) + type(2)

    const tsStart = off
    const timestamp = readUint64BEbig(bytes, off);  off += 8
    const entryType = readUint16BE(bytes, off) as 0 | 1;  off += 2

    if (entryType === 0) {
      // x509_entry signed_entry: uint24 cert_len + cert_bytes
      if (off + 3 > bytes.length) break
      const certLen = readUint24BE(bytes, off);  off += 3 + certLen
    } else if (entryType === 1) {
      // precert_entry signed_entry: issuer_key_hash(32) + uint24 tbs_len + tbs_bytes
      if (off + 35 > bytes.length) break
      const tbsLen = readUint24BE(bytes, off + 32);  off += 32 + 3 + tbsLen
    } else {
      break  // unknown entry type — stop parsing
    }

    // CtExtensions: uint16 ext_len + ext_bytes
    if (off + 2 > bytes.length) break
    const extLen = readUint16BE(bytes, off);  off += 2 + extLen

    // ── End of TimestampedEntry ───────────────────────────────────────────────
    const tsEnd = off
    const timestampedEntryBytes = bytes.slice(tsStart, tsEnd)

    // TileLeaf extra: for precert_entry, the original pre-certificate (ASN.1Cert)
    if (entryType === 1) {
      if (off + 3 > bytes.length) break
      const preCertLen = readUint24BE(bytes, off);  off += 3 + preCertLen
    }

    // TileLeaf extra: certificate chain as SHA-256 fingerprints (uint16 total byte count)
    if (off + 2 > bytes.length) break
    const chainBytes = readUint16BE(bytes, off);  off += 2 + chainBytes

    entries.push({ timestamp, entryType, timestampedEntryBytes })
  }

  return entries
}

/**
 * Compute the RFC 6962 Merkle leaf hash for a data tile entry.
 *
 * Leaf hash = SHA-256(0x00 ‖ version=0x00 ‖ leaf_type=0x00 ‖ timestampedEntryBytes)
 *
 * The three prefix bytes are the domain separator, version (v1), and
 * leaf_type (timestamped_entry) — identical to what merkle.ts prepends when
 * hashing from certificate DER, making the hashes directly comparable.
 */
export async function dataEntryLeafHash(timestampedEntryBytes: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(3 + timestampedEntryBytes.length)
  // input[0] = 0x00: RFC 6962 leaf-hash domain separator
  // input[1] = 0x00: version v1
  // input[2] = 0x00: leaf_type timestamped_entry
  input.set(timestampedEntryBytes, 3)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input))
}

/**
 * Fetch and parse a data tile, handling partial last tiles.
 */
async function fetchDataTile(
  logUrl: string,
  tileIdx: number,
  treeSize: number,
): Promise<DataTileEntry[]> {
  const remainder = treeSize % TILE_WIDTH
  const isLastPartial = remainder > 0 && tileIdx === Math.floor(treeSize / TILE_WIDTH)

  let bytes: Uint8Array
  if (isLastPartial) {
    try {
      bytes = await fetchTileBytes(logUrl, dataTilePath(tileIdx, remainder))
    } catch {
      // Some logs omit the .p suffix for partial tiles
      bytes = await fetchTileBytes(logUrl, dataTilePath(tileIdx))
    }
  } else {
    bytes = await fetchTileBytes(logUrl, dataTilePath(tileIdx))
  }

  return parseDataTile(bytes)
}

/**
 * Confirm that the entry at `leafIdx` matches the expected leaf hash.
 * Used when the SCT's leaf_index extension (C2SP static-ct-api §"Extensions")
 * tells us the index up front — we still fetch ONE data tile to verify the
 * hash matches what we computed from the cert, so a forged or stale
 * extension can't slip past us.
 *
 * Returns the index if it matches, or null on mismatch / out-of-range
 * (caller can fall back to the timestamp-based binary search).
 */
export async function verifyLeafAtIndex(
  logUrl: string,
  leafIdx: number,
  targetLeafHash: Uint8Array,
  treeSize: number,
): Promise<number | null> {
  if (leafIdx < 0 || leafIdx >= treeSize) return null
  const tileIdx = Math.floor(leafIdx / TILE_WIDTH)
  const offset = leafIdx % TILE_WIDTH
  const entries = await fetchDataTile(logUrl, tileIdx, treeSize)
  if (offset >= entries.length) return null
  const hash = await dataEntryLeafHash(entries[offset].timestampedEntryBytes)
  const match = hash.length === targetLeafHash.length &&
    hash.every((b, i) => b === targetLeafHash[i])
  return match ? leafIdx : null
}

/**
 * Binary-search data tiles to find the leaf index matching a given SCT.
 *
 * CT log timestamps are generally monotonically non-decreasing, so we can
 * binary-search on the first entry's timestamp of each tile, then scan the
 * ±2 surrounding tiles for an exact leaf-hash match.
 *
 * @param logUrl          Log base URL (monitoring URL for tiled logs)
 * @param targetTimestamp SCT timestamp in milliseconds (as BigInt)
 * @param targetLeafHash  32-byte Merkle leaf hash computed from the cert
 * @param treeSize        Tree size from the most recent STH / checkpoint
 */
export async function findLeafIndex(
  logUrl: string,
  targetTimestamp: bigint,
  targetLeafHash: Uint8Array,
  treeSize: number,
): Promise<number> {
  const tileCache = new Map<number, DataTileEntry[]>()
  const totalTiles = Math.ceil(treeSize / TILE_WIDTH)

  async function getTile(idx: number): Promise<DataTileEntry[]> {
    if (tileCache.has(idx)) return tileCache.get(idx)!
    const entries = await fetchDataTile(logUrl, idx, treeSize)
    tileCache.set(idx, entries)
    return entries
  }

  function hashesEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((byte, k) => byte === b[k])
  }

  // ── Binary search ─────────────────────────────────────────────────────────
  // Find the rightmost tile whose first-entry timestamp ≤ targetTimestamp.
  let lo = 0
  let hi = totalTiles - 1

  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2)
    const entries = await getTile(mid)
    if (entries.length === 0 || entries[0].timestamp <= targetTimestamp) {
      lo = mid
    } else {
      hi = mid - 1
    }
  }

  // ── Scan window ───────────────────────────────────────────────────────────
  const startTile = Math.max(0, lo - 2)
  const endTile   = Math.min(totalTiles - 1, lo + 2)

  // First pass: timestamps must match exactly (avoids unnecessary SHA-256 calls)
  for (let tileIdx = startTile; tileIdx <= endTile; tileIdx++) {
    const entries = await getTile(tileIdx)
    for (let j = 0; j < entries.length; j++) {
      if (entries[j].timestamp !== targetTimestamp) continue
      const hash = await dataEntryLeafHash(entries[j].timestampedEntryBytes)
      if (hashesEqual(hash, targetLeafHash)) return tileIdx * TILE_WIDTH + j
    }
  }

  // Second pass: compare every leaf hash without timestamp pre-filter
  // (guard against sub-millisecond rounding differences between log and SCT)
  for (let tileIdx = startTile; tileIdx <= endTile; tileIdx++) {
    const entries = await getTile(tileIdx)
    for (let j = 0; j < entries.length; j++) {
      const hash = await dataEntryLeafHash(entries[j].timestampedEntryBytes)
      if (hashesEqual(hash, targetLeafHash)) return tileIdx * TILE_WIDTH + j
    }
  }

  throw new Error(
    `Leaf not found in data tiles ${startTile}–${endTile} ` +
    `(treeSize=${treeSize.toLocaleString()}, target tile=${lo})`,
  )
}

// ── Tile-based inclusion proof ────────────────────────────────────────────────

/**
 * Build the Merkle inclusion-proof audit path for a leaf at `leafIdx`
 * in a tree of `treeSize` leaves, using Sunlight hash tiles.
 *
 * Returns the same audit path format as `ct/v1/get-proof-by-hash`:
 * an ordered array of 32-byte sibling hashes (from leaf level to root).
 */
export async function buildProofFromTiles(
  logUrl: string,
  leafIdx: number,
  treeSize: number,
): Promise<Uint8Array[]> {
  const cache: TileCache = new Map()
  const auditPath: Uint8Array[] = []

  let idx = leafIdx
  let size = treeSize

  for (let binaryLevel = 0; size > 1; binaryLevel++) {
    const sibling = idx ^ 1
    if (sibling < size) {
      const hash = await getHashAtBinaryLevel(logUrl, binaryLevel, sibling, treeSize, cache)
      auditPath.push(hash)
    }
    idx = Math.floor(idx / 2)
    size = Math.ceil(size / 2)
  }

  return auditPath
}
