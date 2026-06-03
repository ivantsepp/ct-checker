/**
 * Shared helpers for Sunlight tile paths — used by both the CT API request log
 * and the inclusion-path visualisation so they can label and cross-reference
 * the same tiles.
 */

/** Hashes per Sunlight tile (tile height 8). Mirrors TILE_WIDTH in ct-static-api. */
export const TILE_WIDTH = 256

export interface ParsedTilePath {
  kind: 'hash' | 'data'
  /** Sunlight tile level (0 for data tiles). */
  level: number
  /** Tile index within the level. */
  idx: number
  /** Width of a partial (`.p/<width>`) tile, if present. */
  partialWidth?: number
}

/**
 * Decode a Sunlight tile endpoint into its kind, level and index.  This inverts
 * `formatTileIndex` (3-digit groups, all but the last prefixed with `x`) and
 * strips any trailing `.p/<width>` partial marker.
 *
 *   tile/data/x001/234      → { kind: 'data', level: 0, idx: 1234 }
 *   tile/3/x001/234.p/100   → { kind: 'hash', level: 3, idx: 1234, partialWidth: 100 }
 */
export function parseTilePath(endpoint: string): ParsedTilePath | null {
  const partial = endpoint.match(/\.p\/(\d+)$/)
  const partialWidth = partial ? Number(partial[1]) : undefined
  const path = partial ? endpoint.slice(0, partial.index) : endpoint

  let kind: 'hash' | 'data'
  let level = 0
  let rest: string
  if (path.startsWith('tile/data/')) {
    kind = 'data'
    rest = path.slice('tile/data/'.length)
  } else {
    const m = path.match(/^tile\/(\d+)\/(.+)$/)
    if (!m) return null
    kind = 'hash'
    level = Number(m[1])
    rest = m[2]
  }

  let idx = 0
  for (const seg of rest.split('/')) idx = idx * 1000 + Number(seg.replace(/^x/, ''))
  if (Number.isNaN(idx)) return null

  return { kind, level, idx, partialWidth }
}

/**
 * Stable identity for a tile, shared between the proof visualisation and the
 * API call log so a sibling can be linked to the request that fetched it.
 */
export function tileKey(kind: 'hash' | 'data', level: number, idx: number): string {
  return kind === 'data' ? `d:${idx}` : `h:${level}:${idx}`
}

/** Human-readable label, e.g. "hash tile L2 #24 (partial 97/256)". */
export function tileLabel(p: ParsedTilePath): string {
  const kind = p.kind === 'data' ? 'data tile' : `hash tile L${p.level}`
  const suffix = p.partialWidth !== undefined ? ` (partial ${p.partialWidth}/${TILE_WIDTH})` : ''
  return `${kind} #${p.idx.toLocaleString()}${suffix}`
}
