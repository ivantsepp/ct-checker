'use client'

import { useState } from 'react'
import type { InclusionProof, TileSource } from '@/types/ct'
import { toHex } from '@/lib/sct-parser'
import { tileKey, tileLabel, TILE_WIDTH } from '@/lib/tile-label'

interface Props {
  proof: InclusionProof
  /** Tile keys currently selected (shared with the API request log). */
  selected?: Set<string> | null
  /** Toggle the selection for a set of tile keys (click to select / clear). */
  onToggle?: (keys: Set<string>) => void
}

interface SourceSummary {
  keys: Set<string>
  label: string
}

/**
 * Collapse a sibling's `TileSource` into the set of tile keys it touched and a
 * readable label.  Entries are grouped by tile; contiguous offsets render as a
 * range.  `direct` siblings are a single stored hash ("from …"); others are
 * recombined from lower entries ("computed from …").
 */
function summarizeSource(src: TileSource | undefined): SourceSummary | null {
  if (!src || src.refs.length === 0) return null

  const byTile = new Map<
    string,
    { kind: 'hash' | 'data'; level: number; idx: number; offsets: number[] }
  >()
  for (const r of src.refs) {
    const k = tileKey(r.kind, r.tileLevel, r.tileIdx)
    const existing = byTile.get(k)
    if (existing) existing.offsets.push(r.offset)
    else byTile.set(k, { kind: r.kind, level: r.tileLevel, idx: r.tileIdx, offsets: [r.offset] })
  }

  const parts: string[] = []
  for (const t of byTile.values()) {
    const base = tileLabel({ kind: t.kind, level: t.level, idx: t.idx })
    if (t.offsets.length === 1) {
      parts.push(`${base} · entry ${t.offsets[0]}`)
    } else {
      const min = Math.min(...t.offsets)
      const max = Math.max(...t.offsets)
      const contiguous = max - min + 1 === t.offsets.length
      parts.push(`${base} · ${contiguous ? `entries ${min}–${max}` : `${t.offsets.length} entries`}`)
    }
  }

  return {
    keys: new Set(byTile.keys()),
    label: (src.direct ? 'from ' : 'computed from ') + parts.join(', '),
  }
}

export default function MerklePathViz({ proof, selected, onToggle }: Props) {
  const [open, setOpen] = useState(false)

  const isTiled = proof.proofApiType === 'tiles'

  // The leaf hash is confirmed against the data tile it lives in.
  const leafSource: SourceSummary | null = isTiled
    ? (() => {
        const idx = Math.floor(proof.leafIndex / TILE_WIDTH)
        const off = proof.leafIndex % TILE_WIDTH
        return {
          keys: new Set([tileKey('data', 0, idx)]),
          label: `from data tile #${idx.toLocaleString()} · entry ${off}`,
        }
      })()
    : null

  const intersects = (keys: Set<string>) =>
    !!selected && [...keys].some((k) => selected.has(k))

  /** Click handler that toggles selection of a node's source tiles. */
  function clickable(keys: Set<string> | undefined) {
    if (!keys) return {}
    return { onClick: () => onToggle?.(keys), role: 'button' as const }
  }

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono cursor-pointer"
      >
        <span className={`transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
        Show inclusion path ({proof.auditPath.length} steps)
      </button>

      {open && (
        <div className="mt-3 space-y-1 font-mono text-xs">
          {/* Leaf */}
          <div
            {...clickable(leafSource?.keys)}
            className={`rounded px-1 -mx-1 transition-colors ${
              leafSource ? 'cursor-pointer' : ''
            } ${leafSource && intersects(leafSource.keys) ? 'bg-amber-500/15' : ''}`}
          >
            <div className="flex items-start gap-2">
              <span className="text-slate-500 w-16 shrink-0 text-right">leaf</span>
              <span className="text-amber-300 break-all">{toHex(proof.leafHash)}</span>
            </div>
            {leafSource && (
              <div className="flex items-start gap-2">
                <span className="w-16 shrink-0" />
                <span className="text-[11px] text-slate-500">↳ {leafSource.label}</span>
              </div>
            )}
          </div>

          {/* Steps — no inter-block gap so a tile that feeds several
              consecutive siblings highlights as one contiguous band.  Each
              block covers the whole step (current ‖ sibling → parent). */}
          <div>
            {proof.steps.map((step, i) => {
              const src = summarizeSource(step.tileSource)
              const active = src ? intersects(src.keys) : false
              return (
                <div
                  key={i}
                  {...clickable(src?.keys)}
                  className={`space-y-1 pt-1 px-1 -mx-1 transition-colors ${
                    src ? 'cursor-pointer' : ''
                  } ${active ? 'bg-amber-500/15' : ''}`}
                >
                  <div className="flex items-center gap-2 ml-16 text-slate-600">
                    <span>
                      SHA-256(0x01 ‖{' '}
                      {step.siblingIsLeft ? (
                        <>
                          <span className="text-sky-400">sibling</span>
                          {' ‖ '}
                          <span className="text-amber-400">current</span>
                        </>
                      ) : (
                        <>
                          <span className="text-amber-400">current</span>
                          {' ‖ '}
                          <span className="text-sky-400">sibling</span>
                        </>
                      )}
                      )
                    </span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 w-16 shrink-0 text-right">
                      {step.siblingIsLeft ? '←' : '→'}
                    </span>
                    <span className="text-sky-300 break-all" title={`Sibling at level ${i}`}>
                      {toHex(step.sibling)}
                    </span>
                  </div>
                  {src && (
                    <div className="flex items-start gap-2">
                      <span className="w-16 shrink-0" />
                      <span className="text-[11px] text-slate-500">↳ {src.label}</span>
                    </div>
                  )}
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 w-16 shrink-0 text-right">L{i + 1}</span>
                    <span className="text-amber-300 break-all">{toHex(step.parentHash)}</span>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Root comparison */}
          <div className="mt-3 pt-3 border-t border-slate-700 space-y-1">
            <div className="flex items-start gap-2">
              <span className="text-slate-500 w-16 shrink-0 text-right">computed</span>
              <span className="text-amber-300 break-all">{toHex(proof.computedRoot)}</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-slate-500 w-16 shrink-0 text-right">STH root</span>
              <span className="text-slate-300 break-all">{toHex(proof.rootHash)}</span>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-16" />
              {proof.verified ? (
                <span className="text-emerald-400 font-semibold">✓ Roots match</span>
              ) : (
                <span className="text-red-400 font-semibold">✗ Root mismatch</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
