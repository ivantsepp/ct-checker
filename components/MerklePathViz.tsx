'use client'

import { useState } from 'react'
import type { InclusionProof } from '@/types/ct'
import { toHex } from '@/lib/sct-parser'

interface Props {
  proof: InclusionProof
}

export default function MerklePathViz({ proof }: Props) {
  const [open, setOpen] = useState(false)

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono"
      >
        <span className={`transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
        Show inclusion path ({proof.auditPath.length} steps)
      </button>

      {open && (
        <div className="mt-3 space-y-1 font-mono text-xs">
          {/* Leaf */}
          <div className="flex items-start gap-2">
            <span className="text-slate-500 w-16 shrink-0 text-right">leaf</span>
            <span className="text-amber-300 break-all">{toHex(proof.leafHash)}</span>
          </div>

          {proof.steps.map((step, i) => (
            <div key={i} className="space-y-1">
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
              <div className="flex items-start gap-2">
                <span className="text-slate-500 w-16 shrink-0 text-right">L{i + 1}</span>
                <span className="text-amber-300 break-all">{toHex(step.parentHash)}</span>
              </div>
            </div>
          ))}

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
