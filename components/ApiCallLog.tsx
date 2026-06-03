'use client'

import { useState } from 'react'
import type { ApiCall } from '@/lib/transport'
import { fromBase64, toHex } from '@/lib/sct-parser'
import { parseTilePath, tileLabel, tileKey } from '@/lib/tile-label'
import RawBytes from './RawBytes'

interface Props {
  calls: ApiCall[]
  /** Tile keys currently selected (shared with the inclusion-path viz). */
  selected?: Set<string> | null
  /** Toggle the selection for a set of tile keys (click to select / clear). */
  onToggle?: (keys: Set<string>) => void
}

/**
 * RFC 6962 JSON responses encode binary fields as base64.  Pull out the ones
 * worth seeing as hex (root hash, tree-head signature, and each audit-path
 * sibling) so the user can compare them against the Merkle visualisation.
 */
function decodeBase64Fields(json: unknown): { label: string; hex: string }[] {
  if (!json || typeof json !== 'object') return []
  const obj = json as Record<string, unknown>
  const out: { label: string; hex: string }[] = []

  const tryDecode = (label: string, value: unknown) => {
    if (typeof value !== 'string') return
    try {
      out.push({ label, hex: toHex(fromBase64(value)) })
    } catch {
      // not valid base64 — skip
    }
  }

  for (const field of ['sha256_root_hash', 'tree_head_signature']) {
    tryDecode(field, obj[field])
  }
  if (Array.isArray(obj.audit_path)) {
    obj.audit_path.forEach((entry, i) => tryDecode(`audit_path[${i}]`, entry))
  }

  return out
}

/** Short, human-readable name for a CT log endpoint. */
function endpointLabel(endpoint: string): string {
  if (endpoint === 'checkpoint') return 'checkpoint'
  if (endpoint === 'ct/v1/get-sth') return 'get-sth'
  if (endpoint === 'ct/v1/get-proof-by-hash') return 'get-proof-by-hash'
  if (endpoint.startsWith('tile/')) {
    const p = parseTilePath(endpoint)
    return p ? tileLabel(p) : endpoint
  }
  return endpoint
}

function ApiCallRow({
  call,
  selected,
  onToggle,
}: {
  call: ApiCall
  selected?: Set<string> | null
  onToggle?: (keys: Set<string>) => void
}) {
  const [open, setOpen] = useState(false)
  const decoded = call.json !== undefined ? decodeBase64Fields(call.json) : []

  // This row's tile identity, so it can be cross-linked with the inclusion-path
  // sibling(s) it provided.
  const parsed = call.endpoint.startsWith('tile/') ? parseTilePath(call.endpoint) : null
  const key = parsed ? tileKey(parsed.kind, parsed.level, parsed.idx) : null
  const active = key !== null && !!selected?.has(key)

  // Clicking the row expands/collapses its details. The proof-path highlight is
  // a separate, explicit control: the ⌖ "locate" button on tile rows toggles a
  // sticky highlight of the path nodes this tile produced (and vice versa).
  return (
    <div
      className={`border rounded transition-colors ${
        active ? 'border-amber-500/70 bg-amber-500/10' : 'border-slate-700 bg-slate-900/60'
      }`}
    >
      <div
        onClick={() => setOpen((o) => !o)}
        title={open ? 'Hide details' : 'Show details'}
        className="w-full flex items-center gap-2 px-2.5 py-1.5 text-left text-xs font-mono hover:bg-slate-800/60 transition-colors cursor-pointer"
      >
        <span className={`inline-block transition-transform text-slate-500 ${open ? 'rotate-90' : ''}`}>▶</span>
        <span className="text-slate-500">{call.method}</span>
        <span className="text-slate-200">{endpointLabel(call.endpoint)}</span>
        {key && (
          <button
            onClick={(e) => {
              e.stopPropagation()
              onToggle?.(new Set([key]))
            }}
            title={
              active
                ? 'Clear highlight in the inclusion path'
                : 'Highlight where this tile is used in the inclusion path'
            }
            aria-pressed={active}
            className={`ml-auto px-1 leading-none rounded cursor-pointer transition-colors ${
              active
                ? 'text-amber-300 bg-amber-500/20'
                : 'text-slate-500 hover:text-amber-300 hover:bg-slate-700/60'
            }`}
          >
            ⌖
          </button>
        )}
        <span
          className={`${key ? '' : 'ml-auto'} px-1.5 py-0.5 rounded font-bold ${
            call.ok ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
          }`}
        >
          {call.ok ? (call.status ?? 'OK') : (call.status ?? 'ERR')}
        </span>
        <span className="text-slate-600">{Math.round(call.durationMs)}ms</span>
      </div>

      {open && (
        <div className="px-2.5 pb-2.5 pt-1 space-y-2 text-xs font-mono border-t border-slate-700/60">
          {/* Request */}
          <div>
            <p className="text-slate-500 mb-0.5">
              Request <span className="text-slate-600">(via {call.via})</span>
            </p>
            <p className="text-slate-300 break-all">{call.endpoint}</p>
            <p className="text-sky-300/80 break-all">{call.url}</p>
            {call.params && Object.keys(call.params).length > 0 && (
              <div className="mt-1 pl-2 border-l border-slate-700 space-y-0.5">
                {Object.entries(call.params).map(([k, v]) => (
                  <div key={k} className="break-all">
                    <span className="text-slate-500">{k}: </span>
                    <span className="text-slate-300">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Response */}
          <div>
            <p className="text-slate-500 mb-0.5">Response</p>
            {call.error && <p className="text-red-300 break-all">{call.error}</p>}
            {call.json !== undefined && (
              <pre className="p-2 bg-slate-950 border border-slate-700 rounded text-slate-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                {JSON.stringify(call.json, null, 2)}
              </pre>
            )}
            {decoded.length > 0 && (
              <div className="mt-1.5">
                <p className="text-slate-500 mb-0.5">Decoded (base64 → hex)</p>
                <div className="pl-2 border-l border-slate-700 space-y-0.5">
                  {decoded.map((d) => (
                    <div key={d.label} className="break-all">
                      <span className="text-slate-500">{d.label}: </span>
                      <span className="text-emerald-300/80">{d.hex}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {call.text !== undefined && (
              <pre className="p-2 bg-slate-950 border border-slate-700 rounded text-slate-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                {call.text}
              </pre>
            )}
            {call.byteLength !== undefined && (
              <RawBytes label="Binary body" hex={call.bytesHex ?? ''} className="mt-0" />
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Collapsible list of the CT-log HTTP calls (get-sth, get-proof-by-hash,
 * checkpoint, tiles) that built this SCT's inclusion proof.
 */
export default function ApiCallLog({ calls, selected, onToggle }: Props) {
  const [open, setOpen] = useState(false)

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono cursor-pointer"
      >
        <span className={`transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
        CT API requests
        <span className="text-slate-600">({calls.length})</span>
      </button>
      {open && (
        <div className="mt-2 space-y-1.5">
          {calls.map((call, i) => (
            <ApiCallRow key={i} call={call} selected={selected} onToggle={onToggle} />
          ))}
        </div>
      )}
    </div>
  )
}
