'use client'

import { useMemo, useRef, useState } from 'react'
import type { CTLog } from '@/types/ct'
import { getOperatorCors } from '@/lib/cors-memory'

/**
 * Autocomplete combobox for adding a CT log to the feed.  `options` is the list
 * of usable logs not already monitored; selecting one calls `onAdd`.
 */
export default function LogPicker({
  options,
  onAdd,
}: {
  options: CTLog[]
  onAdd: (log: CTLog) => void
}) {
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [highlight, setHighlight] = useState(0)
  const blurTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase()
    const pool = q
      ? options.filter(
          (l) =>
            l.description.toLowerCase().includes(q) ||
            (l.operator ?? '').toLowerCase().includes(q),
        )
      : options
    return pool.slice(0, 50)
  }, [options, query])

  function add(log: CTLog | undefined) {
    if (!log) return
    onAdd(log)
    setQuery('')
    setHighlight(0)
    setOpen(false)
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setOpen(true)
      setHighlight((h) => Math.min(h + 1, matches.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setHighlight((h) => Math.max(h - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      add(matches[highlight])
    } else if (e.key === 'Escape') {
      setOpen(false)
    }
  }

  return (
    <div className="relative">
      <input
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          setOpen(true)
          setHighlight(0)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => {
          // Delay so an option's onMouseDown/click registers before close.
          blurTimer.current = setTimeout(() => setOpen(false), 120)
        }}
        onKeyDown={onKeyDown}
        placeholder={options.length ? '+ add log…' : 'all logs added'}
        disabled={!options.length}
        className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs w-40 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-600 disabled:opacity-40"
      />

      {open && matches.length > 0 && (
        <ul className="absolute z-20 mt-1 right-0 w-72 max-h-72 overflow-y-auto bg-slate-900 border border-slate-700 rounded-lg shadow-xl py-1">
          {matches.map((log, i) => {
            const cors = getOperatorCors(log.operator)
            return (
              <li key={log.logId}>
                <button
                  // onMouseDown beats the input's onBlur, so the click lands.
                  onMouseDown={(e) => {
                    e.preventDefault()
                    clearTimeout(blurTimer.current)
                    add(log)
                  }}
                  onMouseEnter={() => setHighlight(i)}
                  className={`w-full text-left px-3 py-1.5 flex items-center gap-2 ${
                    i === highlight ? 'bg-slate-800' : ''
                  }`}
                >
                  <span className="flex-1 min-w-0">
                    <span className="block text-xs text-slate-200 truncate">{log.description}</span>
                    <span className="block text-[10px] text-slate-500 truncate">
                      {log.operator}
                      {log.logType === 'tiled' && ' · sunlight'}
                    </span>
                  </span>
                  {cors === 'ok' && (
                    <span className="text-[9px] text-emerald-400 border border-emerald-800 rounded px-1">
                      CORS ✓
                    </span>
                  )}
                  {cors === 'blocked' && (
                    <span className="text-[9px] text-red-400 border border-red-900 rounded px-1">
                      CORS ✗
                    </span>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
