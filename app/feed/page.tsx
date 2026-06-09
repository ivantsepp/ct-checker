'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { CTLog } from '@/types/ct'
import { getLogList } from '@/lib/log-list'
import {
  streamLog,
  selectFeedLogs,
  listUsableLogs,
  verifyHref,
  type FeedCert,
  type LogStreamController,
} from '@/lib/ct-feed'
import NavBar from '@/components/NavBar'
import FeedDrawer from '@/components/FeedDrawer'
import LogPicker from '@/components/LogPicker'

type Status = 'idle' | 'poll' | 'ok' | 'err'

const MAX_ROWS = 400

function fmtTime(ts: number): string {
  return new Date(ts).toISOString().slice(11, 23) // HH:MM:SS.mmm
}

const dotClass: Record<Status, string> = {
  idle: 'bg-slate-600',
  poll: 'bg-amber-400 animate-pulse',
  ok: 'bg-emerald-400',
  err: 'bg-red-400',
}

export default function FeedPage() {
  const router = useRouter()

  const [logs, setLogs] = useState<CTLog[]>([])
  const [allUsable, setAllUsable] = useState<CTLog[]>([])
  const [statuses, setStatuses] = useState<Record<string, Status>>({})
  const [enabled, setEnabled] = useState<Record<string, boolean>>({})
  const [certs, setCerts] = useState<FeedCert[]>([])
  const [paused, setPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [rate, setRate] = useState(0)
  const [total, setTotal] = useState(0)
  const [skipped, setSkipped] = useState(0)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Refs read inside the long-lived poll loops (avoid stale closures).
  const pausedRef = useRef(false)
  const enabledRef = useRef<Record<string, boolean>>({})
  const controllersRef = useRef<Map<string, LogStreamController>>(new Map())
  const seenRef = useRef<Set<string>>(new Set())
  const rateCounterRef = useRef(0)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])
  useEffect(() => {
    enabledRef.current = enabled
  }, [enabled])

  const setStatus = useCallback((name: string, s: Status) => {
    setStatuses((prev) => (prev[name] === s ? prev : { ...prev, [name]: s }))
  }, [])

  const pushCerts = useCallback((incoming: FeedCert[]) => {
    const fresh = incoming.filter((c) => !seenRef.current.has(c.id))
    if (!fresh.length) return
    for (const c of fresh) seenRef.current.add(c.id)
    // Bound the seen-set so it can't grow without limit.
    if (seenRef.current.size > MAX_ROWS * 4) {
      seenRef.current = new Set(fresh.map((c) => c.id))
    }
    rateCounterRef.current += fresh.length
    setTotal((t) => t + fresh.length)
    setCerts((prev) => [...fresh.reverse(), ...prev].slice(0, MAX_ROWS))
  }, [])

  // ── Rate ticker ─────────────────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setRate(rateCounterRef.current)
      rateCounterRef.current = 0
    }, 1000)
    return () => clearInterval(id)
  }, [])

  // Start a polling loop for one log (idempotent per log description).
  const startLog = useCallback(
    (log: CTLog) => {
      const name = log.description
      if (controllersRef.current.has(name)) return
      controllersRef.current.set(
        name,
        streamLog(log, {
          // pollInterval defaults to a build-aware cadence (slower on static).
          // Idle while globally paused or this log is individually disabled.
          isPaused: () => pausedRef.current || !enabledRef.current[name],
          onStatus: (s) => setStatus(name, s),
          onCerts: (c) => pushCerts(c),
          onSkip: (n) => setSkipped((x) => x + n),
        }),
      )
    },
    [setStatus, pushCerts],
  )

  // ── Boot the pollers ──────────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false
    const controllers = controllersRef.current

    ;(async () => {
      try {
        const all = await getLogList()
        if (cancelled) return
        setAllUsable(listUsableLogs(all))
        const selected = selectFeedLogs(all)
        if (!selected.length) {
          setLoadError('No currently-usable CT logs found in the log list.')
          return
        }
        setLogs(selected)
        const initEnabled: Record<string, boolean> = {}
        const initStatus: Record<string, Status> = {}
        for (const l of selected) {
          initEnabled[l.description] = true
          initStatus[l.description] = 'idle'
        }
        enabledRef.current = initEnabled
        setEnabled(initEnabled)
        setStatuses(initStatus)

        for (const log of selected) startLog(log)
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : String(e))
      }
    })()

    return () => {
      cancelled = true
      for (const c of controllers.values()) c.stop()
      controllers.clear()
    }
  }, [startLog])

  // ── Controls ──────────────────────────────────────────────────────────────────
  function addLog(log: CTLog) {
    const name = log.description
    if (controllersRef.current.has(name)) {
      // Already monitored — just (re-)enable it.
      if (!enabledRef.current[name]) toggleLog(name)
      return
    }
    enabledRef.current = { ...enabledRef.current, [name]: true }
    setEnabled((prev) => ({ ...prev, [name]: true }))
    setStatus(name, 'idle')
    setLogs((prev) => [...prev, log])
    startLog(log)
  }

  function toggleLog(name: string) {
    setEnabled((prev) => {
      const next = { ...prev, [name]: !prev[name] }
      if (next[name]) {
        // Re-enabling resumes from the current tree head, not a stale cursor.
        controllersRef.current.get(name)?.reset()
      } else {
        setStatus(name, 'idle')
      }
      return next
    })
  }

  function togglePause() {
    setPaused((p) => {
      const next = !p
      if (next) {
        // Reflect the paused state on the dots immediately.
        setStatuses((prev) => {
          const out = { ...prev }
          for (const k of Object.keys(out)) out[k] = 'idle'
          return out
        })
      } else {
        // Resume each log at its current tree head (no backlog replay, no skip).
        for (const c of controllersRef.current.values()) c.reset()
      }
      return next
    })
  }

  // ── Filtering ──────────────────────────────────────────────────────────────────
  const filterRe = useMemo(() => {
    const v = filter.trim()
    if (!v) return null
    try {
      return new RegExp(v, 'i')
    } catch {
      return undefined // invalid pattern
    }
  }, [filter])

  const visible = useMemo(() => {
    if (!filterRe) return certs
    return certs.filter((c) => c.domains.some((d) => filterRe.test(d)))
  }, [certs, filterRe])

  // Logs available to add: usable logs not already monitored.
  const pickerOptions = useMemo(() => {
    const monitored = new Set(logs.map((l) => l.description))
    return allUsable.filter((l) => !monitored.has(l.description))
  }, [allUsable, logs])

  const selected = selectedId ? certs.find((c) => c.id === selectedId) ?? null : null

  return (
    <main className="h-screen flex flex-col bg-slate-950 text-slate-100 overflow-hidden">
      <NavBar wide />

      {/* Page heading */}
      <div className="px-6 pt-5 pb-1">
        <h1 className="text-xl font-bold text-slate-50">Live Certificate Feed</h1>
        <p className="text-sm text-slate-400 mt-1 max-w-3xl">
          Every certificate being appended to the monitored CT logs, in real time. Click any row to
          inspect it — or hit <span className="text-emerald-400">Verify →</span> to run the full SCT
          and Merkle inclusion proof on it.
        </p>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap px-6 py-3 border-b border-slate-800">
        {logs.map((log) => {
          const name = log.description
          const on = enabled[name]
          const st = on ? statuses[name] ?? 'idle' : 'idle'
          return (
            <button
              key={name}
              onClick={() => toggleLog(name)}
              title={on ? 'Click to disable' : 'Click to re-enable (resumes from head)'}
              className={`inline-flex items-center gap-1.5 text-xs rounded-full border px-2.5 py-1 cursor-pointer transition-colors ${
                on
                  ? 'border-slate-700 bg-slate-900 text-slate-300 hover:border-emerald-600'
                  : 'border-slate-800 bg-slate-900/40 text-slate-600 line-through'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${dotClass[st]}`} />
              {name}
              {log.logType === 'tiled' && (
                <span className="text-[9px] uppercase tracking-wide text-sky-400 border border-sky-900 rounded px-1">
                  sunlight
                </span>
              )}
            </button>
          )
        })}

        <LogPicker options={pickerOptions} onAdd={addLog} />

        <span className="text-xs text-slate-500 ml-auto whitespace-nowrap">
          {rate}/s · {total.toLocaleString()} seen
          {skipped > 0 && ` · ${skipped.toLocaleString()} skipped`}
        </span>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter domains (regex)…"
          className={`bg-slate-900 border rounded-lg px-3 py-1.5 text-xs font-mono w-56 text-slate-100 placeholder-slate-600 focus:outline-none ${
            filterRe === undefined
              ? 'border-red-600 focus:border-red-500'
              : 'border-slate-700 focus:border-emerald-600'
          }`}
        />
        <button
          onClick={togglePause}
          className="text-xs border border-slate-700 rounded-lg px-3.5 py-1.5 text-slate-300 hover:border-emerald-600 hover:text-emerald-400 cursor-pointer transition-colors"
        >
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 flex overflow-hidden">
        <div className="flex-1 overflow-y-auto">
          {loadError && (
            <div className="m-6 bg-red-900/20 border border-red-700/50 rounded-xl p-4 text-sm text-red-300">
              {loadError}
            </div>
          )}
          <table className="w-full border-collapse">
            <thead>
              <tr className="text-left">
                {['Time', 'Domain', 'SANs', 'Issuer', 'Log', 'Type', ''].map((h, i) => (
                  <th
                    key={i}
                    className="sticky top-0 bg-slate-950 border-b border-slate-800 px-4 py-2.5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((c) => {
                const primary = c.domains[0] || c.subjectCN || '—'
                const extra = c.domains.length - 1
                const href = verifyHref(c)
                return (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedId(c.id === selectedId ? null : c.id)}
                    className={`group border-b border-slate-900 cursor-pointer transition-colors ${
                      c.id === selectedId ? 'bg-sky-950/40' : 'hover:bg-slate-900/60'
                    }`}
                  >
                    <td className="px-4 py-2 text-xs font-mono text-slate-500 whitespace-nowrap">
                      {fmtTime(c.ts)}
                    </td>
                    <td className="px-4 py-2 font-mono text-emerald-400 whitespace-nowrap">
                      {primary}
                      {extra > 0 && <span className="text-slate-500 text-xs ml-1.5">+{extra}</span>}
                    </td>
                    <td className="px-4 py-2 text-slate-500 text-sm">{c.domains.length}</td>
                    <td className="px-4 py-2 text-slate-400 text-sm max-w-[220px] truncate">
                      {c.issuer || '—'}
                    </td>
                    <td className="px-4 py-2 text-slate-400 text-xs whitespace-nowrap">
                      {c.logName}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          c.isPrecert
                            ? 'text-amber-300 border-amber-700/60 bg-amber-500/10'
                            : 'text-slate-400 border-slate-700'
                        }`}
                      >
                        {c.isPrecert ? 'precert' : 'cert'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      {href && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            router.push(href)
                          }}
                          className="opacity-0 group-hover:opacity-100 text-xs font-semibold text-emerald-400 border border-emerald-700 rounded px-2 py-0.5 hover:bg-emerald-500/10 cursor-pointer transition-opacity"
                        >
                          Verify →
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          {!loadError && certs.length === 0 && (
            <div className="flex items-center justify-center gap-3 text-slate-500 py-20">
              <span className="animate-spin text-xl">◌</span>
              <span className="text-sm font-mono">Connecting to CT logs…</span>
            </div>
          )}
        </div>

        {selected && <FeedDrawer cert={selected} onClose={() => setSelectedId(null)} />}
      </div>
    </main>
  )
}
