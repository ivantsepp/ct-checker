'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { getLogList } from '@/lib/log-list'
import { streamLog, selectFeedLogs, type FeedCert, type LogStreamController } from '@/lib/ct-feed'

const ROWS = 6
const POLL_INTERVAL = 5000

function fmtTime(ts: number): string {
  return new Date(ts).toISOString().slice(11, 19) // HH:MM:SS
}

/**
 * Compact live preview of the CT feed for the landing page.  Polls a couple of
 * fast logs and shows the most recent entries; links to the full `/feed` page.
 * Self-contained and stops cleanly on unmount.
 */
export default function LiveTicker() {
  const [rows, setRows] = useState<FeedCert[]>([])
  const [live, setLive] = useState(false)
  const [paused, setPaused] = useState(false)
  const rateRef = useRef(0)
  const [rate, setRate] = useState(0)
  const [logCount, setLogCount] = useState(0)

  // Read inside the long-lived poll loops (avoids stale closures).
  const pausedRef = useRef(false)
  const seenRef = useRef<Set<string>>(new Set())
  const controllersRef = useRef<LogStreamController[]>([])

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    let cancelled = false
    const controllers = controllersRef.current
    const seen = seenRef.current

    const rateId = setInterval(() => {
      setRate(rateRef.current)
      rateRef.current = 0
    }, 1000)

    ;(async () => {
      try {
        const all = await getLogList()
        if (cancelled) return
        // Two logs are enough for a lively preview without hammering endpoints.
        const selected = selectFeedLogs(all, 6).filter((l) => l.logType !== 'tiled').slice(0, 2)
        setLogCount(selected.length)
        for (const log of selected) {
          controllers.push(
            streamLog(log, {
              pollInterval: POLL_INTERVAL,
              isPaused: () => pausedRef.current,
              onCerts: (certs) => {
                const fresh = certs.filter((c) => !seen.has(c.id))
                for (const c of fresh) seen.add(c.id)
                if (!fresh.length) return
                setLive(true)
                rateRef.current += fresh.length
                setRows((prev) => [...fresh.reverse(), ...prev].slice(0, ROWS))
              },
            }),
          )
        }
      } catch {
        // Leave the ticker in its placeholder state.
      }
    })()

    return () => {
      cancelled = true
      clearInterval(rateId)
      for (const c of controllers) c.stop()
      controllers.length = 0
    }
  }, [])

  function togglePause() {
    setPaused((p) => {
      const next = !p
      if (next) setRate(0)
      // Resume each log at its current tree head so a long pause doesn't replay a backlog.
      else for (const c of controllersRef.current) c.reset()
      return next
    })
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-800">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
          <span
            className={`w-1.5 h-1.5 rounded-full bg-emerald-400 ${
              live && !paused ? 'animate-pulse' : 'opacity-40'
            }`}
          />
          LIVE
        </span>
        <span className="text-xs text-slate-500">
          {paused ? 'paused' : live ? `${rate} certs/sec` : 'connecting'}
          {logCount > 0 && ` across ${logCount} CT logs`}
        </span>
        <div className="ml-auto flex items-center gap-3">
          <button
            onClick={togglePause}
            className="text-xs font-medium text-slate-400 hover:text-emerald-400 cursor-pointer transition-colors"
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <Link
            href="/feed"
            className="text-xs font-semibold text-emerald-400 hover:text-emerald-300"
          >
            Open full feed →
          </Link>
        </div>
      </div>
      <div className="divide-y divide-slate-900">
        {rows.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-slate-600 font-mono">
            Waiting for certificates…
          </div>
        ) : (
          rows.map((c) => (
            <div
              key={c.id}
              className="grid grid-cols-[78px_1fr_auto] gap-3 items-center px-4 py-2 text-sm"
            >
              <span className="text-[11px] text-slate-500 font-mono">{fmtTime(c.ts)}</span>
              <span className="text-emerald-400 font-mono truncate">
                {c.domains[0] || c.subjectCN || '—'}
              </span>
              <span className="text-[11px] text-slate-500">{c.logName}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
