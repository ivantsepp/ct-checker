'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { getLogList } from '@/lib/log-list'
import {
  streamLog,
  listUsableLogs,
  FEED_POLL_INTERVAL_MS,
  type FeedCert,
  type LogStreamController,
} from '@/lib/ct-feed'
import { IS_STATIC_BUILD } from '@/lib/transport'

const ROWS = 6

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
  // Seconds until the next poll (static builds only, where polling is slow).
  const [countdown, setCountdown] = useState<number | null>(null)

  // Read inside the long-lived poll loops (avoids stale closures).
  const pausedRef = useRef(false)
  const seenRef = useRef<Set<string>>(new Set())
  const controllersRef = useRef<LogStreamController[]>([])
  const nextPollRef = useRef<Map<string, number>>(new Map())

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
      // Countdown to the soonest scheduled poll (static builds only).
      if (!IS_STATIC_BUILD) return
      if (pausedRef.current) {
        setCountdown(null)
        return
      }
      const times = [...nextPollRef.current.values()]
      setCountdown(
        times.length ? Math.max(0, Math.round((Math.min(...times) - Date.now()) / 1000)) : null,
      )
    }, 1000)

    ;(async () => {
      try {
        const all = await getLogList()
        if (cancelled) return
        // Two RFC 6962 logs (CORS-ordered) are enough for a lively preview
        // without hammering endpoints.
        const selected = listUsableLogs(all)
          .filter((l) => l.logType !== 'tiled')
          .slice(0, 2)
        setLogCount(selected.length)
        for (const log of selected) {
          controllers.push(
            streamLog(log, {
              // pollInterval defaults to a build-aware cadence (slower on static).
              isPaused: () => pausedRef.current,
              onSchedule: (at) => nextPollRef.current.set(log.description, at),
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
        <span className="text-xs text-slate-500 inline-flex items-center gap-1.5 whitespace-nowrap">
          {paused ? (
            <>paused{logCount > 0 ? ` · ${logCount} CT logs` : ''}</>
          ) : IS_STATIC_BUILD && countdown !== null ? (
            <>
              <span className="tabular-nums">
                next poll {countdown === 0 ? 'now…' : `in ${countdown}s`}
              </span>
              <span className="relative h-1 w-10 rounded-full bg-slate-800 overflow-hidden">
                <span
                  className="absolute inset-y-0 left-0 bg-emerald-500/70 transition-[width] duration-1000 ease-linear"
                  style={{
                    width: `${Math.min(100, Math.max(0, (1 - countdown / (FEED_POLL_INTERVAL_MS / 1000)) * 100))}%`,
                  }}
                />
              </span>
              {logCount > 0 ? `· ${logCount} logs` : ''}
            </>
          ) : (
            <>
              {live ? `${rate} certs/sec` : 'connecting'}
              {logCount > 0 ? ` across ${logCount} CT logs` : ''}
            </>
          )}
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
