'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { getLogList } from '@/lib/log-list'
import { pollOnce, selectFeedLogs, type FeedCert } from '@/lib/ct-feed'

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
  const rateRef = useRef(0)
  const [rate, setRate] = useState(0)
  const [logCount, setLogCount] = useState(0)

  useEffect(() => {
    let cancelled = false
    const cursors = new Map<string, number | null>()
    const seen = new Set<string>()

    const rateId = setInterval(() => {
      setRate(rateRef.current)
      rateRef.current = 0
    }, 1000)

    async function loop(logUrl: Parameters<typeof pollOnce>[0]) {
      const name = logUrl.description
      while (!cancelled) {
        try {
          const cursor = cursors.has(name) ? cursors.get(name)! : null
          const result = await pollOnce(logUrl, cursor)
          if (cancelled) return
          cursors.set(name, result.cursor)
          const fresh = result.certs.filter((c) => !seen.has(c.id))
          for (const c of fresh) seen.add(c.id)
          if (fresh.length) {
            setLive(true)
            rateRef.current += fresh.length
            setRows((prev) => [...fresh.reverse(), ...prev].slice(0, ROWS))
          }
        } catch {
          // Ignore transient/CORS errors in the preview; the full feed surfaces them.
        }
        await new Promise((r) => setTimeout(r, POLL_INTERVAL))
      }
    }

    ;(async () => {
      try {
        const all = await getLogList()
        if (cancelled) return
        // Two logs are enough for a lively preview without hammering endpoints.
        const selected = selectFeedLogs(all, 6).filter((l) => l.logType !== 'tiled').slice(0, 2)
        setLogCount(selected.length)
        selected.forEach(loop)
      } catch {
        // Leave the ticker in its placeholder state.
      }
    })()

    return () => {
      cancelled = true
      clearInterval(rateId)
    }
  }, [])

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-800">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
          <span
            className={`w-1.5 h-1.5 rounded-full bg-emerald-400 ${live ? 'animate-pulse' : 'opacity-40'}`}
          />
          LIVE
        </span>
        <span className="text-xs text-slate-500">
          {live ? `${rate} certs/sec` : 'connecting'}
          {logCount > 0 && ` across ${logCount} CT logs`}
        </span>
        <Link
          href="/feed"
          className="ml-auto text-xs font-semibold text-emerald-400 hover:text-emerald-300"
        >
          Open full feed →
        </Link>
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
