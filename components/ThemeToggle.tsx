'use client'

import { useSyncExternalStore } from 'react'

/**
 * Dark/light theme toggle. The source of truth is the `light` class on <html>;
 * the inline script in app/layout.tsx applies it before paint (no FOUC) and
 * seeds it from localStorage / prefers-color-scheme. This button flips the
 * class and persists the choice; the rendered icon stays in sync via a
 * MutationObserver on <html>'s class.
 */

function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  return () => observer.disconnect()
}

function getSnapshot(): 'dark' | 'light' {
  return document.documentElement.classList.contains('light') ? 'light' : 'dark'
}

export default function ThemeToggle() {
  // Server render (and pre-hydration) assumes the dark default; the inline
  // head script may have switched to light before paint, which the client
  // snapshot picks up after hydration.
  const theme = useSyncExternalStore(subscribe, getSnapshot, () => 'dark' as const)

  function toggle() {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.classList.toggle('light', next === 'light')
    try {
      localStorage.setItem('theme', next)
    } catch {
      // ignore (private mode etc.)
    }
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      className="ml-auto flex h-8 w-8 items-center justify-center rounded-md border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors text-sm"
    >
      {theme === 'dark' ? '☀' : '☾'}
    </button>
  )
}
