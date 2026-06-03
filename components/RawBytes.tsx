'use client'

import { useState } from 'react'

interface Props {
  label: string
  hex: string
  className?: string
}

function formatHex(hex: string): string {
  const bytes = hex.match(/.{1,2}/g) ?? []
  const lines: string[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const offset = i.toString(16).padStart(4, '0')
    const hexPart = chunk.map((b) => b.padStart(2, '0')).join(' ').padEnd(47, ' ')
    const asciiPart = chunk
      .map((b) => {
        const code = parseInt(b, 16)
        return code >= 0x20 && code < 0x7f ? String.fromCharCode(code) : '.'
      })
      .join('')
    lines.push(`${offset}  ${hexPart}  ${asciiPart}`)
  }
  return lines.join('\n')
}

export default function RawBytes({ label, hex, className = '' }: Props) {
  const [open, setOpen] = useState(false)
  const byteCount = hex.length / 2

  return (
    <div className={`mt-2 ${className}`}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono cursor-pointer"
      >
        <span className={`transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
        {label}
        <span className="text-slate-600">({byteCount} bytes)</span>
      </button>
      {open && (
        <pre className="mt-2 p-3 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed whitespace-pre [font-variant-ligatures:none]">
          {formatHex(hex)}
        </pre>
      )}
    </div>
  )
}
