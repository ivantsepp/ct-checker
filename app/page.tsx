'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'

export default function Home() {
  const router = useRouter()
  const [mode, setMode] = useState<'domain' | 'cert'>('domain')
  const [domain, setDomain] = useState('')
  const [cert, setCert] = useState('')
  const [error, setError] = useState('')

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')

    if (mode === 'domain') {
      const d = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
      if (!d) { setError('Enter a domain name'); return }
      router.push(`/verify?domain=${encodeURIComponent(d)}`)
    } else {
      const c = cert.trim()
      if (!c) { setError('Paste a certificate'); return }
      router.push(`/verify?cert=${encodeURIComponent(btoa(c))}`)
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Nav */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center gap-3">
          <span className="text-emerald-400 font-mono text-lg font-bold">CT</span>
          <span className="text-slate-200 font-semibold">Certificate Transparency Verifier</span>
        </div>
      </header>

      <div className="flex-1 flex flex-col items-center justify-center px-4 py-16">
        <div className="w-full max-w-2xl space-y-8">
          {/* Hero */}
          <div className="text-center space-y-3">
            <h1 className="text-3xl font-bold text-slate-50">
              Verify Certificate Transparency
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed max-w-lg mx-auto">
              Certificate Transparency (RFC 6962) requires CAs to submit every certificate to
              public, append-only Merkle logs. This tool parses the embedded SCTs, verifies
              each ECDSA signature against the log&apos;s public key, then fetches and verifies
              the Merkle inclusion proof — step by step.
            </p>
          </div>

          {/* Input card */}
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-xl">
            {/* Mode toggle */}
            <div className="flex gap-1 p-1 bg-slate-800 rounded-lg mb-5">
              <button
                className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  mode === 'domain'
                    ? 'bg-slate-600 text-slate-100 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                onClick={() => setMode('domain')}
              >
                Domain
              </button>
              <button
                className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  mode === 'cert'
                    ? 'bg-slate-600 text-slate-100 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                onClick={() => setMode('cert')}
              >
                Paste Certificate
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              {mode === 'domain' ? (
                <div>
                  <label className="block text-xs text-slate-400 mb-1.5 font-medium">
                    Domain name
                  </label>
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="example.com"
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-colors"
                    autoFocus
                  />
                  <p className="text-xs text-slate-500 mt-1.5">
                    The server will connect to port 443 and fetch the leaf certificate.
                  </p>
                </div>
              ) : (
                <div>
                  <label className="block text-xs text-slate-400 mb-1.5 font-medium">
                    Certificate (PEM or base64 DER)
                  </label>
                  <textarea
                    value={cert}
                    onChange={(e) => setCert(e.target.value)}
                    placeholder={'-----BEGIN CERTIFICATE-----\nMIIE…\n-----END CERTIFICATE-----'}
                    rows={7}
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-slate-100 placeholder-slate-500 font-mono text-xs focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-colors resize-none"
                  />
                </div>
              )}

              {error && (
                <p className="text-red-400 text-sm">{error}</p>
              )}

              <button
                type="submit"
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 px-4 rounded-lg transition-colors text-sm"
              >
                Verify →
              </button>
            </form>
          </div>

          {/* What this checks */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            {[
              {
                icon: '🔏',
                title: 'SCT Signature',
                desc: 'Each SCT contains an ECDSA signature from the log. We verify it against the log\'s published public key.',
              },
              {
                icon: '🌲',
                title: 'Merkle Inclusion',
                desc: 'We compute the leaf hash, fetch the audit path from the log API, and walk it to the root.',
              },
              {
                icon: '📋',
                title: 'Log Directory',
                desc: 'Log IDs are resolved against Google\'s trusted log list (log_list.json v3).',
              },
            ].map(({ icon, title, desc }) => (
              <div key={title} className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
                <p className="text-base mb-1">{icon}</p>
                <p className="font-semibold text-slate-200 mb-1">{title}</p>
                <p className="text-slate-500">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </main>
  )
}
