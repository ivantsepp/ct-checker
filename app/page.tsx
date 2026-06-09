'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { HAS_PROXY } from '@/lib/transport'
import { stashCertB64 } from '@/lib/cert-handoff'
import NavBar from '@/components/NavBar'
import LiveTicker from '@/components/LiveTicker'

export default function Home() {
  const router = useRouter()
  // Without a proxy backend the browser can't open a TLS socket, so the domain
  // input is hidden — paste-cert is the only way in.
  const [mode, setMode] = useState<'domain' | 'cert'>(HAS_PROXY ? 'domain' : 'cert')
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
      // Large certs (VMC/BIMI with embedded logos) overflow the URL on static
      // hosts; stashCertB64 spills those to sessionStorage and returns a handle.
      router.push(`/verify?cert=${encodeURIComponent(stashCertB64(btoa(c)))}`)
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <NavBar />

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
            {/* Mode toggle — domain mode hidden without a proxy (no TLS socket) */}
            {HAS_PROXY && (
              <div className="flex gap-1 p-1 bg-slate-800 rounded-lg mb-5">
                <button
                  className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors cursor-pointer ${
                    mode === 'domain'
                      ? 'bg-slate-600 text-slate-100 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                  onClick={() => setMode('domain')}
                >
                  Domain
                </button>
                <button
                  className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-colors cursor-pointer ${
                    mode === 'cert'
                      ? 'bg-slate-600 text-slate-100 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                  onClick={() => setMode('cert')}
                >
                  Paste Certificate
                </button>
              </div>
            )}
            {!HAS_PROXY && (
              <div className="mb-5 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-md px-3 py-2 leading-relaxed">
                <p className="mb-1">
                  This is the frontend-only build hosted on GitHub Pages.
                  Domain lookup is disabled (no TLS socket from the browser).
                </p>
                <p className="mb-1">
                  Paste the leaf certificate <em>and</em>{' '}its issuer (as a PEM
                  chain) for full SCT signature verification — without the
                  issuer, the precert hash can&apos;t be reconstructed. The app
                  will try to fetch the issuer automatically from the cert&apos;s
                  AIA extension, but many CA endpoints block this from the browser.
                </p>
                <p>Some CT logs also block direct browser fetches — those will show as CORS errors.</p>
              </div>
            )}

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
                  <label htmlFor="cert" className="block text-xs text-slate-400 mb-1.5 font-medium">
                    Certificate (PEM, PEM chain, or base64 DER)
                  </label>
                  <textarea
                    id="cert"
                    spellCheck={false}
                    value={cert}
                    onChange={(e) => setCert(e.target.value)}
                    placeholder={'-----BEGIN CERTIFICATE-----\nMIIE...  (leaf)\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIF...  (issuer - needed for SCT precert verify)\n-----END CERTIFICATE-----'}
                    rows={9}
                    // Geist Mono ligates runs of hyphens, mangling the "-----BEGIN/END"
                    // PEM markers (and the pasted cert). Disable ligatures here.
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2.5 text-slate-100 placeholder-slate-500 font-mono text-xs [font-variant-ligatures:none] focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-colors resize-none"
                  />
                </div>
              )}

              {error && (
                <p className="text-red-400 text-sm">{error}</p>
              )}

              <button
                type="submit"
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 px-4 rounded-lg transition-colors text-sm cursor-pointer"
              >
                Verify →
              </button>
            </form>
          </div>

          {/* Live feed preview */}
          <LiveTicker />

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
