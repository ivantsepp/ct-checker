'use client'

import Link from 'next/link'
import type { FeedCert } from '@/lib/ct-feed'
import { verifyHref } from '@/lib/ct-feed'

function fmtDate(d: Date | null): string {
  return d ? d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—'
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-3">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-0.5">{label}</div>
      <div className="text-sm break-all text-slate-200">{children}</div>
    </div>
  )
}

/** Slide-in detail panel for a selected feed certificate. */
export default function FeedDrawer({ cert, onClose }: { cert: FeedCert; onClose: () => void }) {
  const href = verifyHref(cert)

  return (
    <aside className="w-[360px] shrink-0 border-l border-slate-800 bg-slate-900 overflow-y-auto">
      <div className="p-5">
        <h2 className="flex items-center justify-between text-sm font-semibold text-emerald-400 mb-4">
          Certificate detail
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-slate-500 hover:text-slate-200 cursor-pointer text-base leading-none"
          >
            ✕
          </button>
        </h2>

        <Field label="Log">{cert.logName}</Field>
        <Field label="Index">
          <span className="font-mono">#{cert.index.toLocaleString()}</span>
        </Field>
        <Field label="Type">{cert.isPrecert ? 'Precertificate' : 'Certificate'}</Field>
        <Field label="Timestamp">
          <span className="font-mono">{fmtDate(new Date(cert.ts))}</span>
        </Field>
        <Field label="Subject CN">{cert.subjectCN || '—'}</Field>
        <Field label="Issuer">{cert.issuer || '—'}</Field>
        <Field label="Not Before">
          <span className="font-mono">{fmtDate(cert.notBefore)}</span>
        </Field>
        <Field label="Not After">
          <span className="font-mono">{fmtDate(cert.notAfter)}</span>
        </Field>
        <Field label={`Domains (${cert.domains.length})`}>
          <div className="flex flex-col gap-1">
            {cert.domains.map((d, i) => (
              <span key={i} className="font-mono text-xs text-emerald-400">
                {d}
              </span>
            ))}
          </div>
        </Field>

        {href ? (
          <Link
            href={href}
            className="block text-center mt-4 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg text-sm transition-colors"
          >
            Verify this certificate →
          </Link>
        ) : (
          <div className="mt-4 text-xs text-slate-500 bg-slate-800/60 border border-slate-700 rounded-lg p-3 leading-relaxed">
            This is a <span className="text-amber-300">precertificate</span> log entry — a bare
            TBSCertificate with no embedded SCTs, so it can&apos;t be run through the verifier.
            Verification works on the final (x509) certificate.
          </div>
        )}
      </div>
    </aside>
  )
}
