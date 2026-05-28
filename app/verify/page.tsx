'use client'

import { useEffect, useState, useCallback, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import type { ParsedCert, ParsedSCT, SCTVerificationResult } from '@/types/ct'
import { normalizeCertInput, parseCert } from '@/lib/cert-parser'
import { parseSCTList } from '@/lib/sct-parser'
import { getLogList, enrichSCT } from '@/lib/log-list'
import { verifySCTSignature } from '@/lib/sct-verifier'
import { getSTH, getProofByHash } from '@/lib/ct-api'
import { buildInclusionProof } from '@/lib/merkle'
import { toHex } from '@/lib/sct-parser'
import SCTCard from '@/components/SCTCard'

type Phase =
  | 'fetching-cert'
  | 'parsing-cert'
  | 'parsing-scts'
  | 'fetching-logs'
  | 'verifying'
  | 'done'
  | 'error'

interface State {
  phase: Phase
  error?: string
  parsedCert?: ParsedCert
  scts: ParsedSCT[]
  results: SCTVerificationResult[]
}

function CertInfoCard({ cert }: { cert: ParsedCert }) {
  const now = Date.now()
  const valid = now >= cert.notBefore.getTime() && now <= cert.notAfter.getTime()
  const expired = now > cert.notAfter.getTime()

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-5">
      <h2 className="text-base font-semibold text-slate-200 mb-4">Certificate</h2>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt className="text-xs text-slate-500 mb-0.5">Subject</dt>
          <dd className="font-mono text-slate-200 text-xs break-all">{cert.subjectDN || cert.subjectCN}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500 mb-0.5">Issuer</dt>
          <dd className="font-mono text-slate-200 text-xs break-all">{cert.issuerDN || cert.issuerCN}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500 mb-0.5">Not Before</dt>
          <dd className="font-mono text-slate-200 text-xs">{cert.notBefore.toISOString()}</dd>
        </div>
        <div>
          <dt className="text-xs text-slate-500 mb-0.5">Not After</dt>
          <dd className="flex items-center gap-2 font-mono text-slate-200 text-xs">
            {cert.notAfter.toISOString()}
            <span
              className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                valid
                  ? 'bg-emerald-500/20 text-emerald-300'
                  : expired
                    ? 'bg-red-500/20 text-red-300'
                    : 'bg-amber-500/20 text-amber-300'
              }`}
            >
              {valid ? 'VALID' : expired ? 'EXPIRED' : 'NOT YET VALID'}
            </span>
          </dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-slate-500 mb-0.5">Serial Number</dt>
          <dd className="font-mono text-slate-400 text-xs break-all">{cert.serialNumber}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-slate-500 mb-0.5">Size</dt>
          <dd className="font-mono text-slate-400 text-xs">{cert.certDER.length} bytes DER</dd>
        </div>
      </dl>
    </div>
  )
}

function PhaseIndicator({ phase, sctCount }: { phase: Phase; sctCount: number }) {
  const steps = [
    { id: 'fetching-cert', label: 'Fetch certificate' },
    { id: 'parsing-cert', label: 'Parse X.509' },
    { id: 'parsing-scts', label: 'Parse SCTs' },
    { id: 'fetching-logs', label: 'Resolve log IDs' },
    { id: 'verifying', label: `Verify ${sctCount > 0 ? sctCount : ''} SCT${sctCount !== 1 ? 's' : ''}` },
    { id: 'done', label: 'Complete' },
  ]

  const currentIdx = steps.findIndex((s) => s.id === phase)

  return (
    <div className="flex items-center gap-1 text-xs font-mono text-slate-500 overflow-x-auto pb-1">
      {steps.map((step, i) => {
        const done = i < currentIdx || phase === 'done'
        const active = step.id === phase && phase !== 'done'
        return (
          <div key={step.id} className="flex items-center gap-1 shrink-0">
            <span
              className={
                done ? 'text-emerald-400' : active ? 'text-amber-300 animate-pulse' : 'text-slate-600'
              }
            >
              {done ? '✓' : active ? '◌' : '○'}
            </span>
            <span className={done ? 'text-slate-400' : active ? 'text-slate-200' : 'text-slate-600'}>
              {step.label}
            </span>
            {i < steps.length - 1 && <span className="text-slate-700 mx-1">→</span>}
          </div>
        )
      })}
    </div>
  )
}

function VerifyInner() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const domainParam = searchParams.get('domain')
  const certParam = searchParams.get('cert')

  const [state, setState] = useState<State>({
    phase: 'fetching-cert',
    scts: [],
    results: [],
  })

  const updateResult = useCallback((index: number, patch: Partial<SCTVerificationResult>) => {
    setState((prev) => {
      const results = [...prev.results]
      results[index] = { ...results[index], ...patch }
      return { ...prev, results }
    })
  }, [])

  useEffect(() => {
    if (!domainParam && !certParam) {
      setState((s) => ({ ...s, phase: 'error', error: 'No domain or certificate provided.' }))
      return
    }

    let cancelled = false

    async function run() {
      try {
        // ── Step 1: Get DER bytes ─────────────────────────────────────────
        setState((s) => ({ ...s, phase: 'fetching-cert' }))
        let certDER: Uint8Array
        let issuerCertDER: Uint8Array | null = null

        if (domainParam) {
          const res = await fetch(`/api/fetch-cert?domain=${encodeURIComponent(domainParam)}`)
          const data = await res.json()
          if (!res.ok || data.error) throw new Error(data.error ?? `HTTP ${res.status}`)
          certDER = Uint8Array.from(atob(data.certDER), (c) => c.charCodeAt(0))
          if (data.issuerDER) {
            issuerCertDER = Uint8Array.from(atob(data.issuerDER), (c) => c.charCodeAt(0))
          }
        } else {
          const raw = atob(certParam!)
          certDER = normalizeCertInput(raw)
        }

        if (cancelled) return

        // ── Step 2: Parse X.509 ───────────────────────────────────────────
        setState((s) => ({ ...s, phase: 'parsing-cert' }))
        const parsed = parseCert(certDER)
        setState((s) => ({ ...s, parsedCert: parsed }))

        if (!parsed.sctListBytes) {
          setState((s) => ({
            ...s,
            phase: 'error',
            error: 'No CT SCT extension found in this certificate (OID 1.3.6.1.4.1.11129.2.4.2). The cert may be a precertificate or was not CT-logged.',
          }))
          return
        }

        if (cancelled) return

        // ── Step 3: Parse SCT list ────────────────────────────────────────
        setState((s) => ({ ...s, phase: 'parsing-scts' }))
        const rawSCTs = parseSCTList(parsed.sctListBytes)
        if (rawSCTs.length === 0) {
          setState((s) => ({ ...s, phase: 'error', error: 'SCT list parsed but contained 0 SCTs.' }))
          return
        }

        // ── Step 4: Resolve log IDs ───────────────────────────────────────
        setState((s) => ({ ...s, phase: 'fetching-logs' }))
        const logs = await getLogList()
        const scts = rawSCTs.map((s) => enrichSCT(s, logs))

        const initialResults: SCTVerificationResult[] = scts.map((sct) => ({
          sct,
          signatureValid: null,
          inclusionProof: null,
        }))

        setState((s) => ({ ...s, scts, results: initialResults, phase: 'verifying' }))

        if (cancelled) return

        // ── Step 5: Verify each SCT in parallel ──────────────────────────
        await Promise.all(
          scts.map(async (sct, i) => {
            // 5a. Signature verification (tries precert_entry first, then x509_entry)
            const sigResult = await verifySCTSignature(sct, certDER, issuerCertDER)
            if (cancelled) return
            updateResult(i, {
              signatureValid: sigResult.valid,
              signedBlobHex: sigResult.signedBlobHex,
              signatureError: sigResult.error,
              entryType: sigResult.entryType,
            })

            // 5b. Inclusion proof
            if (!sct.log) {
              updateResult(i, { inclusionError: 'Log not found in trusted log list — cannot fetch proof' })
              return
            }

            const logUrl = sct.log.url
            const entryType = sigResult.entryType

            try {
              const sth = await getSTH(logUrl)
              if (cancelled) return

              const lHash = await (await import('@/lib/merkle')).computeLeafHash(
                sct, certDER, entryType, issuerCertDER,
              )
              if (cancelled) return

              const proof = await getProofByHash(
                logUrl,
                lHash,
                sth.treeSize,
                sct.timestamp,
                sct.parsedExtensions.leafIndex,
              )
              if (cancelled) return

              const inclusion = await buildInclusionProof(
                sct,
                certDER,
                entryType,
                issuerCertDER,
                proof.leafIndex,
                sth.treeSize,
                proof.auditPath,
                sth.sha256RootHash,
                sth.apiType,
                proof.proofApiType,
              )
              if (cancelled) return

              updateResult(i, { inclusionProof: inclusion })
            } catch (e) {
              if (!cancelled) {
                updateResult(i, { inclusionError: String(e) })
              }
            }
          }),
        )

        if (!cancelled) setState((s) => ({ ...s, phase: 'done' }))
      } catch (e) {
        if (!cancelled) {
          setState((s) => ({ ...s, phase: 'error', error: String(e) }))
        }
      }
    }

    run()
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domainParam, certParam])

  const title = domainParam ?? 'Pasted certificate'

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      {/* Nav */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center gap-3">
          <button
            onClick={() => router.push('/')}
            className="text-slate-400 hover:text-slate-200 transition-colors text-sm font-mono"
          >
            ← back
          </button>
          <span className="text-slate-600">|</span>
          <span className="text-emerald-400 font-mono text-lg font-bold">CT</span>
          <span className="text-slate-400 font-mono text-sm truncate max-w-sm">{title}</span>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">
        {/* Progress */}
        <PhaseIndicator phase={state.phase} sctCount={state.scts.length} />

        {/* Error state */}
        {state.phase === 'error' && (
          <div className="bg-red-900/20 border border-red-700/50 rounded-xl p-5">
            <p className="text-red-300 font-semibold mb-1">Verification failed</p>
            <p className="text-red-400 text-sm font-mono">{state.error}</p>
          </div>
        )}

        {/* Certificate info */}
        {state.parsedCert && <CertInfoCard cert={state.parsedCert} />}

        {/* SCT summary strip */}
        {state.scts.length > 0 && (
          <div className="bg-slate-900/60 border border-slate-700 rounded-xl p-4">
            <p className="text-xs text-slate-500 mb-3">
              Found <span className="text-slate-200 font-semibold">{state.scts.length}</span>{' '}
              Signed Certificate Timestamp{state.scts.length !== 1 ? 's' : ''} embedded in cert extension
              OID <span className="font-mono">1.3.6.1.4.1.11129.2.4.2</span>
            </p>
            <div className="flex flex-wrap gap-2">
              {state.scts.map((sct, i) => (
                <span
                  key={i}
                  className="text-xs font-mono bg-slate-800 border border-slate-700 rounded px-2.5 py-1 text-slate-300"
                >
                  {sct.log?.description ?? `Unknown (${toHex(sct.logId).slice(0, 12)}…)`}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Per-SCT cards */}
        {state.results.map((result, i) => (
          <SCTCard
            key={i}
            result={result}
            index={i}
            total={state.results.length}
            certDER={state.parsedCert?.certDER ?? new Uint8Array()}
          />
        ))}

        {/* Loading placeholders while fetching cert */}
        {(state.phase === 'fetching-cert' || state.phase === 'parsing-cert' || state.phase === 'parsing-scts' || state.phase === 'fetching-logs') && (
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-8 flex items-center justify-center gap-3 text-slate-500">
            <span className="animate-spin text-xl">◌</span>
            <span className="text-sm font-mono">
              {state.phase === 'fetching-cert' && 'Connecting to server…'}
              {state.phase === 'parsing-cert' && 'Parsing X.509 certificate…'}
              {state.phase === 'parsing-scts' && 'Parsing SCT list…'}
              {state.phase === 'fetching-logs' && 'Fetching CT log directory…'}
            </span>
          </div>
        )}

        {/* Done summary */}
        {state.phase === 'done' && state.results.length > 0 && (
          <div className="border border-slate-700 rounded-xl p-4 text-sm text-slate-400">
            <p className="font-semibold text-slate-200 mb-1">Summary</p>
            <ul className="space-y-1">
              {state.results.map((r, i) => {
                const logName = r.sct.log?.description ?? 'Unknown log'
                const sigOk = r.signatureValid === true
                const proofOk = r.inclusionProof?.verified === true
                return (
                  <li key={i} className="flex items-center gap-2 font-mono text-xs">
                    <span className={sigOk && proofOk ? 'text-emerald-400' : 'text-red-400'}>
                      {sigOk && proofOk ? '✓' : '✗'}
                    </span>
                    <span className="text-slate-300">{logName}</span>
                    <span className="text-slate-600">—</span>
                    <span className={sigOk ? 'text-emerald-400' : 'text-red-400'}>
                      sig: {sigOk ? 'ok' : 'FAIL'}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className={proofOk ? 'text-emerald-400' : r.inclusionError ? 'text-red-400' : 'text-amber-400'}>
                      inclusion:{' '}
                      {proofOk ? 'ok' : r.inclusionError ? 'FAIL' : '?'}
                    </span>
                  </li>
                )
              })}
            </ul>
          </div>
        )}
      </div>
    </main>
  )
}

export default function VerifyPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 font-mono">
          Loading…
        </div>
      }
    >
      <VerifyInner />
    </Suspense>
  )
}
