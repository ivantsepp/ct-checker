'use client'

import { useState } from 'react'
import type { SCTVerificationResult } from '@/types/ct'
import { toHex, fromBase64 } from '@/lib/sct-parser'
import { logState } from '@/lib/log-list'
import VerificationStep from './VerificationStep'
import MerklePathViz from './MerklePathViz'
import RawBytes from './RawBytes'
import ApiCallLog from './ApiCallLog'

const HASH_NAMES: Record<number, string> = { 4: 'SHA-256', 5: 'SHA-384', 6: 'SHA-512' }
const SIG_NAMES: Record<number, string> = { 1: 'RSA', 3: 'ECDSA', 7: 'Ed25519' }

interface Props {
  result: SCTVerificationResult
  index: number
  total: number
  certDER: Uint8Array
}

/** Small inline badge indicating which CT protocol was used. */
function ProtocolBadge({ label, title }: { label: string; title: string }) {
  return (
    <span
      title={title}
      className="inline-block font-mono text-[10px] bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded ml-1 leading-none"
    >
      {label}
    </span>
  )
}

/** Render STH and proof-source badges when the API type is known. */
function ProtocolBadges({
  sthApiType,
  proofApiType,
}: {
  sthApiType?: 'rfc6962' | 'sunlight'
  proofApiType?: 'rfc6962' | 'tiles'
}) {
  return (
    <>
      {sthApiType === 'sunlight' && (
        <ProtocolBadge label="Sunlight ✓" title="Tree head obtained from RFC 9162 /checkpoint (Sunlight signed note)" />
      )}
      {sthApiType === 'rfc6962' && (
        <ProtocolBadge label="RFC 6962 STH" title="Tree head obtained from ct/v1/get-sth" />
      )}
      {proofApiType === 'tiles' && (
        <ProtocolBadge label="tile-proof" title="Audit path reconstructed from RFC 9162 hash tiles" />
      )}
    </>
  )
}

export default function SCTCard({ result, index, total }: Props) {
  const { sct } = result
  const log = sct.log
  const state = log ? logState(log) : null
  const [showSigSteps, setShowSigSteps] = useState(false)
  // Sticky selection linking inclusion-path nodes to the tile requests (in the
  // API log) that produced them, keyed by tile identity (see tileKey). Clicking
  // a node or a tile request selects its tiles; clicking the same selection
  // again clears it.
  const [selectedTiles, setSelectedTiles] = useState<Set<string> | null>(null)
  const toggleTiles = (keys: Set<string>) => {
    setSelectedTiles((prev) =>
      prev && prev.size === keys.size && [...keys].every((k) => prev.has(k)) ? null : keys,
    )
  }

  const stateColour =
    state === 'usable' || state === 'qualified'
      ? 'text-emerald-400'
      : state === 'read-only'
        ? 'text-amber-400'
        : state === 'retired'
          ? 'text-slate-500'
          : 'text-red-400'

  const sigStatus = result.signatureValid === null
    ? 'pending'
    : result.signatureValid
      ? 'pass'
      : 'fail'

  const proofStatus =
    result.inclusionProof === null && !result.inclusionError
      ? 'pending'
      : result.inclusionError
        ? 'fail'
        : result.inclusionProof?.verified
          ? 'pass'
          : 'fail'

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-700 bg-slate-800/60">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-mono text-slate-500 mb-1">
              SCT {index + 1} of {total}
            </p>
            <h3 className="text-base font-semibold text-slate-100">
              {log ? log.description : 'Unknown Log'}
            </h3>
            {log && (
              <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-1.5 flex-wrap">
                {log.operator && <span>{log.operator} · </span>}
                <span className={stateColour}>{state}</span>
                {log.logType === 'tiled' && (
                  <span
                    title="Static CT API log (RFC 9162 / Sunlight) — uses checkpoint + tile-based verification"
                    className="font-mono text-[10px] bg-sky-900/60 text-sky-300 border border-sky-700/50 px-1.5 py-0.5 rounded leading-none"
                  >
                    Sunlight
                  </span>
                )}
              </p>
            )}
          </div>
          <div className="text-right shrink-0">
            <p className="text-xs text-slate-400">Timestamp</p>
            <p className="text-xs font-mono text-slate-200">
              {sct.timestampDate.toISOString().replace('T', ' ').replace('Z', ' UTC')}
            </p>
          </div>
        </div>

        {/* SCT raw fields */}
        <div className="mt-3 space-y-2 text-xs font-mono">
          <div>
            <span className="text-slate-500">Log ID (base64): </span>
            <span className="text-slate-300 break-all">{sct.logIdBase64}</span>
          </div>
          <div>
            <span className="text-slate-500">Log ID (hex): </span>
            <span className="text-slate-300 break-all">{sct.logIdHex}</span>
          </div>
          <div>
            <span className="text-slate-500">Algorithm: </span>
            <span className="text-slate-300">
              {SIG_NAMES[sct.sigAlgorithm] ?? `sig(${sct.sigAlgorithm})`} /{' '}
              {HASH_NAMES[sct.hashAlgorithm] ?? `hash(${sct.hashAlgorithm})`}
            </span>
          </div>
          <div>
            <span className="text-slate-500">Extensions: </span>
            {sct.parsedExtensions.leafIndex !== undefined ? (
              <span className="text-slate-300">
                leaf_index ={' '}
                <span className="text-sky-300">
                  {sct.parsedExtensions.leafIndex.toLocaleString()}
                </span>
                {' '}
                <span className="text-slate-500">
                  (0x{sct.parsedExtensions.leafIndex.toString(16)}, uint40 BE — C2SP static-ct-api)
                </span>
              </span>
            ) : sct.extensions.length > 0 ? (
              <span className="text-slate-300 break-all">{toHex(sct.extensions)}</span>
            ) : (
              <span className="text-slate-500">none</span>
            )}
          </div>
          <div>
            <span className="text-slate-500">Signature (hex): </span>
            <span className="text-slate-300 break-all">{toHex(sct.signature)}</span>
          </div>
        </div>
        <RawBytes label="Signature (DER bytes)" hex={toHex(sct.signature)} className="mt-2" />
      </div>

      {/* Verification steps */}
      <div className="p-5 space-y-3">
        {/* Step 1: Signature */}
        <VerificationStep status={sigStatus} title="SCT Signature Verification">
          {sigStatus === 'pass' && (
            <>
              <p>
                Verified ECDSA signature against the log&apos;s public key.
                {result.entryType === 'precert_entry' && (
                  <> Entry type: <span className="font-mono text-xs bg-slate-800 px-1 py-0.5 rounded">precert_entry</span> — signed over pre-cert TBS (SCT extension removed, CT-poison added).</>
                )}
                {result.entryType === 'x509_entry' && (
                  <> Entry type: <span className="font-mono text-xs bg-slate-800 px-1 py-0.5 rounded">x509_entry</span> — signed over the full certificate DER.</>
                )}
              </p>
              {log && (
                <div className="mt-1 font-mono text-xs">
                  <span className="text-slate-500">Log public key (SPKI, hex): </span>
                  <span className="text-slate-300 break-all">{toHex(fromBase64(log.key))}</span>
                </div>
              )}
              {result.signedBlobHex && (
                <RawBytes label="Signed blob (what the log signed)" hex={result.signedBlobHex} />
              )}

              <p className="text-emerald-400 font-semibold mt-1">
                ✓ Signature verified against log public key
              </p>

              {/* ECDSA verification, step by step — collapsible */}
              <button
                onClick={() => setShowSigSteps((o) => !o)}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono mt-1 cursor-pointer"
              >
                <span className={`transition-transform ${showSigSteps ? 'rotate-90' : ''}`}>▶</span>
                ECDSA verification, step by step
              </button>
              {showSigSteps && (
                <div className="mt-1 p-3 bg-slate-900 border border-slate-700 rounded space-y-1.5 font-mono text-xs">
                  {result.digestHex && (
                    <div>
                      <span className="text-slate-500">
                        ① SHA-256(signed blob){'  '}=
                      </span>{' '}
                      <span className="text-amber-300 break-all">{result.digestHex}</span>
                    </div>
                  )}
                  {result.sigRHex && result.sigSHex && (
                    <>
                      <div>
                        <span className="text-slate-500">② signature&nbsp;r{'           '}=</span>{' '}
                        <span className="text-sky-300 break-all">{result.sigRHex}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">{'  '}signature&nbsp;s{'           '}=</span>{' '}
                        <span className="text-sky-300 break-all">{result.sigSHex}</span>
                      </div>
                    </>
                  )}
                  <p className="text-slate-500 leading-relaxed pt-0.5">
                    ③ ECDSA{result.curve ? ` (${result.curve})` : ''} checks that{' '}
                    <span className="text-sky-400">(r, s)</span> is a valid signature over the{' '}
                    <span className="text-amber-400">digest</span>{' '}under the log&apos;s public key.
                    The signature can&apos;t be recomputed from the message (it embeds a secret
                    random nonce), so verification confirms the relation rather than reproducing
                    the bytes.
                  </p>
                </div>
              )}
            </>
          )}
          {sigStatus === 'fail' && (
            <p className="text-red-300">{result.signatureError ?? 'Signature verification failed'}</p>
          )}
          {sigStatus === 'pending' && <p className="text-slate-500">Waiting...</p>}
        </VerificationStep>

        {/* Step 2: Inclusion proof */}
        <VerificationStep status={proofStatus} title="Merkle Inclusion Proof">
          {result.inclusionError && (
            <>
              <p className="text-red-300">{result.inclusionError}</p>
              {result.apiCalls && result.apiCalls.length > 0 && (
                <ApiCallLog calls={result.apiCalls} />
              )}
            </>
          )}
          {result.inclusionProof && (
            <>
              <p className="flex flex-wrap items-center gap-x-1">
                <span>
                  Leaf {result.inclusionProof.leafIndex.toLocaleString()} of{' '}
                  {result.inclusionProof.treeSize.toLocaleString()}{' '}
                  in the log&apos;s Merkle tree.
                </span>
                <ProtocolBadges
                  sthApiType={result.inclusionProof.sthApiType}
                  proofApiType={result.inclusionProof.proofApiType}
                />
              </p>
              <div className="mt-1 font-mono text-xs space-y-0.5">
                <div>
                  <span className="text-slate-500">Leaf hash:{'  '}</span>
                  <span className="text-slate-300 break-all">
                    {toHex(result.inclusionProof.leafHash)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">
                    {result.inclusionProof.sthApiType === 'sunlight'
                      ? 'Checkpoint root:'
                      : 'STH root:       '}
                  </span>
                  <span className="text-slate-300 break-all">
                    {toHex(result.inclusionProof.rootHash)}
                  </span>
                </div>
              </div>
              {result.apiCalls && result.apiCalls.length > 0 && (
                <ApiCallLog
                  calls={result.apiCalls}
                  selected={selectedTiles}
                  onToggle={toggleTiles}
                />
              )}
              <MerklePathViz
                proof={result.inclusionProof}
                selected={selectedTiles}
                onToggle={toggleTiles}
              />
            </>
          )}
          {proofStatus === 'pending' && !result.inclusionError && (
            <p className="text-slate-500">Waiting...</p>
          )}
        </VerificationStep>
      </div>
    </div>
  )
}
