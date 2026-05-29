import type { ParsedSCT } from '@/types/ct'
import { fromBase64, concat, writeUint16BE, writeUint24BE, writeUint64BE, toHex } from './sct-parser'
import { buildPreCertSignedEntry } from './precert'

function derECDSAToRaw(der: Uint8Array, coordLen: number): Uint8Array {
  let off = 1 // skip SEQUENCE tag
  let seqLen = der[off++]
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f
    seqLen = 0
    for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | der[off++]
  }

  off++ // INTEGER tag for r
  const rLen = der[off++]
  let r = der.slice(off, off + rLen)
  off += rLen

  off++ // INTEGER tag for s
  const sLen = der[off++]
  let s = der.slice(off, off + sLen)

  if (r[0] === 0x00) r = r.slice(1)
  if (s[0] === 0x00) s = s.slice(1)

  const result = new Uint8Array(coordLen * 2)
  result.set(r, coordLen - r.length)
  result.set(s, coordLen * 2 - s.length)
  return result
}

async function importLogKey(spkiB64: string): Promise<{ key: CryptoKey; coordLen: number }> {
  const keyBytes = fromBase64(spkiB64)
  for (const [curve, coordLen] of [['P-256', 32], ['P-384', 48]] as const) {
    try {
      const key = await crypto.subtle.importKey(
        'spki',
        keyBytes.slice(),
        { name: 'ECDSA', namedCurve: curve },
        false,
        ['verify'],
      )
      return { key, coordLen }
    } catch {
      // try next curve
    }
  }
  throw new Error('Cannot import log public key')
}

export function buildX509SignedBlob(sct: ParsedSCT, certDER: Uint8Array): Uint8Array {
  return concat(
    new Uint8Array([0x00, 0x00]),        // version=v1, sig_type=certificate_timestamp
    writeUint64BE(sct.timestamp),
    new Uint8Array([0x00, 0x00]),         // entry_type=x509_entry
    writeUint24BE(certDER.length),
    certDER,
    writeUint16BE(sct.extensions.length),
    sct.extensions,
  )
}

export function buildPrecertSignedBlob(
  sct: ParsedSCT,
  preCertSignedEntry: Uint8Array,
): Uint8Array {
  // signed_entry for precert_entry = PreCert struct (issuer_key_hash || tbs)
  // We need to encode it as the raw bytes in the signed blob
  // RFC 6962 §3.2: entry_type(2) || PreCert
  return concat(
    new Uint8Array([0x00, 0x00]),         // version=v1, sig_type=certificate_timestamp
    writeUint64BE(sct.timestamp),
    new Uint8Array([0x00, 0x01]),         // entry_type=precert_entry
    preCertSignedEntry,                   // issuer_key_hash(32) || uint24(len) || TBS
    writeUint16BE(sct.extensions.length),
    sct.extensions,
  )
}

export type EntryType = 'x509_entry' | 'precert_entry' | 'unknown'

export interface SCTSigVerifyResult {
  valid: boolean
  entryType: EntryType
  signedBlobHex: string
  error?: string
}

export async function verifySCTSignature(
  sct: ParsedSCT,
  certDER: Uint8Array,
  issuerCertDER: Uint8Array | null,
): Promise<SCTSigVerifyResult> {
  if (!sct.log) {
    return { valid: false, entryType: 'unknown', signedBlobHex: '', error: 'Unknown log — cannot verify' }
  }

  let cryptoKey: CryptoKey
  let coordLen: number
  try {
    const imported = await importLogKey(sct.log.key)
    cryptoKey = imported.key
    coordLen = imported.coordLen
  } catch (e) {
    return { valid: false, entryType: 'unknown', signedBlobHex: '', error: String(e) }
  }

  const rawSig = derECDSAToRaw(sct.signature, coordLen)

  // Try precert_entry first (most modern certs)
  if (issuerCertDER) {
    try {
      const preCertEntry = await buildPreCertSignedEntry(certDER, issuerCertDER)
      const blob = buildPrecertSignedBlob(sct, preCertEntry)
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        cryptoKey,
        rawSig.slice(),
        blob.slice(),
      )
      if (valid) {
        return { valid: true, entryType: 'precert_entry', signedBlobHex: toHex(blob) }
      }
    } catch (e) {
      // fall through to x509
    }
  }

  // Fall back to x509_entry (direct submission of final cert)
  const x509Blob = buildX509SignedBlob(sct, certDER)
  try {
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      rawSig.slice(),
      x509Blob.slice(),
    )
    if (valid) return { valid: true, entryType: 'x509_entry', signedBlobHex: toHex(x509Blob) }
    // Neither precert_entry (if attempted) nor x509_entry matched.  The most
    // likely cause for a modern cert is a missing issuer — almost every leaf
    // cert today is logged as a precertificate, and rebuilding that requires
    // the issuer's SPKI for `issuer_key_hash`.
    const hint = issuerCertDER
      ? 'Signature does not match either precert_entry or x509_entry framing.'
      : 'No issuer certificate available, so precert_entry verification was skipped ' +
        'and x509_entry framing did not match. Paste the full PEM chain (leaf + issuer) ' +
        'and try again.'
    return { valid: false, entryType: 'x509_entry', signedBlobHex: toHex(x509Blob), error: hint }
  } catch (e) {
    return { valid: false, entryType: 'unknown', signedBlobHex: toHex(x509Blob), error: String(e) }
  }
}
