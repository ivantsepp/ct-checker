/**
 * Pre-certificate reconstruction for CT v1 (RFC 6962 §3.2) verification.
 *
 * CAs submit pre-certificates (with a CT-poison extension) to logs. The log
 * stores a PreCert struct that contains the TBS cert with BOTH the SCT list
 * extension AND the CT poison extension removed (RFC 6962 §3.2: "the Poison
 * Extension MUST be removed from the TBSCertificate before hashing").
 *
 * So the TBS in the log = final cert TBS minus SCT list extension.
 * No poison extension needs to be added back.
 */

import { readTLV, encodeTLV } from './asn1-utils'
import { concat } from './sct-parser'

// OID value bytes (without tag/length) for 1.3.6.1.4.1.11129.2.4.2 (SCT list)
const SCT_OID_VALUE = new Uint8Array([
  0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
])

function isSCTExtension(extBytes: Uint8Array): boolean {
  if (extBytes[0] !== 0x30) return false
  const seqTLV = readTLV(extBytes, 0)
  // First child should be OID
  const oidTLV = readTLV(extBytes, seqTLV.valueStart)
  if (oidTLV.tag !== 0x06) return false
  if (oidTLV.len !== SCT_OID_VALUE.length) return false
  return SCT_OID_VALUE.every((b, i) => extBytes[oidTLV.valueStart + i] === b)
}

function extractTBSFromCert(certDER: Uint8Array): { tbs: Uint8Array; tbsOffset: number } {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)
  // Return the full TBS TLV (tag + length + value)
  return {
    tbs: certDER.slice(certTLV.valueStart, tbsTLV.end),
    tbsOffset: certTLV.valueStart,
  }
}

function extractTBSContent(certDER: Uint8Array): { content: Uint8Array; extA3Offset: number } {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)
  const content = certDER.slice(tbsTLV.valueStart, tbsTLV.end)

  // Find [3] EXPLICIT extensions tag (0xa3)
  let extA3Offset = -1
  walkChildren(certDER, tbsTLV, (_tlv, off) => {
    if (certDER[off] === 0xa3) {
      extA3Offset = off - tbsTLV.valueStart // relative to tbsContent
      return true
    }
  })

  return { content, extA3Offset }
}

/**
 * Reconstruct the pre-cert TBS from the final certificate DER.
 * This produces the TBS bytes that were submitted to CT logs.
 */
export function buildPrecertTBS(certDER: Uint8Array): Uint8Array {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)
  const tbsContent = certDER.slice(tbsTLV.valueStart, tbsTLV.end)

  // Find the [3] EXPLICIT container for extensions
  let extA3Offset = -1
  let off = 0
  while (off < tbsContent.length) {
    const tlv = readTLV(tbsContent, off)
    if (tlv.tag === 0xa3) {
      extA3Offset = off
      break
    }
    off = tlv.end
  }

  if (extA3Offset === -1) {
    // No extensions: just encode TBS as-is (treat as x509 entry)
    return certDER.slice(certTLV.valueStart, tbsTLV.end)
  }

  const a3TLV = readTLV(tbsContent, extA3Offset)
  const seqTLV = readTLV(tbsContent, a3TLV.valueStart)

  // Collect extensions, skipping SCT list extension
  const kept: Uint8Array[] = []
  let eOff = seqTLV.valueStart
  while (eOff < seqTLV.end) {
    const eTLV = readTLV(tbsContent, eOff)
    const extBytes = tbsContent.slice(eOff, eTLV.end)
    if (!isSCTExtension(extBytes)) kept.push(extBytes)
    eOff = eTLV.end
  }

  // Re-encode: SEQUENCE OF Extensions → [3] EXPLICIT → TBS
  const newSeq = encodeTLV(0x30, concat(...kept))
  const newA3 = encodeTLV(0xa3, newSeq)
  const tbsBefore = tbsContent.slice(0, extA3Offset)
  return encodeTLV(0x30, concat(tbsBefore, newA3))
}

/**
 * Extract the SubjectPublicKeyInfo DER bytes from a certificate.
 * Used to compute the issuer_key_hash in the PreCert structure.
 */
export function extractSPKI(certDER: Uint8Array): Uint8Array {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)

  // Walk TBS elements; SPKI is after version?, serial, sigAlg, issuer, validity, subject
  let offset = tbsTLV.valueStart
  let seqCount = 0 // count non-tagged SEQUENCEs

  while (offset < tbsTLV.end) {
    const tlv = readTLV(certDER, offset)
    if (tlv.tag === 0xa0) {
      // [0] EXPLICIT version — skip without incrementing seqCount
      offset = tlv.end
      continue
    }
    if (tlv.tag === 0x02) {
      // INTEGER serialNumber
      offset = tlv.end
      continue
    }
    if (tlv.tag === 0x30) {
      seqCount++
      // seqCount 1=sigAlg, 2=issuer, 3=validity, 4=subject, 5=SPKI
      if (seqCount === 5) {
        return certDER.slice(offset, tlv.end)
      }
      offset = tlv.end
      continue
    }
    // Any other tag — break (shouldn't happen before SPKI in a valid cert)
    break
  }

  throw new Error('SubjectPublicKeyInfo not found in certificate TBS')
}

/**
 * Build the PreCert signed_entry structure (RFC 6962 §3.2):
 *   issuer_key_hash (32 bytes) || uint24 tbs_len || pre-cert TBS bytes
 */
export async function buildPreCertSignedEntry(
  certDER: Uint8Array,
  issuerCertDER: Uint8Array,
): Promise<Uint8Array> {
  const issuerSPKI = extractSPKI(issuerCertDER)
  const issuerKeyHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', issuerSPKI.slice()),
  )
  const precertTBS = buildPrecertTBS(certDER)

  // PreCert = issuer_key_hash || uint24(len) || tbs_certificate
  const lenBytes = new Uint8Array([
    (precertTBS.length >> 16) & 0xff,
    (precertTBS.length >> 8) & 0xff,
    precertTBS.length & 0xff,
  ])
  return concat(issuerKeyHash, lenBytes, precertTBS)
}
