import * as asn1js from 'asn1js'
import { Certificate } from 'pkijs'
import type { ParsedCert } from '@/types/ct'

const SCT_OID = '1.3.6.1.4.1.11129.2.4.2'
const CN_OID = '2.5.4.3'

export function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function normalizeCertInput(input: string): Uint8Array {
  input = input.trim()

  if (input.startsWith('-----BEGIN')) {
    return pemToDer(input)
  }

  try {
    const clean = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(clean)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    if (bytes[0] === 0x30) return bytes
  } catch {
    // fall through
  }

  throw new Error('Invalid certificate. Paste a PEM block or base64-encoded DER.')
}

function getStringAttr(typesAndValues: unknown[], oid: string): string {
  for (const tv of typesAndValues as Array<{ type: string; value: unknown }>) {
    if (tv.type === oid) {
      const val = tv.value as { valueBlock?: { value?: string }; value?: string }
      return val?.valueBlock?.value ?? val?.value ?? ''
    }
  }
  return ''
}

function buildDN(typesAndValues: unknown[]): string {
  const parts: string[] = []
  const oidNames: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
  }
  for (const tv of typesAndValues as Array<{ type: string; value: unknown }>) {
    const val = (tv.value as { valueBlock?: { value?: string } })?.valueBlock?.value
    if (val) {
      const name = oidNames[tv.type] ?? tv.type
      parts.push(`${name}=${val}`)
    }
  }
  return parts.join(', ')
}

export function parseCert(derBytes: Uint8Array): ParsedCert {
  // .slice() always returns a Uint8Array backed by a plain ArrayBuffer
  const sliced = derBytes.slice()
  const asn1 = asn1js.fromBER(sliced.buffer as ArrayBuffer)
  if (asn1.offset === -1) throw new Error('Failed to parse certificate ASN.1')

  const cert = new Certificate({ schema: asn1.result })

  const subjectAttrs = cert.subject.typesAndValues
  const issuerAttrs = cert.issuer.typesAndValues

  const subjectCN = getStringAttr(subjectAttrs, CN_OID) || '(no CN)'
  const issuerCN = getStringAttr(issuerAttrs, CN_OID) || '(no CN)'
  const subjectDN = buildDN(subjectAttrs)
  const issuerDN = buildDN(issuerAttrs)

  const notBefore = cert.notBefore.value
  const notAfter = cert.notAfter.value

  const sctExt = cert.extensions?.find((e) => e.extnID === SCT_OID)

  let sctListBytes: Uint8Array | null = null
  if (sctExt) {
    // extnValue OCTET STRING's valueHex = DER of extension value type
    // For CT, the extension value type is OCTET STRING containing TLS bytes
    const rawValue = new Uint8Array(sctExt.extnValue.valueBlock.valueHex)
    try {
      const innerBuf = rawValue.slice().buffer as ArrayBuffer
      const inner = asn1js.fromBER(innerBuf)
      if (inner.offset !== -1 && rawValue[0] === 0x04) {
        sctListBytes = new Uint8Array(
          (inner.result as asn1js.OctetString).valueBlock.valueHex,
        )
      } else {
        sctListBytes = rawValue
      }
    } catch {
      sctListBytes = rawValue
    }
  }

  const serialHex = Array.from(new Uint8Array(cert.serialNumber.valueBlock.valueHex))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')

  return {
    subjectCN,
    issuerCN,
    subjectDN,
    issuerDN,
    notBefore,
    notAfter,
    sctListBytes,
    certDER: derBytes,
    serialNumber: serialHex,
  }
}
