/**
 * Best-effort issuer fetch via the leaf certificate's Authority Information
 * Access (AIA) extension.
 *
 * SCTs in modern certs are signed over the *precertificate* (RFC 6962 §3.2),
 * so verifying them requires the issuer's SubjectPublicKeyInfo to compute
 * `issuer_key_hash`.  When the user pastes only the leaf cert (no chain),
 * we try to fetch the issuer from the URL in the AIA `caIssuers` access
 * description (1.3.6.1.5.5.7.48.2).
 *
 * Caveats:
 *   - Many CA AIA URLs are plain HTTP (e.g. `http://r13.i.lencr.org/`).
 *     Mixed-content blocking and missing CORS headers will silently fail
 *     these from an HTTPS origin (like GitHub Pages).
 *   - Some CAs serve PKCS#7 bundles instead of single DER.  We only handle
 *     a single DER (`application/pkix-cert`) blob — anything else throws.
 *
 * Callers should swallow exceptions and fall back to telling the user to
 * paste the full chain.
 */

import * as asn1js from 'asn1js'
import { Certificate } from 'pkijs'

const AIA_OID = '1.3.6.1.5.5.7.1.1'
const CA_ISSUERS_OID = '1.3.6.1.5.5.7.48.2'

/**
 * Extract the caIssuers URL from a certificate's AIA extension, or null
 * if no such URL is present.
 */
export function caIssuersUrlFromCert(certDER: Uint8Array): string | null {
  const sliced = certDER.slice()
  const asn1 = asn1js.fromBER(sliced.buffer as ArrayBuffer)
  if (asn1.offset === -1) return null
  const cert = new Certificate({ schema: asn1.result })

  const aiaExt = cert.extensions?.find((e) => e.extnID === AIA_OID)
  // `parsedValue` is populated by pkijs when it recognises the extension OID.
  const parsed = aiaExt?.parsedValue as
    | { accessDescriptions?: Array<{ accessMethod: string; accessLocation: { value?: string } }> }
    | undefined
  if (!parsed?.accessDescriptions) return null

  for (const desc of parsed.accessDescriptions) {
    if (desc.accessMethod === CA_ISSUERS_OID) {
      const url = desc.accessLocation?.value
      if (typeof url === 'string' && url.length > 0) return url
    }
  }
  return null
}

/**
 * Fetch the issuer certificate referenced by the leaf cert's AIA extension.
 * Returns the issuer DER bytes, or throws on any failure (no URL, CORS
 * blocked, non-DER response, etc.).
 */
export async function fetchIssuerFromAIA(certDER: Uint8Array): Promise<Uint8Array> {
  const url = caIssuersUrlFromCert(certDER)
  if (!url) throw new Error('No AIA caIssuers URL in certificate')

  // Browser fetch throws TypeError for both CORS rejection and mixed-content
  // blocking — both are likely failure modes on a static (HTTPS) host.
  const res = await fetch(url, { headers: { Accept: 'application/pkix-cert' } })
  if (!res.ok) throw new Error(`AIA fetch ${url} returned ${res.status}`)

  const buf = new Uint8Array(await res.arrayBuffer())
  // Heuristic: a single DER certificate starts with SEQUENCE (0x30).  PKCS#7
  // bundles also start with 0x30 but we don't try to unwrap them — the user
  // can paste the chain instead.
  if (buf.length < 2 || buf[0] !== 0x30) {
    throw new Error(`AIA fetch ${url} returned non-DER content`)
  }
  return buf
}
