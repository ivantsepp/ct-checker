/**
 * Lightweight X.509 / TBSCertificate field extractor for the live feed.
 *
 * The feed processes dozens of entries per second and must handle precert log
 * entries, which carry a *bare* TBSCertificate (no outer Certificate SEQUENCE)
 * — something pkijs's `Certificate` (used by `lib/cert-parser.ts`) does not
 * parse.  Rather than pay pkijs's per-cert cost or special-case precerts, we
 * use a minimal DER walker that pulls just the handful of fields the feed shows
 * (domains, issuer, subject CN, validity) from either a full Certificate or a
 * raw TBSCertificate.
 *
 * Ported from the standalone CT stream prototype (transparency_certs/index.html).
 */

const UTF8 = new TextDecoder()

// Well-known OIDs (DER content bytes, no tag/length).
const OID_CN = Uint8Array.of(0x55, 0x04, 0x03) // 2.5.4.3  commonName
const OID_O = Uint8Array.of(0x55, 0x04, 0x0a) // 2.5.4.10 organizationName
const OID_SAN = Uint8Array.of(0x55, 0x1d, 0x11) // 2.5.29.17 subjectAltName

export interface FeedCertFields {
  /** dNSName / IP SANs, falling back to the subject CN if no SAN extension. */
  domains: string[]
  /** Subject commonName, if any. */
  subjectCN: string
  /** Issuer organization, falling back to issuer CN. */
  issuer: string
  notBefore: Date | null
  notAfter: Date | null
}

interface TLV {
  tag: number
  v: Uint8Array
  end: number
}

function derLen(b: Uint8Array, p: number): { len: number; p: number } {
  const x = b[p++]
  if (x < 0x80) return { len: x, p }
  let len = 0
  for (let i = x & 0x7f; i--; ) len = (len << 8) | b[p++]
  return { len, p }
}

/** Read one TLV element at position `p`. */
function derTLV(b: Uint8Array, p: number): TLV | null {
  if (p >= b.length) return null
  const tag = b[p++]
  const { len, p: p2 } = derLen(b, p)
  return { tag, v: b.subarray(p2, p2 + len), end: p2 + len }
}

/** Parse all consecutive TLV elements within `b`. */
function derAll(b: Uint8Array): TLV[] {
  const out: TLV[] = []
  let p = 0
  while (p < b.length) {
    const el = derTLV(b, p)
    if (!el) break
    out.push(el)
    p = el.end
  }
  return out
}

function oidEq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

/** Parse an X.500 Name (SEQUENCE OF SET OF {OID, value}) → { cn, o }. */
function parseName(b: Uint8Array): { cn: string; o: string } {
  let cn = ''
  let o = ''
  for (const rdn of derAll(b)) {
    for (const atv of derAll(rdn.v)) {
      const [oidEl, valEl] = derAll(atv.v)
      if (!oidEl || !valEl) continue
      const s = UTF8.decode(valEl.v)
      if (oidEq(oidEl.v, OID_CN)) cn = s
      if (oidEq(oidEl.v, OID_O)) o = s
    }
  }
  return { cn, o }
}

/** Parse UTCTime (0x17) or GeneralizedTime (0x18) → Date. */
function parseTime(tag: number, v: Uint8Array): Date {
  const s = UTF8.decode(v)
  let yr: number
  let rest: string
  if (tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ
    yr = +s.slice(0, 2)
    yr += yr >= 50 ? 1900 : 2000
    rest = s.slice(2)
  } else {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    yr = +s.slice(0, 4)
    rest = s.slice(4)
  }
  return new Date(
    Date.UTC(
      yr,
      +rest.slice(0, 2) - 1,
      +rest.slice(2, 4),
      +rest.slice(4, 6),
      +rest.slice(6, 8),
      +rest.slice(8, 10),
    ),
  )
}

/** Parse a SubjectAltName extension value (SEQUENCE of GeneralName) → string[]. */
function parseSANs(b: Uint8Array): string[] {
  const names: string[] = []
  for (const el of derAll(b)) {
    const t = el.tag & 0x1f
    if (t === 2) {
      // [2] dNSName
      names.push(UTF8.decode(el.v))
    } else if (t === 7 && el.v.length === 4) {
      // [7] iPAddress v4
      names.push(Array.from(el.v).join('.'))
    } else if (t === 7 && el.v.length === 16) {
      // [7] iPAddress v6
      names.push(
        Array.from({ length: 8 }, (_, i) =>
          ((el.v[i * 2] << 8) | el.v[i * 2 + 1]).toString(16),
        ).join(':'),
      )
    }
  }
  return names
}

/** Parse a TBSCertificate buffer into the fields the feed displays. */
function parseTBS(b: Uint8Array): FeedCertFields {
  const els = derAll(b)
  let i = 0

  if (els[i]?.tag === 0xa0) i++ // optional [0] EXPLICIT version
  i++ // serialNumber
  i++ // signature AlgorithmIdentifier
  const issuer = els[i] ? parseName(els[i++].v) : { cn: '', o: '' }

  let notBefore: Date | null = null
  let notAfter: Date | null = null
  if (els[i]) {
    const [a, b2] = derAll(els[i++].v)
    if (a) notBefore = parseTime(a.tag, a.v)
    if (b2) notAfter = parseTime(b2.tag, b2.v)
  }

  const subject = els[i] ? parseName(els[i++].v) : { cn: '', o: '' }
  i++ // subjectPublicKeyInfo

  let domains: string[] = []
  for (; i < els.length; i++) {
    if (els[i].tag !== 0xa3) continue // [3] extensions
    const extSeq = derAll(els[i].v)[0]
    if (!extSeq) continue
    for (const ext of derAll(extSeq.v)) {
      const xs = derAll(ext.v)
      if (!xs.length || !oidEq(xs[0].v, OID_SAN)) continue
      // Structure: OID, [BOOLEAN critical,] OCTET STRING value
      const octet = xs[xs.length - 1]
      const sanSeq = derTLV(octet.v, 0)
      if (sanSeq) domains = parseSANs(sanSeq.v)
    }
  }

  if (!domains.length && subject.cn) domains = [subject.cn]
  return {
    domains,
    subjectCN: subject.cn,
    issuer: issuer.o || issuer.cn,
    notBefore,
    notAfter,
  }
}

/**
 * Extract feed fields from a log entry's certificate bytes.
 *
 * @param der        x509 entry: full Certificate DER.  precert entry: the bare
 *                   TBSCertificate DER.
 * @param isPrecert  true when `der` is a TBSCertificate (precert_entry).
 */
export function parseLeafCertFields(der: Uint8Array, isPrecert: boolean): FeedCertFields | null {
  try {
    if (isPrecert) {
      // precert entries store the TBSCertificate as a full SEQUENCE.
      const tbs = derTLV(der, 0)
      return tbs ? parseTBS(tbs.v) : null
    }
    // x509 entries: Certificate ::= SEQUENCE { tbsCertificate, ... }
    const cert = derTLV(der, 0)
    if (!cert) return null
    const tbs = derTLV(cert.v, 0)
    return tbs ? parseTBS(tbs.v) : null
  } catch {
    return null
  }
}
