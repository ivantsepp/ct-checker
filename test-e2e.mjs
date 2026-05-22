/**
 * End-to-end smoke test: fetch google.com cert, parse SCTs,
 * verify signatures, and verify Merkle inclusion proofs.
 * Run with: node test-e2e.mjs
 */

import * as tls from 'tls'
import * as asn1js from 'asn1js'
import { Certificate } from 'pkijs'

const BASE = 'http://localhost:3000'
const DOMAIN = 'google.com'

// ── helpers ──────────────────────────────────────────────────────────────────

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function fromBase64(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(bin, c => c.charCodeAt(0))
}

function readU16(d, o) { return (d[o] << 8) | d[o + 1] }
function readU64(d, o) {
  let r = 0n
  for (let i = 0; i < 8; i++) r = (r << 8n) | BigInt(d[o + i])
  return r
}
function writeU16(v) { return new Uint8Array([(v >> 8) & 0xff, v & 0xff]) }
function writeU24(v) { return new Uint8Array([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]) }
function writeU64(v) {
  const b = new Uint8Array(8)
  let x = v
  for (let i = 7; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n }
  return b
}
function concat(...arrays) {
  const t = arrays.reduce((n, a) => n + a.length, 0)
  const r = new Uint8Array(t)
  let off = 0; for (const a of arrays) { r.set(a, off); off += a.length }
  return r
}

// ── Step 1: fetch cert from API ───────────────────────────────────────────────

console.log(`\n[1] Fetching certificate for ${DOMAIN}...`)
const certRes = await fetch(`${BASE}/api/fetch-cert?domain=${DOMAIN}`)
const certData = await certRes.json()
if (certData.error) throw new Error(certData.error)
const certDER = fromBase64(certData.certDER)
const issuerDER = certData.issuerDER ? fromBase64(certData.issuerDER) : null
console.log(`    ✓ Got ${certDER.length}-byte DER, issuer: ${issuerDER ? issuerDER.length + ' bytes' : 'not provided'}`)

// ── Step 2: parse X.509 + extract SCT list ────────────────────────────────────

console.log('\n[2] Parsing X.509...')
const asn1 = asn1js.fromBER(certDER.slice().buffer)
if (asn1.offset === -1) throw new Error('ASN.1 parse failed')
const cert = new Certificate({ schema: asn1.result })

const SCT_OID = '1.3.6.1.4.1.11129.2.4.2'
const sctExt = cert.extensions?.find(e => e.extnID === SCT_OID)
if (!sctExt) throw new Error('No SCT extension found')

const rawValue = new Uint8Array(sctExt.extnValue.valueBlock.valueHex)
const inner = asn1js.fromBER(rawValue.slice().buffer)
const sctListBytes = rawValue[0] === 0x04
  ? new Uint8Array(inner.result.valueBlock.valueHex)
  : rawValue

const subjectCN = cert.subject.typesAndValues
  .find(tv => tv.type === '2.5.4.3')?.value?.valueBlock?.value ?? '(no CN)'
console.log(`    ✓ Subject CN: ${subjectCN}`)
console.log(`    ✓ SCT list: ${sctListBytes.length} bytes`)

// ── Step 3: parse SCT list ────────────────────────────────────────────────────

console.log('\n[3] Parsing SCTs...')
function parseSCTs(raw) {
  const listLen = readU16(raw, 0)
  const scts = []
  let off = 2
  while (off < 2 + listLen) {
    const sctLen = readU16(raw, off); off += 2
    if (!sctLen) break
    const bytes = raw.slice(off, off + sctLen); off += sctLen
    let p = 0
    const version = bytes[p++]
    const logId = bytes.slice(p, p + 32); p += 32
    const timestamp = readU64(bytes, p); p += 8
    const extLen = readU16(bytes, p); p += 2
    const extensions = bytes.slice(p, p + extLen); p += extLen
    const hashAlg = bytes[p++], sigAlg = bytes[p++]
    const sigLen = readU16(bytes, p); p += 2
    const signature = bytes.slice(p, p + sigLen)
    scts.push({ version, logId, timestamp, extensions, hashAlg, sigAlg, signature })
  }
  return scts
}

const scts = parseSCTs(sctListBytes)
console.log(`    ✓ Parsed ${scts.length} SCT(s)`)

// ── Step 4: resolve log IDs ───────────────────────────────────────────────────

console.log('\n[4] Fetching log list...')
const logsRes = await fetch(`${BASE}/api/log-list`)
const logsData = await logsRes.json()
const logs = logsData.logs
console.log(`    ✓ Loaded ${logs.length} logs`)

function findLog(logId) {
  const needle = btoa(String.fromCharCode(...logId))
  return logs.find(l => l.logId === needle) ?? null
}

for (const sct of scts) {
  sct.log = findLog(sct.logId)
  console.log(`    SCT: ${sct.log?.description ?? 'UNKNOWN LOG'} — ts ${new Date(Number(sct.timestamp)).toISOString()}`)
}

// ── Step 5: verify signatures ─────────────────────────────────────────────────

console.log('\n[5] Verifying SCT signatures...')

function readTLV(data, offset) {
  const tag = data[offset]
  let p = offset + 1, len
  if (data[p] & 0x80) { const n = data[p] & 0x7f; p++; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | data[p++] }
  else len = data[p++]
  return { tag, len, valueStart: p, end: p + len }
}

function encodeTLV(tag, value) {
  const len = value.length
  let lenEnc
  if (len < 128) lenEnc = [len]
  else if (len < 256) lenEnc = [0x81, len]
  else lenEnc = [0x82, (len >> 8) & 0xff, len & 0xff]
  const r = new Uint8Array(1 + lenEnc.length + len)
  r[0] = tag; r.set(lenEnc, 1); r.set(value, 1 + lenEnc.length)
  return r
}

const SCT_OID_VALUE = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02])
const CT_POISON_EXT = new Uint8Array([0x30,0x11,0x06,0x09,0x2b,0x06,0x01,0x04,0x01,0xd6,0x79,0x02,0x04,0x03,0x01,0x01,0xff,0x04,0x02,0x05,0x00])

function isSCTExt(extBytes) {
  if (extBytes[0] !== 0x30) return false
  const seq = readTLV(extBytes, 0)
  const oid = readTLV(extBytes, seq.valueStart)
  if (oid.tag !== 0x06 || oid.len !== SCT_OID_VALUE.length) return false
  return SCT_OID_VALUE.every((b, i) => extBytes[oid.valueStart + i] === b)
}

function buildPrecertTBS(certDER) {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)
  const tbs = certDER.slice(tbsTLV.valueStart, tbsTLV.end)
  let extA3Off = -1, off = 0
  while (off < tbs.length) {
    const t = readTLV(tbs, off)
    if (t.tag === 0xa3) { extA3Off = off; break }
    off = t.end
  }
  if (extA3Off === -1) return certDER.slice(certTLV.valueStart, tbsTLV.end)
  const a3 = readTLV(tbs, extA3Off)
  const seq = readTLV(tbs, a3.valueStart)
  const kept = []; let eOff = seq.valueStart
  while (eOff < seq.end) {
    const e = readTLV(tbs, eOff)
    const extBytes = tbs.slice(eOff, e.end)
    if (!isSCTExt(extBytes)) kept.push(extBytes)
    eOff = e.end
  }
  const newSeq = encodeTLV(0x30, concat(...kept))
  const newA3 = encodeTLV(0xa3, newSeq)
  return encodeTLV(0x30, concat(tbs.slice(0, extA3Off), newA3))
}

function extractSPKI(certDER) {
  const certTLV = readTLV(certDER, 0)
  const tbsTLV = readTLV(certDER, certTLV.valueStart)
  let off = tbsTLV.valueStart, seqCount = 0
  while (off < tbsTLV.end) {
    const t = readTLV(certDER, off)
    if (t.tag === 0xa0 || t.tag === 0x02) { off = t.end; continue }
    if (t.tag === 0x30) {
      seqCount++
      if (seqCount === 5) return certDER.slice(off, t.end)
      off = t.end; continue
    }
    break
  }
  throw new Error('SPKI not found')
}

function derECDSAToRaw(der, coordLen) {
  let off = 1
  let seqLen = der[off++]
  if (seqLen & 0x80) { const n = seqLen & 0x7f; seqLen = 0; for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | der[off++] }
  off++; const rLen = der[off++]; let r = der.slice(off, off + rLen); off += rLen
  off++; const sLen = der[off++]; let s = der.slice(off, off + sLen)
  if (r[0] === 0) r = r.slice(1); if (s[0] === 0) s = s.slice(1)
  const result = new Uint8Array(coordLen * 2)
  result.set(r, coordLen - r.length); result.set(s, coordLen * 2 - s.length)
  return result
}

async function tryVerify(sct, blob, key, coordLen) {
  const rawSig = derECDSAToRaw(sct.signature, coordLen)
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig.slice(), blob.slice())
}

const sctEntryTypes = []

for (let i = 0; i < scts.length; i++) {
  const sct = scts[i]
  if (!sct.log) { console.log(`    SCT ${i + 1}: SKIP (unknown log)`); sctEntryTypes.push('unknown'); continue }

  const keyBytes = fromBase64(sct.log.key)
  let key, coordLen
  for (const [curve, cl] of [['P-256', 32], ['P-384', 48]]) {
    try { key = await crypto.subtle.importKey('spki', keyBytes.slice(), { name: 'ECDSA', namedCurve: curve }, false, ['verify']); coordLen = cl; break } catch {}
  }
  if (!key) { console.log(`    SCT ${i + 1}: FAIL (cannot import key)`); sctEntryTypes.push('unknown'); continue }

  // Try precert_entry first
  let valid = false, entryType = 'unknown'
  if (issuerDER) {
    try {
      const issuerSPKI = extractSPKI(issuerDER)
      const issuerKeyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', issuerSPKI.slice()))
      const precertTBS = buildPrecertTBS(certDER)
      const lenBytes = new Uint8Array([(precertTBS.length >> 16) & 0xff, (precertTBS.length >> 8) & 0xff, precertTBS.length & 0xff])
      const preCertEntry = concat(issuerKeyHash, lenBytes, precertTBS)
      const blob = concat(new Uint8Array([0x00, 0x00]), writeU64(sct.timestamp), new Uint8Array([0x00, 0x01]), preCertEntry, writeU16(sct.extensions.length), sct.extensions)
      valid = await tryVerify(sct, blob, key, coordLen)
      if (valid) entryType = 'precert_entry'
    } catch(e) { console.log(`      precert attempt error: ${e.message}`) }
  }
  if (!valid) {
    const blob = concat(new Uint8Array([0x00, 0x00]), writeU64(sct.timestamp), new Uint8Array([0x00, 0x00]), writeU24(certDER.length), certDER, writeU16(sct.extensions.length), sct.extensions)
    valid = await tryVerify(sct, blob, key, coordLen)
    if (valid) entryType = 'x509_entry'
  }
  sctEntryTypes.push(entryType)
  console.log(`    SCT ${i + 1} (${sct.log.description}): signature ${valid ? '✓ VALID' : '✗ INVALID'} [${entryType}]`)
}

// ── Step 6: inclusion proofs ──────────────────────────────────────────────────

console.log('\n[6] Verifying Merkle inclusion proofs...')

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data.slice()))
}

async function leafHash(sct, certDER) {
  const leaf = concat(
    new Uint8Array([0x00, 0x00]),
    writeU64(sct.timestamp),
    new Uint8Array([0x00, 0x00]),
    writeU24(certDER.length),
    certDER,
    writeU16(sct.extensions.length),
    sct.extensions,
  )
  return sha256(concat(new Uint8Array([0x00]), leaf))
}

for (let i = 0; i < scts.length; i++) {
  const sct = scts[i]
  if (!sct.log) { console.log(`    SCT ${i + 1}: SKIP (unknown log)`); continue }

  try {
    const sthRes = await fetch(`${BASE}/api/ct-proxy?logUrl=${encodeURIComponent(sct.log.url)}&endpoint=ct/v1/get-sth`)
    const sth = await sthRes.json()
    if (sth.error) throw new Error(sth.error)

    // Use the correct entry type for the leaf hash
    let lHash
    const entryType = sctEntryTypes[i]
    if (entryType === 'precert_entry' && issuerDER) {
      const issuerSPKI = extractSPKI(issuerDER)
      const issuerKeyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', issuerSPKI.slice()))
      const precertTBS = buildPrecertTBS(certDER)
      const lenBytes = new Uint8Array([(precertTBS.length >> 16) & 0xff, (precertTBS.length >> 8) & 0xff, precertTBS.length & 0xff])
      const preCertEntry = concat(issuerKeyHash, lenBytes, precertTBS)
      const leaf = concat(new Uint8Array([0x00, 0x00]), writeU64(sct.timestamp), new Uint8Array([0x00, 0x01]), preCertEntry, writeU16(sct.extensions.length), sct.extensions)
      lHash = await sha256(concat(new Uint8Array([0x00]), leaf))
    } else {
      lHash = await leafHash(sct, certDER)
    }
    const hashB64 = btoa(String.fromCharCode(...lHash))

    const proofRes = await fetch(`${BASE}/api/ct-proxy?logUrl=${encodeURIComponent(sct.log.url)}&endpoint=ct/v1/get-proof-by-hash&hash=${encodeURIComponent(hashB64)}&tree_size=${sth.tree_size}`)
    const proofData = await proofRes.json()
    if (proofData.error) throw new Error(proofData.error)

    const rootHash = fromBase64(sth.sha256_root_hash)
    const auditPath = proofData.audit_path.map(fromBase64)

    let hash = lHash
    let index = proofData.leaf_index
    for (const sibling of auditPath) {
      hash = index % 2 === 0
        ? await sha256(concat(new Uint8Array([0x01]), hash, sibling))
        : await sha256(concat(new Uint8Array([0x01]), sibling, hash))
      index = Math.floor(index / 2)
    }

    const match = hash.every((b, j) => b === rootHash[j])
    console.log(`    SCT ${i + 1} (${sct.log.description}): inclusion proof ${match ? '✓ VERIFIED' : '✗ MISMATCH'}`)
    console.log(`           leaf_index=${proofData.leaf_index}, tree_size=${sth.tree_size}, path_len=${auditPath.length}`)
  } catch (e) {
    console.log(`    SCT ${i + 1}: ERROR — ${e.message}`)
  }
}

console.log('\n✓ All checks complete.\n')
