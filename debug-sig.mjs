/**
 * Deep debug: print everything about the first SCT signature to diagnose
 * what signed blob the log actually verified.
 */

import * as asn1js from 'asn1js'
import { Certificate } from 'pkijs'

const BASE = 'http://localhost:3000'
const DOMAIN = 'google.com'

function toHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('') }
function fromBase64(b64) { const bin = atob(b64.replace(/-/g,'+').replace(/_/g,'/')); return Uint8Array.from(bin, c => c.charCodeAt(0)) }
function readTLV(d, o) {
  const tag = d[o]; let p = o + 1, len
  if (d[p] & 0x80) { const n = d[p] & 0x7f; p++; len = 0; for (let i=0; i<n; i++) len = (len<<8)|d[p++] }
  else len = d[p++]
  return { tag, len, valueStart: p, end: p+len }
}
function encodeTLV(tag, value) {
  const len = value.length
  let le
  if (len < 128) le = [len]
  else if (len < 256) le = [0x81, len]
  else le = [0x82, (len>>8)&0xff, len&0xff]
  const r = new Uint8Array(1+le.length+len); r[0]=tag; r.set(le,1); r.set(value,1+le.length); return r
}
function concat(...a) { const t=a.reduce((n,x)=>n+x.length,0),r=new Uint8Array(t);let o=0;for(const x of a){r.set(x,o);o+=x.length}return r }
function writeU16(v) { return new Uint8Array([(v>>8)&0xff,v&0xff]) }
function writeU24(v) { return new Uint8Array([(v>>16)&0xff,(v>>8)&0xff,v&0xff]) }
function writeU64(v) { const b=new Uint8Array(8);let x=v;for(let i=7;i>=0;i--){b[i]=Number(x&0xffn);x>>=8n}return b }
function readU16(d,o){return(d[o]<<8)|d[o+1]}
function readU64(d,o){let r=0n;for(let i=0;i<8;i++)r=(r<<8n)|BigInt(d[o+i]);return r}

// Fetch cert
const certRes = await fetch(`${BASE}/api/fetch-cert?domain=${DOMAIN}`)
const certData = await certRes.json()
const certDER = fromBase64(certData.certDER)
const issuerDER = certData.issuerDER ? fromBase64(certData.issuerDER) : null

// Parse first SCT
const asn1 = asn1js.fromBER(certDER.slice().buffer)
const cert = new Certificate({ schema: asn1.result })
const sctExt = cert.extensions?.find(e => e.extnID === '1.3.6.1.4.1.11129.2.4.2')
const rawVal = new Uint8Array(sctExt.extnValue.valueBlock.valueHex)
const inner = asn1js.fromBER(rawVal.slice().buffer)
const sctListBytes = rawVal[0] === 0x04 ? new Uint8Array(inner.result.valueBlock.valueHex) : rawVal

let off = 2, sctLen = readU16(sctListBytes, off-2+2), p = 0
off = 2
const sctLen0 = readU16(sctListBytes, off); off+=2
const sctBytes = sctListBytes.slice(off, off+sctLen0)
p = 0
const ver = sctBytes[p++]
const logId = sctBytes.slice(p, p+32); p+=32
const timestamp = readU64(sctBytes, p); p+=8
const extLen = readU16(sctBytes, p); p+=2
const extensions = sctBytes.slice(p, p+extLen); p+=extLen
const hashAlg = sctBytes[p++], sigAlg = sctBytes[p++]
const sigLen0 = readU16(sctBytes, p); p+=2
const signature = sctBytes.slice(p, p+sigLen0)

console.log('=== First SCT ===')
console.log('logId:', toHex(logId))
console.log('timestamp:', new Date(Number(timestamp)).toISOString())
console.log('hashAlgorithm:', hashAlg, '(4=SHA-256, 5=SHA-384)')
console.log('sigAlgorithm:', sigAlg, '(3=ECDSA)')
console.log('extensions len:', extLen)
console.log('signature len:', sigLen0)
console.log('signature first 16:', toHex(signature.slice(0, 16)), '...')

// Fetch log list to get public key
const logsRes = await fetch(`${BASE}/api/log-list`)
const { logs } = await logsRes.json()
const needle = btoa(String.fromCharCode(...logId))
const log = logs.find(l => l.logId === needle)
console.log('\nLog:', log?.description ?? 'UNKNOWN')
if (!log) process.exit(1)

// Import key
let key, coordLen
for (const [curve, cl] of [['P-256', 32], ['P-384', 48]]) {
  try { key = await crypto.subtle.importKey('spki', fromBase64(log.key).slice(), { name: 'ECDSA', namedCurve: curve }, false, ['verify']); coordLen = cl; console.log('Key curve:', curve); break } catch {}
}

function derECDSAToRaw(der, cl) {
  let o = 1, sl = der[o++]
  if (sl & 0x80) { const n = sl & 0x7f; sl=0; for (let i=0;i<n;i++) sl=(sl<<8)|der[o++] }
  o++; const rl=der[o++]; let r=der.slice(o,o+rl); o+=rl
  o++; const sl2=der[o++]; let s=der.slice(o,o+sl2)
  if (r[0]===0) r=r.slice(1); if (s[0]===0) s=s.slice(1)
  const res=new Uint8Array(cl*2); res.set(r,cl-r.length); res.set(s,cl*2-s.length); return res
}

const rawSig = derECDSAToRaw(signature, coordLen)

async function tryBlob(label, blob) {
  const v = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig.slice(), blob.slice())
  console.log(label + ':', v ? '✓ VALID' : '✗ invalid')
  return v
}

// --- Test 1: x509_entry with full cert DER ---
const blob_x509 = concat(
  new Uint8Array([0,0]), writeU64(timestamp), new Uint8Array([0,0]),
  writeU24(certDER.length), certDER,
  writeU16(extLen), extensions,
)
await tryBlob('x509_entry (full cert)', blob_x509)

if (issuerDER) {
  console.log('\nIssuer DER available:', issuerDER.length, 'bytes')

  // Extract issuer SPKI
  function extractSPKI(der) {
    const ct = readTLV(der, 0); const tb = readTLV(der, ct.valueStart)
    let o = tb.valueStart, sc = 0
    while (o < tb.end) {
      const t = readTLV(der, o)
      if (t.tag === 0xa0 || t.tag === 0x02) { o = t.end; continue }
      if (t.tag === 0x30) { sc++; if (sc===5) return der.slice(o, t.end); o = t.end; continue }
      break
    }
    throw new Error('SPKI not found')
  }

  const issuerSPKI = extractSPKI(issuerDER)
  const issuerKeyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', issuerSPKI.slice()))
  console.log('Issuer SPKI first 16:', toHex(issuerSPKI.slice(0, 16)), '...')
  console.log('Issuer key hash:', toHex(issuerKeyHash))

  // SCT OID value bytes (10 bytes)
  const SCT_OID = new Uint8Array([0x2b,0x06,0x01,0x04,0x01,0xd6,0x79,0x02,0x04,0x02])
  function isSCTExt(b) {
    if (b[0] !== 0x30) return false
    const seq = readTLV(b, 0); const oid = readTLV(b, seq.valueStart)
    return oid.tag === 0x06 && oid.len === SCT_OID.length && SCT_OID.every((x,i) => b[oid.valueStart+i]===x)
  }

  function buildPrecertTBS(cDER, poisonExt) {
    const ct = readTLV(cDER, 0); const tb = readTLV(cDER, ct.valueStart)
    const tbs = cDER.slice(tb.valueStart, tb.end)
    let a3off = -1, o = 0
    while (o < tbs.length) { const t = readTLV(tbs, o); if (t.tag === 0xa3) { a3off = o; break }; o = t.end }
    if (a3off === -1) return cDER.slice(ct.valueStart, tb.end)
    const a3 = readTLV(tbs, a3off); const seq = readTLV(tbs, a3.valueStart)
    const kept = []; let eo = seq.valueStart
    while (eo < seq.end) { const e = readTLV(tbs, eo); const b = tbs.slice(eo, e.end); if (!isSCTExt(b)) kept.push(b); eo = e.end }
    if (poisonExt) kept.push(poisonExt)
    const newSeq = encodeTLV(0x30, concat(...kept))
    const newA3 = encodeTLV(0xa3, newSeq)
    return encodeTLV(0x30, concat(tbs.slice(0, a3off), newA3))
  }

  function buildBlob(precertTBS, poisonLabel) {
    const lb = new Uint8Array([(precertTBS.length>>16)&0xff,(precertTBS.length>>8)&0xff,precertTBS.length&0xff])
    const pce = concat(issuerKeyHash, lb, precertTBS)
    const blob = concat(new Uint8Array([0,0]), writeU64(timestamp), new Uint8Array([0,1]), pce, writeU16(extLen), extensions)
    return blob
  }

  // Test: precert_entry WITH poison (correct DER: 30 13 06 0a ...)
  const POISON_CORRECT = new Uint8Array([0x30,0x13,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0xd6,0x79,0x02,0x04,0x03,0x01,0x01,0xff,0x04,0x02,0x05,0x00])
  const tbs1 = buildPrecertTBS(certDER, POISON_CORRECT)
  await tryBlob('precert_entry + correct poison (30 13 06 0a)', buildBlob(tbs1))

  // Test: precert_entry WITHOUT poison extension
  const tbs2 = buildPrecertTBS(certDER, null)
  await tryBlob('precert_entry (no poison added)', buildBlob(tbs2))

  // Test: precert_entry with old wrong poison (30 11 06 09 ...)
  const POISON_WRONG = new Uint8Array([0x30,0x11,0x06,0x09,0x2b,0x06,0x01,0x04,0x01,0xd6,0x79,0x02,0x04,0x03,0x01,0x01,0xff,0x04,0x02,0x05,0x00])
  const tbs3 = buildPrecertTBS(certDER, POISON_WRONG)
  await tryBlob('precert_entry + WRONG poison (30 11 06 09)', buildBlob(tbs3))

  console.log('\nPrecert TBS (with correct poison) first 64 bytes:', toHex(tbs1.slice(0, 64)), '...')
  console.log('Precert TBS (no poison) first 64 bytes:', toHex(tbs2.slice(0, 64)), '...')
}
