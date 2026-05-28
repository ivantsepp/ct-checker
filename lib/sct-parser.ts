import type { SCT } from '@/types/ct'

function readUint16BE(data: Uint8Array, offset: number): number {
  return (data[offset] << 8) | data[offset + 1]
}

function readUint64BE(data: Uint8Array, offset: number): bigint {
  let result = 0n
  for (let i = 0; i < 8; i++) {
    result = (result << 8n) | BigInt(data[offset + i])
  }
  return result
}

export function parseSCTList(raw: Uint8Array): SCT[] {
  if (raw.length < 2) throw new Error('SCT list too short')

  const listLen = readUint16BE(raw, 0)
  if (listLen + 2 > raw.length) {
    throw new Error(`SCT list length mismatch: declared ${listLen}, buffer ${raw.length - 2}`)
  }

  const scts: SCT[] = []
  let offset = 2

  while (offset < 2 + listLen) {
    if (offset + 2 > raw.length) break
    const sctLen = readUint16BE(raw, offset)
    offset += 2

    if (sctLen === 0 || offset + sctLen > raw.length) break
    const sctBytes = raw.slice(offset, offset + sctLen)
    scts.push(parseSCT(sctBytes))
    offset += sctLen
  }

  return scts
}

export function parseSCT(bytes: Uint8Array): SCT {
  let offset = 0

  const version = bytes[offset++]
  if (version !== 0) throw new Error(`Unsupported SCT version: ${version}`)

  const logId = bytes.slice(offset, offset + 32)
  offset += 32

  const timestamp = readUint64BE(bytes, offset)
  offset += 8

  const extensionsLen = readUint16BE(bytes, offset)
  offset += 2
  const extensions = bytes.slice(offset, offset + extensionsLen)
  offset += extensionsLen

  const hashAlgorithm = bytes[offset++]
  const sigAlgorithm = bytes[offset++]

  const sigLen = readUint16BE(bytes, offset)
  offset += 2
  const signature = bytes.slice(offset, offset + sigLen)

  return { version, logId, timestamp, extensions, hashAlgorithm, sigAlgorithm, signature }
}

/**
 * Decoded fields from an SCT's `CtExtensions` blob.
 *
 * The wire format is a TLS extension list:
 *
 *   struct {
 *     uint8  extension_type;
 *     uint16 extension_data_length;
 *     opaque extension_data[extension_data_length];
 *   } Extension;
 *
 * Only one type is currently defined by C2SP static-ct-api:
 *   - type 0 = leaf_index: uint40 BE giving the 0-based position of this
 *     entry in the log's Merkle tree.  Lets verifiers skip the binary
 *     search over data tiles when locating the leaf.
 *
 * RFC 6962 (non-Sunlight) SCTs typically have an empty extensions blob.
 */
export interface SCTExtensionData {
  leafIndex?: number
}

export function parseSCTExtensions(bytes: Uint8Array): SCTExtensionData {
  const result: SCTExtensionData = {}
  let off = 0
  while (off + 3 <= bytes.length) {
    const extType = bytes[off]
    const extLen = readUint16BE(bytes, off + 1)
    off += 3
    if (off + extLen > bytes.length) break  // truncated; bail

    if (extType === 0 && extLen === 5) {
      // uint40 BE leaf_index — JS Number safely represents up to 2^53.
      let idx = 0
      for (let i = 0; i < 5; i++) idx = idx * 256 + bytes[off + i]
      result.leafIndex = idx
    }
    off += extLen
  }
  return result
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function toHexColonSep(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
}

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    result.set(a, offset)
    offset += a.length
  }
  return result
}

export function writeUint16BE(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff])
}

export function writeUint24BE(value: number): Uint8Array {
  return new Uint8Array([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff])
}

export function writeUint64BE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8)
  let v = value
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return bytes
}
