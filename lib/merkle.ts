import type { SCT, InclusionProof, InclusionStep } from '@/types/ct'
import { concat, writeUint16BE, writeUint24BE, writeUint64BE } from './sct-parser'
import { buildPreCertSignedEntry } from './precert'
import type { EntryType } from './sct-verifier'

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data.slice()))
}

async function leafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x00]), data))
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right))
}

function buildTimestampedEntryX509(sct: SCT, certDER: Uint8Array): Uint8Array {
  return concat(
    new Uint8Array([0x00, 0x00]),     // version=v1, leaf_type=timestamped_entry
    writeUint64BE(sct.timestamp),
    new Uint8Array([0x00, 0x00]),     // entry_type=x509_entry
    writeUint24BE(certDER.length),
    certDER,
    writeUint16BE(sct.extensions.length),
    sct.extensions,
  )
}

function buildTimestampedEntryPrecert(sct: SCT, preCertEntry: Uint8Array): Uint8Array {
  // preCertEntry = issuer_key_hash(32) || uint24(tbs_len) || tbs_bytes
  return concat(
    new Uint8Array([0x00, 0x00]),     // version=v1, leaf_type=timestamped_entry
    writeUint64BE(sct.timestamp),
    new Uint8Array([0x00, 0x01]),     // entry_type=precert_entry
    preCertEntry,
    writeUint16BE(sct.extensions.length),
    sct.extensions,
  )
}

export async function computeLeafHash(
  sct: SCT,
  certDER: Uint8Array,
  entryType: EntryType,
  issuerCertDER: Uint8Array | null,
): Promise<Uint8Array> {
  if (entryType === 'precert_entry' && issuerCertDER) {
    const preCertEntry = await buildPreCertSignedEntry(certDER, issuerCertDER)
    return leafHash(buildTimestampedEntryPrecert(sct, preCertEntry))
  }
  return leafHash(buildTimestampedEntryX509(sct, certDER))
}

export async function verifyInclusionProof(
  lHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
  expectedRoot: Uint8Array,
): Promise<{ verified: boolean; computedRoot: Uint8Array; steps: InclusionStep[] }> {
  const steps: InclusionStep[] = []
  let index = leafIndex
  let hash = lHash

  for (let level = 0; level < auditPath.length; level++) {
    const sibling = auditPath[level]
    const siblingIsLeft = index % 2 !== 0
    const parentHash = siblingIsLeft
      ? await nodeHash(sibling, hash)
      : await nodeHash(hash, sibling)

    steps.push({ level, currentHash: hash, sibling, siblingIsLeft, parentHash })
    hash = parentHash
    index = Math.floor(index / 2)
  }

  const verified = hash.length === expectedRoot.length && hash.every((b, i) => b === expectedRoot[i])
  return { verified, computedRoot: hash, steps }
}

export async function buildInclusionProof(
  sct: SCT,
  certDER: Uint8Array,
  entryType: EntryType,
  issuerCertDER: Uint8Array | null,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
  rootHash: Uint8Array,
  sthApiType?: 'rfc6962' | 'sunlight',
  proofApiType?: 'rfc6962' | 'tiles',
): Promise<InclusionProof> {
  const lHash = await computeLeafHash(sct, certDER, entryType, issuerCertDER)
  const { verified, computedRoot, steps } = await verifyInclusionProof(
    lHash,
    leafIndex,
    treeSize,
    auditPath,
    rootHash,
  )
  return {
    leafIndex,
    treeSize,
    auditPath,
    rootHash,
    leafHash: lHash,
    computedRoot,
    verified,
    steps,
    sthApiType,
    proofApiType,
  }
}
