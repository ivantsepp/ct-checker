export interface SCT {
  version: number
  logId: Uint8Array
  timestamp: bigint
  extensions: Uint8Array
  hashAlgorithm: number
  sigAlgorithm: number
  signature: Uint8Array
}

export interface CTLog {
  description: string
  logId: string
  key: string
  /**
   * For RFC 6962 logs: the log's HTTP API base URL.
   * For tiled (RFC 9162) logs: the monitoring URL used for verification
   * (checkpoint, tiles, backward-compat ct/v1/ endpoints).
   */
  url: string
  /** Only present for tiled logs: the URL CAs use to submit certificates. */
  submissionUrl?: string
  state: Record<string, { timestamp: string } | undefined>
  temporalInterval?: { startInclusive: string; endExclusive: string }
  operator?: string
  /** Distinguishes RFC 6962 logs from Static CT API / Sunlight tiled logs. */
  logType?: 'rfc6962' | 'tiled'
}

import type { SCTExtensionData } from '@/lib/sct-parser'
import type { ApiCall } from '@/lib/transport'

export interface ParsedSCT extends SCT {
  log: CTLog | null
  logIdHex: string
  logIdBase64: string
  timestampDate: Date
  /** Decoded SCT extension list — notably leaf_index for static-ct-api logs. */
  parsedExtensions: SCTExtensionData
}

/** A single tile-entry read used to obtain a Merkle node hash. */
export interface TileEntryRef {
  kind: 'hash' | 'data'
  /** Sunlight tile level (0 = leaves). Always 0 for data tiles. */
  tileLevel: number
  /** Tile index within the level. */
  tileIdx: number
  /** Entry offset within the tile (0–255). */
  offset: number
}

/**
 * Provenance of one audit-path sibling: the hash-tile entry (or entries, when
 * the node is a computed subtree root) it was derived from.  Only populated for
 * tiled (Sunlight / RFC 9162) proofs.
 */
export interface TileSource {
  refs: TileEntryRef[]
  /** True when the hash is a single complete-subtree hash stored directly in a tile. */
  direct: boolean
}

export interface InclusionStep {
  level: number
  currentHash: Uint8Array
  sibling: Uint8Array
  siblingIsLeft: boolean
  parentHash: Uint8Array
  /** Tiled logs only: which hash-tile entry(ies) produced this sibling. */
  tileSource?: TileSource
}

export interface InclusionProof {
  leafIndex: number
  treeSize: number
  auditPath: Uint8Array[]
  rootHash: Uint8Array
  leafHash: Uint8Array
  computedRoot: Uint8Array
  verified: boolean
  steps: InclusionStep[]
  /** Which API provided the signed tree head (STH / checkpoint). */
  sthApiType?: 'rfc6962' | 'sunlight'
  /** How the audit path was obtained. */
  proofApiType?: 'rfc6962' | 'tiles'
}

export interface SCTVerificationResult {
  sct: ParsedSCT
  signatureValid: boolean | null
  signatureError?: string
  signedBlobHex?: string
  /** SHA-256 digest of the signed blob — the message the ECDSA signature authenticates. */
  digestHex?: string
  /** Named curve of the log's key (e.g. P-256). */
  curve?: string
  /** ECDSA signature `r` component (hex). */
  sigRHex?: string
  /** ECDSA signature `s` component (hex). */
  sigSHex?: string
  entryType?: 'x509_entry' | 'precert_entry' | 'unknown'
  inclusionProof: InclusionProof | null
  inclusionError?: string
  /** CT-log HTTP calls made while building the inclusion proof. */
  apiCalls?: ApiCall[]
}

export interface ParsedCert {
  subjectCN: string
  issuerCN: string
  subjectDN: string
  issuerDN: string
  notBefore: Date
  notAfter: Date
  sctListBytes: Uint8Array | null
  certDER: Uint8Array
  serialNumber: string
}
