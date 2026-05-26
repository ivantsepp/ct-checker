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

export interface ParsedSCT extends SCT {
  log: CTLog | null
  logIdHex: string
  logIdBase64: string
  timestampDate: Date
}

export interface InclusionStep {
  level: number
  currentHash: Uint8Array
  sibling: Uint8Array
  siblingIsLeft: boolean
  parentHash: Uint8Array
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
  entryType?: 'x509_entry' | 'precert_entry' | 'unknown'
  inclusionProof: InclusionProof | null
  inclusionError?: string
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
