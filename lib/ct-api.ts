import { fromBase64 } from './sct-parser'
import { ctFetch, type ApiRecorder } from './transport'
import {
  buildProofFromTiles,
  findLeafIndex,
  verifyLeafAtIndex,
} from './ct-static-api'

export interface STH {
  treeSize: number
  timestamp: bigint
  sha256RootHash: Uint8Array
  /** Which protocol provided this tree head. */
  apiType?: 'rfc6962' | 'sunlight'
}

export interface CTProofResponse {
  leafIndex: number
  auditPath: Uint8Array[]
  /** How the audit path was obtained. */
  proofApiType: 'rfc6962' | 'tiles'
}

async function ctGet(
  logUrl: string,
  path: string,
  params?: Record<string, string>,
  recorder?: ApiRecorder,
): Promise<unknown> {
  const { json } = await ctFetch(logUrl, path, params, recorder)
  return json
}

/**
 * Fetch the current signed tree head from an RFC 6962 log's `ct/v1/get-sth`.
 *
 * This hits only the RFC 6962 endpoint — Sunlight / tiled logs use
 * `getSTHFromCheckpoint` instead.  The caller selects the right one based on
 * the log's declared type in the CT log list (`log.logType`).
 */
export async function getSTH(logUrl: string, recorder?: ApiRecorder): Promise<STH> {
  const data = (await ctGet(logUrl, 'ct/v1/get-sth', undefined, recorder)) as {
    tree_size: number
    timestamp: number
    sha256_root_hash: string
  }
  return {
    treeSize: data.tree_size,
    timestamp: BigInt(data.timestamp),
    sha256RootHash: fromBase64(data.sha256_root_hash),
    apiType: 'rfc6962',
  }
}

/**
 * Fetch an inclusion proof from an RFC 6962 log's `ct/v1/get-proof-by-hash`.
 *
 * RFC 6962 only — Sunlight / tiled logs use `getProofFromTiles` instead.
 */
export async function getProofByHash(
  logUrl: string,
  leafHash: Uint8Array,
  treeSize: number,
  recorder?: ApiRecorder,
): Promise<CTProofResponse> {
  const hashB64 = btoa(String.fromCharCode(...leafHash))
  const data = (await ctGet(logUrl, 'ct/v1/get-proof-by-hash', {
    hash: hashB64,
    tree_size: String(treeSize),
  }, recorder)) as { leaf_index: number; audit_path: string[] }
  return {
    leafIndex: data.leaf_index,
    auditPath: (data.audit_path ?? []).map(fromBase64),
    proofApiType: 'rfc6962',
  }
}

/**
 * Reconstruct an inclusion proof for a Sunlight / RFC 9162 (tiled) log from
 * hash tiles.  The leaf index is sourced in order of preference:
 *
 *   1. `knownLeafIndex` — from the SCT's C2SP static-ct-api `leaf_index`
 *      extension.  Costs ONE data-tile fetch to confirm.
 *   2. Binary search over data tiles by timestamp (~log2(treeSize/256) fetches).
 *
 * @param sctTimestamp    SCT timestamp in milliseconds (bigint).  Used only
 *                        if `knownLeafIndex` is absent or doesn't verify.
 * @param knownLeafIndex  Leaf index from the SCT extensions, if present.
 */
export async function getProofFromTiles(
  logUrl: string,
  leafHash: Uint8Array,
  treeSize: number,
  sctTimestamp?: bigint,
  knownLeafIndex?: number,
  recorder?: ApiRecorder,
): Promise<CTProofResponse> {
  let leafIndex: number | null = null

  // Step 1a: if the SCT carries a leaf_index extension, confirm it with one
  //          fetch and use it directly — this skips ~log2(N/256) data-tile
  //          probes from the binary search.
  if (knownLeafIndex !== undefined) {
    leafIndex = await verifyLeafAtIndex(logUrl, knownLeafIndex, leafHash, treeSize, recorder)
  }

  // Step 1b: fall back to timestamp-based binary search if the extension
  //          was absent or didn't verify (forged / stale / wrong log).
  if (leafIndex === null) {
    if (sctTimestamp === undefined) {
      throw new Error(
        'No usable leaf_index extension or SCT timestamp was provided to locate the leaf in tiles',
      )
    }
    leafIndex = await findLeafIndex(logUrl, sctTimestamp, leafHash, treeSize, recorder)
  }

  // Step 2: reconstruct the audit path from hash tiles.
  const auditPath = await buildProofFromTiles(logUrl, leafIndex, treeSize, recorder)
  return { leafIndex, auditPath, proofApiType: 'tiles' }
}
