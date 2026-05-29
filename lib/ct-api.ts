import { fromBase64 } from './sct-parser'
import { ctFetch } from './transport'
import {
  getSTHFromCheckpoint,
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

async function ctGet(logUrl: string, path: string, params?: Record<string, string>): Promise<unknown> {
  const { json } = await ctFetch(logUrl, path, params)
  return json
}

/**
 * Fetch the current signed tree head.
 * Tries RFC 6962 `ct/v1/get-sth` first; if that fails (e.g. a Sunlight-only
 * log), falls back to parsing the RFC 9162 `/checkpoint` signed note.
 */
export async function getSTH(logUrl: string): Promise<STH> {
  // ── RFC 6962 path ─────────────────────────────────────────────────────────
  try {
    const data = (await ctGet(logUrl, 'ct/v1/get-sth')) as {
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
  } catch (rfc6962Err) {
    // ── Sunlight / RFC 9162 fallback ─────────────────────────────────────────
    try {
      return await getSTHFromCheckpoint(logUrl)
    } catch (sunlightErr) {
      throw new Error(
        `RFC 6962 get-sth failed (${rfc6962Err}); Sunlight checkpoint also failed (${sunlightErr})`,
      )
    }
  }
}

/**
 * Fetch an inclusion proof for a given leaf hash.
 *
 * Tries RFC 6962 `ct/v1/get-proof-by-hash` first.  If that fails (e.g. a
 * Sunlight-only log that doesn't implement the compat endpoint), we fall back
 * to reconstructing the audit path from hash tiles.  The leaf index for the
 * tile path is sourced in order of preference:
 *
 *   1. `knownLeafIndex` — from the SCT's C2SP static-ct-api `leaf_index`
 *      extension.  Costs ONE data-tile fetch to confirm.
 *   2. Binary search over data tiles by timestamp (~log2(treeSize/256) fetches).
 *
 * @param sctTimestamp    SCT timestamp in milliseconds (bigint).  Used only
 *                        if `knownLeafIndex` is absent or doesn't verify.
 * @param knownLeafIndex  Leaf index from the SCT extensions, if present.
 */
export async function getProofByHash(
  logUrl: string,
  leafHash: Uint8Array,
  treeSize: number,
  sctTimestamp?: bigint,
  knownLeafIndex?: number,
): Promise<CTProofResponse> {
  // ── RFC 6962 path ─────────────────────────────────────────────────────────
  try {
    const hashB64 = btoa(String.fromCharCode(...leafHash))
    const data = (await ctGet(logUrl, 'ct/v1/get-proof-by-hash', {
      hash: hashB64,
      tree_size: String(treeSize),
    })) as { leaf_index: number; audit_path: string[] }
    return {
      leafIndex: data.leaf_index,
      auditPath: (data.audit_path ?? []).map(fromBase64),
      proofApiType: 'rfc6962',
    }
  } catch {
    // ── Sunlight / tile-based fallback ────────────────────────────────────────
    let leafIndex: number | null = null

    // Step 1a: if the SCT carries a leaf_index extension, confirm it with one
    //          fetch and use it directly — this skips ~log2(N/256) data-tile
    //          probes from the binary search.
    if (knownLeafIndex !== undefined) {
      leafIndex = await verifyLeafAtIndex(logUrl, knownLeafIndex, leafHash, treeSize)
    }

    // Step 1b: fall back to timestamp-based binary search if the extension
    //          was absent or didn't verify (forged / stale / wrong log).
    if (leafIndex === null) {
      if (sctTimestamp === undefined) {
        throw new Error(
          'Log does not support ct/v1/get-proof-by-hash and no usable ' +
          'leaf_index extension or SCT timestamp was provided',
        )
      }
      leafIndex = await findLeafIndex(logUrl, sctTimestamp, leafHash, treeSize)
    }

    // Step 2: reconstruct the audit path from hash tiles.
    const auditPath = await buildProofFromTiles(logUrl, leafIndex, treeSize)
    return { leafIndex, auditPath, proofApiType: 'tiles' }
  }
}
