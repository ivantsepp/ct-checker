import { fromBase64 } from './sct-parser'
import { getSTHFromCheckpoint, buildProofFromTiles, findLeafIndex } from './ct-static-api'

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
  const qs = params ? '&' + new URLSearchParams(params).toString() : ''
  const url = `/api/ct-proxy?logUrl=${encodeURIComponent(logUrl)}&endpoint=${encodeURIComponent(path)}${qs}`
  const res = await fetch(url)
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`CT API ${res.status}: ${body}`)
  }
  return res.json()
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
 * to discovering the leaf index via a binary search over the log's data tiles
 * and then reconstructing the audit path from hash tiles.
 *
 * @param sctTimestamp  SCT timestamp in milliseconds (bigint), used as the
 *                      binary-search key for data-tile leaf discovery.
 */
export async function getProofByHash(
  logUrl: string,
  leafHash: Uint8Array,
  treeSize: number,
  sctTimestamp?: bigint,
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
    if (sctTimestamp === undefined) {
      throw new Error(
        'Log does not support ct/v1/get-proof-by-hash; ' +
        'cannot fall back to tile-based proof without the SCT timestamp',
      )
    }
    // Step 1: find the leaf index by binary-searching data tiles on timestamp,
    //         then confirming with a leaf-hash comparison.
    const leafIndex = await findLeafIndex(logUrl, sctTimestamp, leafHash, treeSize)
    // Step 2: reconstruct the audit path from hash tiles.
    const auditPath = await buildProofFromTiles(logUrl, leafIndex, treeSize)
    return { leafIndex, auditPath, proofApiType: 'tiles' }
  }
}
