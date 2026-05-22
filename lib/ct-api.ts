import { fromBase64 } from './sct-parser'

export interface STH {
  treeSize: number
  timestamp: bigint
  sha256RootHash: Uint8Array
}

export interface CTProofResponse {
  leafIndex: number
  auditPath: Uint8Array[]
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

export async function getSTH(logUrl: string): Promise<STH> {
  const data = (await ctGet(logUrl, 'ct/v1/get-sth')) as {
    tree_size: number
    timestamp: number
    sha256_root_hash: string
  }
  return {
    treeSize: data.tree_size,
    timestamp: BigInt(data.timestamp),
    sha256RootHash: fromBase64(data.sha256_root_hash),
  }
}

export async function getProofByHash(
  logUrl: string,
  leafHash: Uint8Array,
  treeSize: number,
): Promise<CTProofResponse> {
  const hashB64 = btoa(String.fromCharCode(...leafHash))
  const data = (await ctGet(logUrl, 'ct/v1/get-proof-by-hash', {
    hash: hashB64,
    tree_size: String(treeSize),
  })) as { leaf_index: number; audit_path: string[] }
  return {
    leafIndex: data.leaf_index,
    auditPath: (data.audit_path ?? []).map(fromBase64),
  }
}
