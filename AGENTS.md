<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

# Project: CT inclusion-proof checker

A Next.js app that, given a domain, fetches its TLS certificate, parses the embedded SCTs, verifies each SCT signature against the Chrome CT log list, and reconstructs + verifies the RFC 6962 Merkle inclusion proof end-to-end. The UI walks the user through every step (cert → SCT → leaf hash → audit path → root).

## Architecture

- **`lib/`** — protocol code, no React. Reusable from both client and (Node-only) API routes.
  - `cert-parser.ts`, `precert.ts`, `asn1-utils.ts` — X.509 / pre-cert DER handling (uses `pkijs` + `asn1js`).
  - `sct-parser.ts` — TLS-encoded SignedCertificateTimestampList + small bytes/base64 helpers re-exported widely.
  - `sct-verifier.ts` — verifies the SCT's ECDSA signature against the log's public key.
  - `log-list.ts` — wraps `/api/log-list` (cached Chrome v3 log_list.json).
  - `ct-api.ts` — `getSTH` and `getProofByHash`. Tries **RFC 6962** (`ct/v1/get-sth`, `ct/v1/get-proof-by-hash`) first, falls back to **Sunlight / static-ct-api** (RFC 9162).
  - `ct-static-api.ts` — Sunlight tile fetching, checkpoint parsing, `findLeafIndex` (binary search over data tiles by SCT timestamp), `buildProofFromTiles`.
  - `merkle.ts` — leaf-hash construction (x509 vs precert), `verifyInclusionProof` (RFC 6962 §2.1.1).
- **`app/api/`** — server-side proxies; the browser can't reach CT logs directly.
  - `ct-proxy/` — forwards to a log URL. Validates the URL against the cached log list (open-redirect protection). Encodes responses as JSON, plain text (checkpoint), or `{ bytes: base64 }` (binary tiles) depending on the endpoint.
  - `log-list/` — proxied/cached Chrome v3 log list.
  - `fetch-cert/` — opens a TLS socket to `<domain>:443` and returns the peer cert + issuer DER.
- **`app/page.tsx`** — domain input. **`app/verify/page.tsx`** — the verification walkthrough; orchestrates everything.
- **`components/`** — UI: `SCTCard`, `MerklePathViz`, `VerificationStep`, `RawBytes`.

## Two CT log protocols, one frontend

RFC 6962 logs serve JSON via `ct/v1/*`. Sunlight / static-ct-api logs serve a signed-note checkpoint at `/checkpoint` and binary hash/data tiles under `/tile/...`. `ct-api.ts` tries RFC 6962 first and falls back transparently — most Sunlight logs do NOT serve `ct/v1/get-sth`. Code that "fixes RFC 6962" must usually be reproduced for the tile path.

## Subtle invariants (don't break these)

- **Sunlight hash tiles at level L > 0 store only complete-subtree hashes.** `entriesAtTileLevel(N, L) = floor(N / 2^(L·8))` — **not** ceil. The incomplete right-edge subtree at level L is computed from leaves, not stored.
- **Partial right-edge subtree hashes use the RFC 6962 §2.1 split:** `k = largest power of 2 < n`, recurse on `[0, k)` (complete subtree, tile lookup) and `[k, n)` (recurse). See `subtreeHash` in `lib/ct-static-api.ts`.
- **`verifyInclusionProof` skips levels per RFC 6962 §2.1.1.** When `fn == sn`, the sibling is on the LEFT regardless of LSB(fn); after that step, shift `fn`/`sn` up while LSB(fn) == 0. Naïve "one audit-path entry per consecutive level" verifiers silently produce wrong roots for leaves near the rightmost partial edge.
- **Leaf hash = `SHA-256(0x00 || version=0x00 || leaf_type=0x00 || TimestampedEntry)`.** The three prefix bytes are part of the hash input (RFC 6962). Pre-certs use a different `TimestampedEntry` payload (issuer key hash + TBS) built in `lib/precert.ts`.
- **Sunlight data tiles use the `TileLeaf` framing**, which is RFC 6962's `TimestampedEntry` followed by (for precerts) the original pre-cert, then a `Fingerprint chain<0..2^16-1>`. The leaf hash is computed over only the `TimestampedEntry` slice — `parseDataTile` returns that slice as `timestampedEntryBytes`.
- **Tile URL format** — every path segment except the last is prefixed with `x` and zero-padded to 3 digits (e.g. `tile/3/x001/234`). Partial tiles append `.p/<width>` (`1 ≤ width < 256`).

## Running

`npm run dev` — Next.js 16 + Turbopack on port 3000.
`npm run lint` — eslint.
`test-e2e.mjs` and `debug-sig.mjs` at the repo root are ad-hoc scripts; there's no formal test suite.
