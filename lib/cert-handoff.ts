// Handing a pasted/clicked certificate to the verify page.
//
// Small certs ride in the `cert` query param (base64 DER/PEM), which keeps the
// resulting URL shareable. But VMC / BIMI certs embed a brand logo — usually a
// gzipped SVG — and run to ~14 KB of base64, far past the URL-length limit that
// static hosts enforce (GitHub Pages' CDN answers a long request line with
// 414 URI Too Long; the dev server has no such limit, so it only bites in prod).
// Compression doesn't help: the logo is already gzip-compressed inside the cert.
//
// For oversized payloads we stash the base64 in sessionStorage and put a short
// sentinel in the URL instead. sessionStorage is per-tab and survives the
// client-side navigation to /verify, which is all we need.

const STORAGE_KEY = 'ct-checker:pasted-cert'

/**
 * Sentinel `cert` value meaning "the real payload is in sessionStorage".
 * Base64 never contains underscores, so this can't collide with a real payload.
 */
export const CERT_SESSION_SENTINEL = '__session__'

/**
 * Max length (after URL-encoding) we'll allow the `cert` param to reach before
 * spilling to sessionStorage. Kept well under the ~8 KB request line that
 * common CDNs/proxies accept, while leaving normal TLS certs inline (and thus
 * shareable).
 */
const MAX_CERT_IN_URL = 6000

/**
 * Given a base64 cert payload, return the value to place in the `cert` query
 * param: the payload itself when small, or the session sentinel (after stashing
 * the payload in sessionStorage) when it would overflow the URL.
 */
export function stashCertB64(b64: string): string {
  if (encodeURIComponent(b64).length <= MAX_CERT_IN_URL) return b64
  try {
    sessionStorage.setItem(STORAGE_KEY, b64)
    return CERT_SESSION_SENTINEL
  } catch {
    // sessionStorage unavailable (e.g. privacy mode) — fall back to the URL and
    // let the host decide; a 414 is still clearer than silently dropping data.
    return b64
  }
}

/**
 * Rewrite a `/verify?cert=…` href so an oversized payload is stashed in
 * sessionStorage instead of inlined. Safe to call on every href; only the
 * clicked one ends up in storage, so building many hrefs up front (e.g. one per
 * feed row) doesn't clobber. Returns non-cert hrefs unchanged.
 */
export function resolveVerifyHref(href: string): string {
  const marker = '?cert='
  const i = href.indexOf(marker)
  if (i < 0) return href
  const b64 = decodeURIComponent(href.slice(i + marker.length))
  return `/verify?cert=${encodeURIComponent(stashCertB64(b64))}`
}

/**
 * Resolve a `cert` query value back to its base64 payload, reading from
 * sessionStorage when the value is the session sentinel.
 */
export function resolveCert(certParam: string): string {
  if (certParam !== CERT_SESSION_SENTINEL) return certParam
  const stored = typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_KEY) : null
  if (!stored) {
    throw new Error(
      'The pasted certificate is no longer available — it is kept only in this ' +
        'browser tab and could not be found. Go back and paste it again.',
    )
  }
  return stored
}
