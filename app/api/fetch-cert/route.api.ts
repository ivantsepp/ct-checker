import { NextRequest, NextResponse } from 'next/server'
import * as tls from 'tls'
import * as net from 'net'
import { lookup } from 'dns/promises'
import { withCors, preflight } from '@/lib/cors'

// Needs Node's `tls`/`dns` — never the Edge runtime.
export const runtime = 'nodejs'

function isValidDomain(s: string): boolean {
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(s)
}

/**
 * SSRF guard: reject addresses that point inside the deployment's own network
 * (loopback, RFC 1918 private ranges, link-local — including the cloud
 * metadata endpoint 169.254.169.254). We resolve the host ourselves and then
 * connect to the *resolved* IP (with SNI preserved) so a later DNS rebind
 * can't slip past this check.
 */
function isBlockedAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    if (a === 127) return true // loopback
    if (a === 10) return true // private
    if (a === 0) return true // "this host"
    if (a === 169 && b === 254) return true // link-local + cloud metadata
    if (a === 192 && b === 168) return true // private
    if (a === 172 && b >= 16 && b <= 31) return true // private
    return false
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase()
    if (lower === '::1' || lower === '::') return true // loopback / unspecified
    if (lower.startsWith('fe80')) return true // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true // unique-local
    // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4 address.
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped) return isBlockedAddress(mapped[1])
    return false
  }
  return true // unparseable → block
}

export function OPTIONS(request: NextRequest) {
  return preflight(request)
}

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')
  const json = (body: unknown, init?: ResponseInit) =>
    withCors(NextResponse.json(body, init), origin)

  const domain = request.nextUrl.searchParams.get('domain')
  if (!domain) return json({ error: 'domain required' }, { status: 400 })
  if (!isValidDomain(domain)) return json({ error: 'invalid domain' }, { status: 400 })

  // Resolve first so we can both reject internal targets and pin the IP.
  let address: string
  try {
    ;({ address } = await lookup(domain))
  } catch {
    return json({ error: 'DNS resolution failed' }, { status: 502 })
  }
  if (isBlockedAddress(address)) {
    return json({ error: 'refusing to connect to a private/internal address' }, { status: 403 })
  }

  try {
    const result = await new Promise<{ certDER: Buffer; issuerDER: Buffer | null }>((resolve, reject) => {
      const socket = tls.connect(
        // Connect to the resolved IP, but keep SNI/cert validation keyed to the
        // hostname so we still receive the right certificate.
        { host: address, port: 443, servername: domain, rejectUnauthorized: false },
        () => {
          // true = get full chain so we can access issuerCertificate
          const cert = socket.getPeerCertificate(true)
          socket.destroy()
          if (!cert?.raw) { reject(new Error('No certificate received')); return }
          const issuerRaw = cert.issuerCertificate?.raw ?? null
          // Guard against self-signed certs where issuer === subject
          const issuerDER = issuerRaw && !issuerRaw.equals(cert.raw) ? issuerRaw : null
          resolve({ certDER: cert.raw, issuerDER })
        },
      )
      socket.setTimeout(10_000, () => { socket.destroy(); reject(new Error('Connection timeout')) })
      socket.on('error', reject)
    })

    return json({
      certDER: result.certDER.toString('base64'),
      issuerDER: result.issuerDER ? result.issuerDER.toString('base64') : null,
    })
  } catch (e) {
    // Generic message on purpose: distinct errors (refused vs timeout vs TLS
    // failure) would turn this into a :443 port-scan oracle for public hosts.
    console.error('fetch-cert: connection failed for', domain, e)
    return json({ error: 'Could not retrieve certificate' }, { status: 502 })
  }
}
