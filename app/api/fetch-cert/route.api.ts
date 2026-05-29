import { NextRequest, NextResponse } from 'next/server'
import * as tls from 'tls'

function isValidDomain(s: string): boolean {
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(s)
}

export async function GET(request: NextRequest) {
  const domain = request.nextUrl.searchParams.get('domain')
  if (!domain) return NextResponse.json({ error: 'domain required' }, { status: 400 })
  if (!isValidDomain(domain)) return NextResponse.json({ error: 'invalid domain' }, { status: 400 })

  try {
    const result = await new Promise<{ certDER: Buffer; issuerDER: Buffer | null }>((resolve, reject) => {
      const socket = tls.connect(
        { host: domain, port: 443, servername: domain, rejectUnauthorized: false },
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

    return NextResponse.json({
      certDER: result.certDER.toString('base64'),
      issuerDER: result.issuerDER ? result.issuerDER.toString('base64') : null,
    })
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 })
  }
}
