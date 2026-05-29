import type { NextConfig } from 'next'

/**
 * The same codebase produces two builds:
 *
 *   - Dynamic (default — `npm run dev` / `npm run build`):
 *     Includes the server-side proxy under `app/api/`.  Route handlers are
 *     named `route.api.ts` and discovered via the extended `pageExtensions`.
 *
 *   - Static (`npm run build:static`):
 *     `output: 'export'` produces a fully static site in `out/`.  We strip
 *     `api.ts` from `pageExtensions` so Next.js does NOT try to compile the
 *     route handlers (which read `Request` and would break static export).
 *
 * For GitHub Pages, set `NEXT_PUBLIC_BASE_PATH` to the repo's URL path
 * (e.g. `/ct-checker`) so asset URLs resolve correctly.
 */
const isStatic = process.env.NEXT_PUBLIC_STATIC_BUILD === '1'
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? ''

const defaultExtensions = ['tsx', 'ts', 'jsx', 'js']

const nextConfig: NextConfig = {
  pageExtensions: isStatic
    ? defaultExtensions
    : ['api.ts', ...defaultExtensions],
  ...(isStatic
    ? {
        output: 'export',
        basePath: basePath || undefined,
        assetPrefix: basePath || undefined,
        // next/image cannot run optimization on a static host
        images: { unoptimized: true },
        // Helps GH Pages serve nested routes (`/foo/` → `/foo/index.html`)
        trailingSlash: true,
      }
    : {}),
}

export default nextConfig
