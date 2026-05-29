# CT Inclusion-Proof Checker

A Next.js app that, given a domain or pasted certificate, parses the embedded
SCTs, verifies each ECDSA signature against the Chrome CT log list, then
reconstructs and verifies the RFC 6962 Merkle inclusion proof end-to-end.

## Two build modes

The same codebase supports two deployments:

### Dynamic (full features)

Runs as a normal Next.js app with server-side route handlers under `app/api/`:

- `/api/fetch-cert` — opens a TLS socket to `<domain>:443` to fetch the leaf cert.
- `/api/ct-proxy` — forwards browser requests to CT logs, sidestepping CORS.
- `/api/log-list` — cached proxy for the Chrome v3 log list.

```bash
npm run dev      # Next.js dev server on http://localhost:3000
npm run build    # Production build with API routes
npm start
```

### Static (frontend-only, GitHub Pages)

A fully static build that runs in the browser only — no proxy, no TLS socket.

```bash
npm run build:static       # produces ./out/
```

In this mode:

- **Domain input is hidden** — the browser cannot open a TLS socket to port 443.
  Users must paste a certificate (PEM or base64 DER).
- **CT log fetches go directly from the browser to each log.** Most major logs
  (Google, Cloudflare, Sectigo) serve `Access-Control-Allow-Origin: *`, but
  some do not — those fail with a `CORSError` and are surfaced in the UI as an
  informational banner. SCT signature verification still works locally; only
  inclusion-proof reconstruction is affected.
- The Chrome log list is fetched directly from `gstatic.com` (CORS-enabled).

#### Deploy to GitHub Pages

A workflow is included at [.github/workflows/deploy.yml](.github/workflows/deploy.yml):

1. In repo settings, enable **Pages → Build and deployment → GitHub Actions**.
2. Push to `main`. The workflow builds with `NEXT_PUBLIC_BASE_PATH=/<repo>` and
   uploads `out/` as the Pages artifact.
3. For a custom domain (served at `/`), set `NEXT_PUBLIC_BASE_PATH` to an empty
   string in the workflow.

## Architecture

See [AGENTS.md](AGENTS.md) for the protocol-level invariants (RFC 6962 §2.1.1
skipping, Sunlight tile structure, leaf-hash framing, etc.) you must respect
when modifying `lib/`.

Build-mode switching:

- `process.env.NEXT_PUBLIC_STATIC_BUILD === '1'` toggles all client-side code
  paths via `IS_STATIC_BUILD` in [lib/transport.ts](lib/transport.ts).
- [next.config.ts](next.config.ts) strips `api.ts` from `pageExtensions` in
  static builds so route handlers (named `route.api.ts`) aren't discovered.

## Lint / scripts

```bash
npm run lint
node test-e2e.mjs        # ad-hoc end-to-end smoke test (Node-only)
node debug-sig.mjs       # ad-hoc signature debugging script
```
