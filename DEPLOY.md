# Deploying (Vercel backend + GitHub Pages frontend)

The app splits into two free-tier deployments from one repo:

- **Backend** — this same app in **dynamic** mode on **Vercel (Hobby)**. Only its
  `/api/*` routes are used. `fetch-cert` needs Node's `tls`/`dns`, which Vercel's
  Node serverless runtime provides (Cloudflare Workers can't read a TLS peer cert,
  which is why we don't use them here).
- **Frontend** — the **static** (`output: export`) build on **GitHub Pages**. It
  calls the Vercel backend via `NEXT_PUBLIC_PROXY_BASE`.

## How requests route

`lib/transport.ts` defines `HAS_PROXY` and `apiUrl()`:

| Build | `NEXT_PUBLIC_PROXY_BASE` | Behavior |
|-------|--------------------------|----------|
| dynamic (`dev`/`build`) | unset | same-origin `/api/*` (unchanged) |
| static + remote proxy | set to Vercel URL | `/api/*` calls prefixed with it |
| static, no proxy | unset | direct browser → CT log (CORS-limited; domain lookup disabled) |

## 1. Backend on Vercel

1. Import the repo at vercel.com (framework auto-detected as Next.js; default
   build = `npm run build`, the dynamic build — leave it).
2. Set env var **`ALLOWED_ORIGIN`** = your Pages origin, e.g.
   `https://<user>.github.io` (locks CORS; defaults to `*` if unset).
3. Deploy → note the URL, e.g. `https://ct-checker.vercel.app`.

## 2. Frontend on GitHub Pages

1. Repo **Settings → Pages** → Source = **GitHub Actions**.
2. Repo **Settings → Secrets and variables → Actions → Variables** → add
   **`PROXY_BASE`** = the Vercel URL from step 1.
3. Push to `main` (or run the workflow manually). `.github/workflows/deploy-pages.yml`
   builds with `NEXT_PUBLIC_BASE_PATH=/<repo>` + `NEXT_PUBLIC_PROXY_BASE` and publishes `out/`.

## Order & gotchas

- Deploy Vercel **first** (you need its URL for `PROXY_BASE`).
- After the first Pages deploy, confirm `ALLOWED_ORIGIN` on Vercel matches the
  real `https://<user>.github.io` origin.
- `ct-proxy` keeps its open-redirect guard (validates `logUrl` against the log
  list) — leave it; without it the public backend is an open proxy.
- `fetch-cert` blocks private/loopback/link-local targets (SSRF guard). DNS
  rebinding is mitigated by resolving once and pinning the IP.
