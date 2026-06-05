'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import ThemeToggle from '@/components/ThemeToggle'

const LINKS = [
  { href: '/', label: 'Verify' },
  { href: '/feed', label: 'Live Feed' },
]

/**
 * Shared top navigation: brand + primary links + theme toggle.
 *
 * The app is a small handful of routes, so a top nav (not a sidebar) keeps the
 * structure flat.  `wide` widens the inner container for full-bleed pages like
 * the feed table; the default matches the centered content on the home page.
 */
export default function NavBar({ wide = false }: { wide?: boolean }) {
  const pathname = usePathname()

  return (
    <header className="border-b border-slate-800 px-6 py-4">
      <div className={`${wide ? 'max-w-none' : 'max-w-4xl'} mx-auto flex items-center gap-3`}>
        <Link href="/" className="flex items-center gap-2">
          <span className="text-emerald-400 font-mono text-lg font-bold">CT</span>
          <span className="text-slate-200 font-semibold hidden sm:inline">
            Certificate Transparency Verifier
          </span>
        </Link>

        <nav className="flex items-center gap-1 ml-2">
          {LINKS.map(({ href, label }) => {
            const active = href === '/' ? pathname === '/' : pathname.startsWith(href)
            return (
              <Link
                key={href}
                href={href}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'text-emerald-400 bg-emerald-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                {label}
              </Link>
            )
          })}
        </nav>

        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
