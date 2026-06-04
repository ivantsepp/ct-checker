export default function Footer() {
  return (
    <footer className="border-t border-slate-800 px-6 py-4 text-center">
      <p className="text-xs text-slate-500">
        Built with{' '}
        <a
          href="https://claude.com/claude-code"
          target="_blank"
          rel="noopener noreferrer"
          className="text-slate-400 hover:text-emerald-400 transition-colors"
        >
          Claude Code
        </a>
      </p>
    </footer>
  )
}
