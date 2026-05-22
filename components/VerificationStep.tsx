'use client'

export type StepStatus = 'pending' | 'running' | 'pass' | 'fail' | 'warn'

interface Props {
  status: StepStatus
  title: string
  children?: React.ReactNode
}

const icons: Record<StepStatus, string> = {
  pending: '○',
  running: '◌',
  pass: '✓',
  fail: '✗',
  warn: '⚠',
}

const colours: Record<StepStatus, string> = {
  pending: 'text-slate-500 border-slate-700 bg-slate-900/30',
  running: 'text-amber-400 border-amber-500/30 bg-amber-400/5',
  pass:    'text-emerald-400 border-emerald-500/30 bg-emerald-400/5',
  fail:    'text-red-400 border-red-500/30 bg-red-400/5',
  warn:    'text-amber-400 border-amber-500/30 bg-amber-400/5',
}

const badgeColours: Record<StepStatus, string> = {
  pending: 'bg-slate-700 text-slate-300',
  running: 'bg-amber-500/20 text-amber-300',
  pass:    'bg-emerald-500/20 text-emerald-300',
  fail:    'bg-red-500/20 text-red-300',
  warn:    'bg-amber-500/20 text-amber-300',
}

const labels: Record<StepStatus, string> = {
  pending: 'PENDING',
  running: 'RUNNING',
  pass:    'PASS',
  fail:    'FAIL',
  warn:    'WARN',
}

export default function VerificationStep({ status, title, children }: Props) {
  return (
    <div className={`rounded-lg border p-4 ${colours[status]}`}>
      <div className="flex items-center gap-3 mb-2">
        <span className="text-lg font-mono font-bold">{icons[status]}</span>
        <span className="font-semibold text-slate-100">{title}</span>
        <span className={`ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded ${badgeColours[status]}`}>
          {labels[status]}
        </span>
      </div>
      {children && <div className="mt-2 ml-8 text-sm text-slate-300 space-y-1">{children}</div>}
    </div>
  )
}
