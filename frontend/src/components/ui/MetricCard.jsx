import React from 'react'
import clsx from 'clsx'

export default function MetricCard({ label, value, sub, icon: Icon, accent = 'blue', className }) {
  const accents = {
    blue:   'text-sky-400  border-sky-400/20  bg-sky-400/5',
    red:    'text-rose-500 border-rose-500/20 bg-rose-500/5',
    purple: 'text-violet-400 border-violet-400/20 bg-violet-400/5',
    green:  'text-green-400 border-green-400/20 bg-green-400/5',
    yellow: 'text-yellow-400 border-yellow-400/20 bg-yellow-400/5',
  }

  return (
    <div className={clsx(
      'card flex flex-col gap-2 relative overflow-hidden',
      'before:absolute before:top-0 before:left-0 before:right-0 before:h-px',
      'before:bg-gradient-to-r before:from-transparent before:via-sky-400/30 before:to-transparent',
      className
    )}>
      <div className="flex items-start justify-between">
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-600">{label}</span>
        {Icon && (
          <div className={clsx('p-1.5 rounded-lg border', accents[accent])}>
            <Icon size={14} />
          </div>
        )}
      </div>
      <div className={clsx(
        'text-2xl font-black font-mono',
        accent === 'red' ? 'text-rose-500' :
        accent === 'purple' ? 'text-violet-400' :
        accent === 'green' ? 'text-green-400' :
        accent === 'yellow' ? 'text-yellow-400' :
        'text-sky-400'
      )} style={{ textShadow: '0 0 20px currentColor' }}>
        {value ?? '—'}
      </div>
      {sub && <p className="text-xs text-slate-600">{sub}</p>}
    </div>
  )
}
