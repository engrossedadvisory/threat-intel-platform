import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchStats } from '../api/client'
import { RefreshCw, Bell, Shield } from 'lucide-react'

export default function Header() {
  const { data: stats, dataUpdatedAt } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
  })

  const openAlerts = stats?.counts?.watchlist_hits ?? 0
  const updated = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : '—'

  return (
    <header className="flex items-center justify-between px-5 py-2 bg-navy-900
                       border-b border-navy-600 shrink-0">
      {/* Brand */}
      <div className="flex items-center gap-2.5">
        <Shield size={18} className="text-sky-400 drop-shadow-[0_0_6px_#38bdf8]" />
        <span className="font-black text-sm tracking-widest select-none">
          <span className="text-white">VAN</span>
          <span className="bg-gradient-to-r from-sky-400 via-violet-400 to-fuchsia-400
                           bg-clip-text text-transparent">TELLIGENCE</span>
        </span>
        <span className="hidden sm:block text-xs text-navy-500 border-l border-navy-600
                         pl-2.5 ml-0.5 font-mono">Threat Intelligence Platform</span>
      </div>

      {/* Status */}
      <div className="flex items-center gap-4 text-xs text-slate-600">
        <span className="hidden sm:flex items-center gap-1.5">
          <RefreshCw size={11} className="text-sky-400" />
          Updated {updated}
        </span>
        {openAlerts > 0 && (
          <span className="flex items-center gap-1.5 text-rose-500 font-semibold animate-pulse">
            <Bell size={13} />
            {openAlerts} alert{openAlerts !== 1 ? 's' : ''}
          </span>
        )}
      </div>
    </header>
  )
}
