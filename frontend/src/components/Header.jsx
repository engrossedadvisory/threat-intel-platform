import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchStats } from '../api/client'
import { RefreshCw, Bell } from 'lucide-react'
import { useLocation } from 'react-router-dom'

const PAGE_TITLES = {
  '/dashboard':   'Dashboard',
  '/feeds':       'Threat Feeds',
  '/actors':      'Threat Actor Profiles',
  '/ioc-hunt':    'IOC Hunt & Enrichment',
  '/attack':      'MITRE ATT&CK Matrix',
  '/cves':        'CVE Tracker',
  '/darkweb':     'Dark Web Monitor',
  '/watchlist':   'Watchlist',
  '/ai-analyst':  'AI Analyst',
  '/feed-health': 'Feed Health',
}

export default function Header() {
  const { pathname } = useLocation()
  const title = PAGE_TITLES[pathname] || 'VANTELLIGENCE'

  const { data: stats, dataUpdatedAt } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
  })

  const openAlerts = stats?.counts?.watchlist_hits ?? 0
  const updated = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : '—'

  return (
    <header className="flex items-center justify-between px-6 py-3 bg-navy-900
                       border-b border-navy-500 shrink-0 min-h-[56px]">
      <h1 className="text-base font-semibold text-slate-300 tracking-wide">{title}</h1>

      <div className="flex items-center gap-4 text-xs text-slate-600">
        <span className="flex items-center gap-1.5">
          <RefreshCw size={11} className="text-sky-400" />
          Updated {updated}
        </span>
        {openAlerts > 0 && (
          <span className="flex items-center gap-1.5 text-rose-500 font-medium">
            <Bell size={13} />
            {openAlerts} alert{openAlerts !== 1 ? 's' : ''}
          </span>
        )}
      </div>
    </header>
  )
}
