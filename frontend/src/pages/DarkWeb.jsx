import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchDarkWeb } from '../api/client'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { Globe, AlertTriangle } from 'lucide-react'

export default function DarkWeb() {
  const [severity, setSeverity] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['darkweb', severity],
    queryFn: () => fetchDarkWeb({ ...(severity && { severity }), limit: 200 }),
  })

  const rows = data?.data ?? []

  const COLS = [
    {
      key: 'severity',
      label: 'Severity',
      render: v => (
        <span className={
          v === 'critical' ? 'badge-high' :
          v === 'high'     ? 'badge-high' :
          v === 'medium'   ? 'badge-medium' :
                             'badge-low'
        }>{v}</span>
      ),
    },
    {
      key: 'title',
      label: 'Title',
      render: (v, row) => (
        <div>
          <p className="text-slate-200 font-medium text-xs">{v}</p>
          {row.source_url && (
            <a href={row.source_url} target="_blank" rel="noreferrer"
               className="text-slate-600 text-xs hover:text-sky-400 transition-colors flex items-center gap-1 mt-0.5">
              <Globe size={10} />{row.source_name}
            </a>
          )}
        </div>
      ),
    },
    {
      key: 'keyword_matched',
      label: 'Matched Keyword',
      render: v => <span className="badge-info font-mono">{v}</span>,
    },
    {
      key: 'actor_handle',
      label: 'Actor Handle',
      render: v => v && v !== 'Unknown'
        ? <span className="text-rose-400 font-mono">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'snippet',
      label: 'Snippet',
      render: v => (
        <span className="text-slate-500 line-clamp-2 text-xs font-mono">{v || '—'}</span>
      ),
    },
    {
      key: 'ai_summary',
      label: 'AI Summary',
      render: v => v
        ? <span className="text-slate-400 text-xs">🤖 {v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'first_seen',
      label: 'First Seen',
      render: v => <span className="text-slate-600 font-mono text-xs">
        {v ? new Date(v).toLocaleDateString() : '—'}
      </span>,
    },
  ]

  return (
    <div className="space-y-4">
      <div className="card flex items-start gap-3 border-l-4 border-rose-500/50">
        <AlertTriangle size={18} className="text-rose-500 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-slate-300">Dark Web Monitor</p>
          <p className="text-xs text-slate-600 mt-0.5">
            Monitors Tor hidden services for keyword matches. Configure keywords and sources in Admin.
            Raw breach content is never stored — metadata only.
          </p>
        </div>
      </div>

      <div className="card flex flex-wrap gap-3 items-center">
        <select className="input" value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="text-xs text-slate-600 ml-auto">{rows.length} mentions</span>
      </div>

      {isLoading ? <LoadingSpinner /> : (
        rows.length === 0
          ? <div className="card text-center text-slate-600 py-16">
              <Globe size={32} className="mx-auto mb-3 opacity-30" />
              <p>No dark web mentions yet.</p>
              <p className="text-xs mt-1">Enable the dark web feed and configure keywords in Admin.</p>
            </div>
          : <DataTable columns={COLS} data={rows} pageSize={25} />
      )}
    </div>
  )
}
