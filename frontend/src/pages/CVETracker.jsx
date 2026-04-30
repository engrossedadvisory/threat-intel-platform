import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchCVEs } from '../api/client'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'

export default function CVETracker() {
  const [kevOnly, setKevOnly] = useState(false)
  const [minCvss, setMinCvss] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['cves', kevOnly, minCvss],
    queryFn: () => fetchCVEs({
      ...(kevOnly && { is_kev: true }),
      ...(minCvss && { min_cvss: minCvss }),
      limit: 500,
    }),
  })

  const rows = data?.data ?? []

  const COLS = [
    {
      key: 'cve_id',
      label: 'CVE',
      render: v => (
        <a href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noreferrer"
           className="font-mono text-sky-400 hover:text-sky-300 transition-colors">
          {v}
        </a>
      ),
    },
    {
      key: 'cvss_score',
      label: 'CVSS',
      render: v => v == null ? <span className="text-slate-600">—</span> : (
        <span className={`font-mono font-bold ${
          v >= 9 ? 'text-rose-500' :
          v >= 7 ? 'text-orange-400' :
          v >= 4 ? 'text-yellow-400' :
                   'text-green-400'
        }`}>{v.toFixed(1)}</span>
      ),
    },
    {
      key: 'is_kev',
      label: 'KEV',
      render: v => v
        ? <span className="badge-high">KEV</span>
        : <span className="text-slate-600 text-xs">—</span>,
    },
    {
      key: 'vendor',
      label: 'Vendor',
      render: v => <span className="text-slate-400">{v || '—'}</span>,
    },
    {
      key: 'product',
      label: 'Product',
      render: v => <span className="text-slate-400">{v || '—'}</span>,
    },
    {
      key: 'description',
      label: 'Description',
      render: v => <span className="text-slate-500 line-clamp-2">{v || '—'}</span>,
    },
    {
      key: 'cisa_due_date',
      label: 'CISA Due',
      render: v => v
        ? <span className="text-yellow-400 font-mono text-xs">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
  ]

  return (
    <div className="space-y-4">
      <div className="card flex flex-wrap gap-3 items-center">
        <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={e => setKevOnly(e.target.checked)}
            className="accent-sky-400"
          />
          CISA KEV only
        </label>
        <select className="input" value={minCvss} onChange={e => setMinCvss(e.target.value)}>
          <option value="">Any CVSS</option>
          <option value="9.0">Critical (9.0+)</option>
          <option value="7.0">High (7.0+)</option>
          <option value="4.0">Medium (4.0+)</option>
        </select>
        <span className="text-xs text-slate-600 ml-auto">{rows.length.toLocaleString()} CVEs</span>
      </div>
      {isLoading ? <LoadingSpinner /> : <DataTable columns={COLS} data={rows} pageSize={50} />}
    </div>
  )
}
