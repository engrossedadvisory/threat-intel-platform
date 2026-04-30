import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchIOCs, searchIOC, fetchIOCsByType } from '../api/client'
import IOCPieChart from '../components/charts/IOCPieChart'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { Search, ExternalLink } from 'lucide-react'

function EnrichmentBadge({ source, data }) {
  if (!data) return null
  const parsed = typeof data === 'string' ? (() => { try { return JSON.parse(data) } catch { return {} } })() : data
  return (
    <div className="mt-1 p-2 rounded bg-navy-700 border border-navy-500 text-xs space-y-0.5">
      <p className="text-slate-600 font-semibold uppercase tracking-wider text-[10px]">{source}</p>
      {parsed.vt_verdict && (
        <p className={parsed.vt_verdict === 'malicious' ? 'text-rose-500' : 'text-green-400'}>
          VirusTotal: {parsed.vt_verdict} ({parsed.vt_malicious_count ?? 0} engines)
        </p>
      )}
      {parsed.greynoise_classification && (
        <p className="text-sky-400">GreyNoise: {parsed.greynoise_classification}</p>
      )}
      {parsed.ai_synopsis && (
        <p className="text-slate-400">🤖 {parsed.ai_synopsis}</p>
      )}
    </div>
  )
}

export default function IOCHunt() {
  const [query,   setQuery]   = useState('')
  const [iocType, setIocType] = useState('')
  const [searched, setSearched] = useState(null)
  const [searching, setSearching] = useState(false)

  const { data: byType }    = useQuery({ queryKey: ['iocs-by-type'],  queryFn: fetchIOCsByType })
  const { data: listData, isLoading } = useQuery({
    queryKey: ['iocs', iocType],
    queryFn: () => fetchIOCs({ ...(iocType && { ioc_type: iocType }), limit: 500 }),
  })

  const typeData = byType?.data ?? []
  const rows = listData?.data ?? []

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!query.trim()) return
    setSearching(true)
    try {
      const result = await searchIOC(query.trim())
      setSearched(result)
    } finally {
      setSearching(false)
    }
  }

  const COLS = [
    {
      key: 'ioc_type',
      label: 'Type',
      render: v => <span className="badge-info">{v}</span>,
    },
    {
      key: 'value',
      label: 'Value',
      render: (v, row) => (
        <div>
          <span className="font-mono text-slate-200 break-all">{v}</span>
          {row.source_feed && (
            <span className="ml-2 feed-tag">{row.source_feed}</span>
          )}
        </div>
      ),
    },
    {
      key: 'malware_family',
      label: 'Malware Family',
      render: v => v && v !== 'Unknown'
        ? <span className="text-rose-400 font-medium">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'threat_actor',
      label: 'Actor',
      render: v => v && v !== 'Unknown'
        ? <span className="text-sky-400">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'created_at',
      label: 'First Seen',
      render: v => <span className="text-slate-600 font-mono text-xs">
        {v ? new Date(v).toLocaleDateString() : '—'}
      </span>,
    },
  ]

  const totalIOCs = typeData.reduce((s, d) => s + (d.count ?? 0), 0)

  return (
    <div className="space-y-5">
      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-sky-400">{totalIOCs.toLocaleString()}</div>
          <div className="text-xs text-slate-600 mt-1">Total IOCs</div>
        </div>
        {typeData.slice(0, 3).map(t => (
          <div key={t.ioc_type} className="card text-center cursor-pointer hover:border-sky-400/30 transition-colors"
               onClick={() => setIocType(iocType === t.ioc_type ? '' : t.ioc_type)}>
            <div className="text-xl font-black font-mono text-slate-300">{(t.count ?? 0).toLocaleString()}</div>
            <div className="text-xs text-slate-600 mt-1 uppercase">{t.ioc_type}</div>
          </div>
        ))}
      </div>

      {/* Search + chart row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Search panel */}
        <div className="card space-y-3">
          <p className="section-title">IOC Lookup</p>
          <form onSubmit={handleSearch} className="flex gap-2">
            <input
              className="input flex-1"
              placeholder="Search IP, domain, hash, URL…"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
            <button type="submit" className="btn-primary flex items-center gap-1.5">
              <Search size={14} />
              {searching ? 'Searching…' : 'Search'}
            </button>
          </form>

          {searched && (
            <div className="space-y-2">
              {searched.iocs?.length === 0 && (
                <p className="text-slate-600 text-sm">No IOCs found for this indicator.</p>
              )}
              {searched.iocs?.map((ioc, i) => (
                <div key={i} className="p-3 rounded-lg bg-navy-700 border border-navy-500 text-xs space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="badge-info">{ioc.ioc_type}</span>
                    <span className="font-mono text-slate-200 break-all">{ioc.value}</span>
                  </div>
                  {ioc.malware_family && ioc.malware_family !== 'Unknown' && (
                    <p className="text-rose-400">Family: {ioc.malware_family}</p>
                  )}
                  {ioc.source_feed && <p className="text-slate-600">Feed: {ioc.source_feed}</p>}
                </div>
              ))}
              {searched.enrichments?.length > 0 && (
                <div className="mt-2">
                  <p className="text-xs text-slate-600 mb-1">Enrichment data:</p>
                  {searched.enrichments.map((e, i) => (
                    <EnrichmentBadge key={i} source={e.source} data={e.raw_data} />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* IOC type pie */}
        <div className="card">
          <p className="section-title">IOC Distribution by Type</p>
          <IOCPieChart data={typeData.map(d => ({ ioc_type: d.ioc_type, count: d.count }))} />
        </div>
      </div>

      {/* Full IOC table */}
      <div className="card space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <p className="section-title mb-0">IOC Database</p>
          <div className="flex items-center gap-2">
            <select className="input" value={iocType} onChange={e => setIocType(e.target.value)}>
              <option value="">All types</option>
              {typeData.map(t => (
                <option key={t.ioc_type} value={t.ioc_type}>
                  {t.ioc_type} ({t.count})
                </option>
              ))}
            </select>
          </div>
        </div>
        {isLoading ? <LoadingSpinner /> : <DataTable columns={COLS} data={rows} pageSize={50} />}
      </div>
    </div>
  )
}
