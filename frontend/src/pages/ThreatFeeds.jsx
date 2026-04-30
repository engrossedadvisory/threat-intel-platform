import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchReports } from '../api/client'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { Search } from 'lucide-react'

const INFRA_FEEDS = new Set([
  'spamhaus','dshield','cert_transparency','github_monitor',
  'sslbl','openphish','nvd','cisa_kev','apt_groups',
])

const FEED_COLORS = {
  ransomware_live:    '#ff4d6d',
  feodo_tracker:      '#f97316',
  threatfox:          '#a78bfa',
  cybercrime_tracker: '#38bdf8',
  otx:                '#4ade80',
  rss_feeds:          '#fbbf24',
  malwarebazaar:      '#c084fc',
  urlhaus:            '#06b6d4',
}

export default function ThreatFeeds() {
  const [feed,   setFeed]   = useState('')
  const [search, setSearch] = useState('')
  const [minConf, setMinConf] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['reports', feed, minConf],
    queryFn: () => fetchReports({
      ...(feed && { source_feed: feed }),
      ...(minConf && { min_confidence: minConf }),
      limit: 500,
    }),
  })

  const rows = (data?.data ?? []).filter(r =>
    !search ||
    r.threat_actor?.toLowerCase().includes(search.toLowerCase()) ||
    r.summary?.toLowerCase().includes(search.toLowerCase()) ||
    r.source_feed?.toLowerCase().includes(search.toLowerCase())
  )

  // Feed breakdown for the filter bar
  const feedCounts = (data?.data ?? []).reduce((acc, r) => {
    if (!INFRA_FEEDS.has(r.source_feed)) {
      acc[r.source_feed] = (acc[r.source_feed] || 0) + 1
    }
    return acc
  }, {})

  const COLS = [
    {
      key: 'source_feed',
      label: 'Feed',
      render: v => (
        <span className="feed-tag" style={{ color: FEED_COLORS[v] || '#3d5a80' }}>
          {v?.toUpperCase()}
        </span>
      ),
    },
    {
      key: 'threat_actor',
      label: 'Actor',
      render: v => v && v !== 'Unknown'
        ? <span className="text-sky-400 font-medium">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'target_industry',
      label: 'Industry',
      render: v => v && v !== 'Unknown'
        ? <span className="text-slate-400">{v}</span>
        : <span className="text-slate-600">—</span>,
    },
    {
      key: 'confidence_score',
      label: 'Conf',
      render: v => (
        <span className={
          v >= 80 ? 'text-rose-500 font-mono font-semibold' :
          v >= 60 ? 'text-sky-400 font-mono' :
                    'text-slate-600 font-mono'
        }>{v}%</span>
      ),
    },
    {
      key: 'summary',
      label: 'Summary',
      render: v => <span className="text-slate-400 line-clamp-2">{v || '—'}</span>,
    },
    {
      key: 'created_at',
      label: 'Date',
      render: v => <span className="text-slate-600 font-mono text-xs whitespace-nowrap">
        {v ? new Date(v).toLocaleDateString() : '—'}
      </span>,
    },
  ]

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="card flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
          <input
            className="input pl-8 w-full"
            placeholder="Search actor, summary…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="input"
          value={feed}
          onChange={e => setFeed(e.target.value)}
        >
          <option value="">All feeds</option>
          {Object.entries(feedCounts).sort((a,b) => b[1]-a[1]).map(([f, c]) => (
            <option key={f} value={f}>{f} ({c})</option>
          ))}
        </select>
        <select
          className="input"
          value={minConf}
          onChange={e => setMinConf(e.target.value)}
        >
          <option value="">Any confidence</option>
          <option value="80">High (80+)</option>
          <option value="60">Medium (60+)</option>
          <option value="40">Low (40+)</option>
        </select>
        <span className="text-xs text-slate-600">{rows.length.toLocaleString()} reports</span>
      </div>

      {/* Feed pill row */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(feedCounts).sort((a,b) => b[1]-a[1]).map(([f, c]) => (
          <button
            key={f}
            onClick={() => setFeed(feed === f ? '' : f)}
            className={`text-xs px-3 py-1 rounded-full border transition-all ${
              feed === f
                ? 'bg-sky-400/15 border-sky-400/40 text-sky-400'
                : 'bg-navy-700 border-navy-500 text-slate-500 hover:border-navy-300'
            }`}
            style={feed === f ? {} : { borderColor: FEED_COLORS[f] + '40', color: FEED_COLORS[f] }}
          >
            {f} <span className="opacity-60 ml-1">{c}</span>
          </button>
        ))}
      </div>

      {isLoading ? <LoadingSpinner /> : <DataTable columns={COLS} data={rows} pageSize={50} />}
    </div>
  )
}
