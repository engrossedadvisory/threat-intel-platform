import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchFeedStatus } from '../api/client'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  CartesianGrid, ResponsiveContainer,
} from 'recharts'
import { CheckCircle, XCircle, Clock, RefreshCw } from 'lucide-react'

const TOOLTIP_STYLE = {
  backgroundColor: '#080e1c',
  border: '1px solid #0f2040',
  borderRadius: 8,
  fontSize: 12,
}

export default function FeedHealth() {
  const { data, isLoading, dataUpdatedAt, refetch } = useQuery({
    queryKey: ['feed-status'],
    queryFn: fetchFeedStatus,
  })

  if (isLoading) return <LoadingSpinner text="Loading feed health…" />

  const feeds = data?.data ?? []

  const statusIcon = (s) => {
    if (s === 'ok')      return <CheckCircle size={14} className="text-green-400" />
    if (s === 'error')   return <XCircle size={14} className="text-rose-500" />
    if (s === 'running') return <RefreshCw size={14} className="text-sky-400 animate-spin" />
    return <Clock size={14} className="text-slate-600" />
  }

  const chartData = [...feeds]
    .sort((a, b) => (b.total_records ?? 0) - (a.total_records ?? 0))
    .slice(0, 15)

  const okCount    = feeds.filter(f => f.status === 'ok').length
  const errCount   = feeds.filter(f => f.status === 'error').length
  const totalRecs  = feeds.reduce((s, f) => s + (f.total_records ?? 0), 0)

  return (
    <div className="space-y-5">
      {/* Summary row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-green-400">{okCount}</div>
          <div className="text-xs text-slate-600 mt-1">Healthy Feeds</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-rose-500">{errCount}</div>
          <div className="text-xs text-slate-600 mt-1">Errored Feeds</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-sky-400">{totalRecs.toLocaleString()}</div>
          <div className="text-xs text-slate-600 mt-1">Total Records</div>
        </div>
      </div>

      {/* Records per feed chart */}
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <p className="section-title mb-0">Records per Feed</p>
          <button onClick={() => refetch()} className="btn-ghost flex items-center gap-1.5 text-xs">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
        <ResponsiveContainer width="100%" height={Math.max(240, chartData.length * 28)}>
          <BarChart data={chartData} layout="vertical"
            margin={{ top: 4, right: 40, left: 8, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#0f2040" horizontal={false} />
            <XAxis type="number" tick={{ fill: '#3d5a80', fontSize: 10 }}
                   axisLine={{ stroke: '#0f2040' }} tickLine={false} />
            <YAxis type="category" dataKey="feed_name" width={140}
                   tick={{ fill: '#8fb0d0', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE}
                     labelStyle={{ color: '#c8d8f0' }}
                     itemStyle={{ color: '#38bdf8' }} />
            <Bar dataKey="total_records" name="Records" fill="#38bdf8"
                 radius={[0, 4, 4, 0]} opacity={0.85} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Feed detail cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {feeds.map(f => (
          <div key={f.feed_name}
            className={`card-sm flex flex-col gap-2 border ${
              f.status === 'error'   ? 'border-rose-500/30' :
              f.status === 'ok'      ? 'border-green-400/20' :
              f.status === 'running' ? 'border-sky-400/30' :
                                       'border-navy-500'
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <span className="font-semibold text-slate-300 text-sm truncate">
                {f.feed_name}
              </span>
              {statusIcon(f.status)}
            </div>
            <div className="grid grid-cols-2 gap-x-3 text-xs">
              <span className="text-slate-600">Records</span>
              <span className="font-mono text-slate-300 text-right">
                {(f.total_records ?? 0).toLocaleString()}
              </span>
              <span className="text-slate-600">Last run</span>
              <span className="font-mono text-slate-500 text-right text-[11px]">
                {f.last_run ? new Date(f.last_run).toLocaleString() : '—'}
              </span>
              <span className="text-slate-600">Last success</span>
              <span className="font-mono text-slate-500 text-right text-[11px]">
                {f.last_success ? new Date(f.last_success).toLocaleString() : '—'}
              </span>
            </div>
            {f.status === 'error' && f.error_message && (
              <p className="text-rose-500 text-xs bg-rose-500/10 rounded p-2 border border-rose-500/20">
                {f.error_message}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
