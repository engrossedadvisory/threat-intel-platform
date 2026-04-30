import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchWatchlist, addWatchlistItem, deleteWatchlistItem, fetchWatchlistHits } from '../api/client'
import DataTable from '../components/ui/DataTable'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { Plus, Trash2, Eye, Bell } from 'lucide-react'

export default function Watchlist() {
  const qc = useQueryClient()
  const [tab, setTab] = useState('assets')
  const [form, setForm] = useState({ asset_type: 'domain', value: '', label: '' })
  const [adding, setAdding] = useState(false)

  const { data: wlData, isLoading: wlLoading } = useQuery({
    queryKey: ['watchlist'],
    queryFn: fetchWatchlist,
  })
  const { data: hitsData, isLoading: hitsLoading } = useQuery({
    queryKey: ['watchlist-hits'],
    queryFn: () => fetchWatchlistHits({ limit: 200 }),
  })

  const addMutation = useMutation({
    mutationFn: addWatchlistItem,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['watchlist'] })
      setForm({ asset_type: 'domain', value: '', label: '' })
      setAdding(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteWatchlistItem,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['watchlist'] }),
  })

  const assets = wlData?.data ?? []
  const hits   = hitsData?.data ?? []

  const ASSET_COLS = [
    {
      key: 'asset_type',
      label: 'Type',
      render: v => <span className="badge-info uppercase">{v}</span>,
    },
    { key: 'value', label: 'Value',
      render: v => <span className="font-mono text-slate-200">{v}</span> },
    { key: 'label', label: 'Label',
      render: v => <span className="text-slate-400">{v || '—'}</span> },
    {
      key: 'created_at',
      label: 'Added',
      render: v => <span className="text-slate-600 font-mono text-xs">
        {v ? new Date(v).toLocaleDateString() : '—'}
      </span>,
    },
    {
      key: 'id',
      label: '',
      render: (v) => (
        <button
          onClick={() => { if (window.confirm('Remove from watchlist?')) deleteMutation.mutate(v) }}
          className="text-slate-600 hover:text-rose-500 transition-colors p-1"
        >
          <Trash2 size={13} />
        </button>
      ),
    },
  ]

  const HIT_COLS = [
    {
      key: 'severity',
      label: 'Severity',
      render: v => (
        <span className={
          v === 'high'   ? 'badge-high' :
          v === 'medium' ? 'badge-medium' : 'badge-low'
        }>{v}</span>
      ),
    },
    { key: 'asset_value', label: 'Asset',
      render: v => <span className="font-mono text-slate-200">{v || '—'}</span> },
    { key: 'hit_type', label: 'Type',
      render: v => <span className="badge-info">{v}</span> },
    { key: 'context', label: 'Context',
      render: v => <span className="text-slate-500 text-xs">{v || '—'}</span> },
    {
      key: 'found_at',
      label: 'Found',
      render: v => <span className="text-slate-600 font-mono text-xs">
        {v ? new Date(v).toLocaleDateString() : '—'}
      </span>,
    },
  ]

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 gap-3">
        <div className="card flex items-center gap-3">
          <Eye size={20} className="text-sky-400" />
          <div>
            <div className="text-xl font-black font-mono text-sky-400">{assets.length}</div>
            <div className="text-xs text-slate-600">Watched Assets</div>
          </div>
        </div>
        <div className="card flex items-center gap-3">
          <Bell size={20} className="text-rose-500" />
          <div>
            <div className="text-xl font-black font-mono text-rose-500">{hits.length}</div>
            <div className="text-xs text-slate-600">Total Hits</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex rounded-lg border border-navy-500 overflow-hidden w-fit">
        {[['assets', 'Watched Assets', Eye], ['hits', 'Alerts', Bell]].map(([id, label, Icon]) => (
          <button key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors
                        ${id !== 'assets' ? 'border-l border-navy-500' : ''} ${
              tab === id
                ? 'bg-sky-400/15 text-sky-400'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <Icon size={13} />{label}
          </button>
        ))}
      </div>

      {/* Add asset form */}
      {tab === 'assets' && (
        <div className="card">
          {!adding ? (
            <button onClick={() => setAdding(true)} className="btn-primary flex items-center gap-2">
              <Plus size={14} /> Add Asset
            </button>
          ) : (
            <form
              onSubmit={e => { e.preventDefault(); addMutation.mutate(form) }}
              className="flex flex-wrap gap-3 items-end"
            >
              <select className="input"
                value={form.asset_type}
                onChange={e => setForm(f => ({ ...f, asset_type: e.target.value }))}
              >
                {['domain','ip','keyword','email','hash'].map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <input className="input flex-1 min-w-[180px]" placeholder="Value"
                value={form.value}
                onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
                required
              />
              <input className="input flex-1 min-w-[150px]" placeholder="Label (optional)"
                value={form.label}
                onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
              />
              <button type="submit" className="btn-primary" disabled={addMutation.isPending}>
                {addMutation.isPending ? 'Adding…' : 'Add'}
              </button>
              <button type="button" onClick={() => setAdding(false)} className="btn-ghost">Cancel</button>
            </form>
          )}
        </div>
      )}

      {tab === 'assets' && (
        wlLoading ? <LoadingSpinner /> : <DataTable columns={ASSET_COLS} data={assets} pageSize={25} />
      )}
      {tab === 'hits' && (
        hitsLoading ? <LoadingSpinner /> : <DataTable columns={HIT_COLS} data={hits} pageSize={25} />
      )}
    </div>
  )
}
