import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchTechniques, fetchTTPUsage } from '../api/client'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import TTPBarChart from '../components/charts/TTPBarChart'

const TACTIC_ORDER = [
  'Reconnaissance','Resource Development','Initial Access','Execution',
  'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
  'Discovery','Lateral Movement','Collection','Command and Control',
  'Exfiltration','Impact',
]

export default function ATTACKMatrix() {
  const [search, setSearch] = useState('')
  const [selectedTactic, setSelectedTactic] = useState('')

  const { data: techData, isLoading } = useQuery({
    queryKey: ['techniques'],
    queryFn: () => fetchTechniques({ limit: 1000 }),
  })
  const { data: usageData } = useQuery({
    queryKey: ['ttp-usage'],
    queryFn: fetchTTPUsage,
  })

  if (isLoading) return <LoadingSpinner text="Loading ATT&CK techniques…" />

  const techniques = techData?.data ?? []
  const usage = usageData?.data ?? []

  const usageMap = usage.reduce((m, u) => {
    m[u.technique_id] = u.count
    return m
  }, {})

  // Group by tactic
  const byTactic = {}
  for (const t of techniques) {
    const tactic = t.tactic || 'Unknown'
    if (!byTactic[tactic]) byTactic[tactic] = []
    byTactic[tactic].push({ ...t, usage_count: usageMap[t.technique_id] || 0 })
  }

  const orderedTactics = [
    ...TACTIC_ORDER.filter(t => byTactic[t]),
    ...Object.keys(byTactic).filter(t => !TACTIC_ORDER.includes(t)),
  ]

  const filteredTactics = selectedTactic
    ? orderedTactics.filter(t => t === selectedTactic)
    : orderedTactics

  const searchedTechniques = techniques.filter(t =>
    !search ||
    t.technique_id?.toLowerCase().includes(search.toLowerCase()) ||
    t.name?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-5">
      {/* Top observed TTPs chart */}
      {usage.length > 0 && (
        <div className="card">
          <p className="section-title">Top Observed Techniques</p>
          <TTPBarChart data={usage} />
        </div>
      )}

      {/* Filters */}
      <div className="card flex flex-wrap gap-3 items-center">
        <input
          className="input flex-1 min-w-[200px]"
          placeholder="Search technique ID or name…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          className="input"
          value={selectedTactic}
          onChange={e => setSelectedTactic(e.target.value)}
        >
          <option value="">All tactics</option>
          {orderedTactics.map(t => (
            <option key={t} value={t}>{t} ({byTactic[t]?.length ?? 0})</option>
          ))}
        </select>
        <span className="text-xs text-slate-600">{techniques.length.toLocaleString()} techniques</span>
      </div>

      {/* Matrix grid */}
      {!search ? (
        <div className="space-y-4">
          {filteredTactics.map(tactic => {
            const techs = (byTactic[tactic] ?? []).sort((a, b) => b.usage_count - a.usage_count)
            return (
              <div key={tactic} className="card">
                <div className="flex items-center gap-2 mb-3">
                  <h3 className="text-sm font-semibold text-slate-300">{tactic}</h3>
                  <span className="text-xs text-slate-600">{techs.length} techniques</span>
                  {techs.some(t => t.usage_count > 0) && (
                    <span className="badge-high ml-1">observed</span>
                  )}
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
                  {techs.map(t => (
                    <div
                      key={t.technique_id}
                      title={t.description?.slice(0, 200)}
                      className={`p-2 rounded-lg border text-xs transition-all ${
                        t.usage_count > 0
                          ? 'border-violet-400/40 bg-violet-400/10 hover:bg-violet-400/15'
                          : 'border-navy-500 bg-navy-700 hover:bg-navy-600'
                      }`}
                    >
                      <div className={`font-mono font-semibold text-[11px] ${
                        t.usage_count > 0 ? 'text-violet-400' : 'text-slate-600'
                      }`}>{t.technique_id}</div>
                      <div className="text-slate-400 mt-0.5 leading-tight line-clamp-2">{t.name}</div>
                      {t.usage_count > 0 && (
                        <div className="text-violet-400/70 text-[10px] mt-1">
                          {t.usage_count}× observed
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="card">
          <p className="section-title">Search Results ({searchedTechniques.length})</p>
          <div className="space-y-2">
            {searchedTechniques.map(t => (
              <div key={t.technique_id}
                className="flex gap-3 p-3 rounded-lg bg-navy-700 border border-navy-500">
                <span className="font-mono text-violet-400 text-sm shrink-0 w-20">{t.technique_id}</span>
                <div>
                  <p className="text-slate-300 text-sm font-medium">{t.name}</p>
                  {t.tactic && <p className="text-slate-600 text-xs">{t.tactic}</p>}
                  {usageMap[t.technique_id] > 0 && (
                    <p className="text-violet-400 text-xs mt-0.5">
                      Observed {usageMap[t.technique_id]}× in threat reports
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
