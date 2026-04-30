import React, { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchTechniques, fetchTTPUsage } from '../api/client'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { ChevronDown, ChevronRight, ExternalLink, X } from 'lucide-react'

const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

const TACTIC_COLORS = {
  'Reconnaissance':       '#1e3a5f',
  'Resource Development': '#1a3d4f',
  'Initial Access':       '#3d1a1a',
  'Execution':            '#3d2a1a',
  'Persistence':          '#2d3d1a',
  'Privilege Escalation': '#1a3d2a',
  'Defense Evasion':      '#1a2d3d',
  'Credential Access':    '#3d1a3a',
  'Discovery':            '#1a3a3d',
  'Lateral Movement':     '#2a1a3d',
  'Collection':           '#3d3a1a',
  'Command and Control':  '#3d1a2a',
  'Exfiltration':         '#3a3d1a',
  'Impact':               '#3d1a1a',
}

function TechniqueCard({ tech, observed, onClick, expanded, subCount }) {
  return (
    <div
      onClick={() => onClick(tech)}
      className={`
        px-2 py-1.5 rounded text-[11px] cursor-pointer transition-all select-none
        ${observed
          ? 'bg-violet-400/20 border border-violet-400/50 hover:bg-violet-400/30'
          : 'bg-navy-700 border border-navy-500 hover:bg-navy-600'
        }
      `}
    >
      <div className={`font-mono font-bold ${observed ? 'text-violet-300' : 'text-slate-500'}`}>
        {tech.technique_id}
      </div>
      <div className={`leading-tight mt-0.5 ${observed ? 'text-slate-200' : 'text-slate-400'}`}>
        {tech.name}
      </div>
      {subCount > 0 && (
        <div className="flex items-center gap-1 mt-1 text-slate-600">
          <ChevronRight size={10} />
          <span>{subCount} sub-techniques</span>
        </div>
      )}
      {observed > 0 && (
        <div className="text-violet-400/80 mt-0.5">{observed}× observed</div>
      )}
    </div>
  )
}

function DetailPanel({ tech, subTechniques, usageMap, onClose }) {
  if (!tech) return null
  const mitrUrl = `https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}/`
  const observed = usageMap[tech.technique_id] || 0

  return (
    <div className="fixed inset-y-0 right-0 w-96 max-w-full bg-navy-900 border-l border-navy-500
                    shadow-2xl z-50 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between p-4 border-b border-navy-600">
        <div>
          <div className="font-mono text-violet-400 text-sm font-bold">{tech.technique_id}</div>
          <div className="text-slate-200 font-semibold mt-0.5">{tech.name}</div>
          {tech.tactic && (
            <div className="text-xs text-slate-600 mt-1">
              {tech.tactic.split(',').map(t => t.trim()).join(' · ')}
            </div>
          )}
        </div>
        <button onClick={onClose}
          className="text-slate-600 hover:text-slate-300 transition-colors shrink-0 ml-2">
          <X size={18} />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {observed > 0 && (
          <div className="flex items-center gap-2 px-3 py-2 bg-violet-400/10 border
                          border-violet-400/30 rounded-lg">
            <span className="text-violet-400 font-mono font-bold text-sm">{observed}×</span>
            <span className="text-violet-300 text-xs">observed in threat reports</span>
          </div>
        )}

        {tech.description && (
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">
              Description
            </p>
            <p className="text-slate-400 text-xs leading-relaxed line-clamp-12">
              {tech.description}
            </p>
          </div>
        )}

        {subTechniques.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
              Sub-techniques ({subTechniques.length})
            </p>
            <div className="space-y-1.5">
              {subTechniques.map(sub => (
                <div key={sub.technique_id}
                  className={`px-2.5 py-2 rounded border text-xs ${
                    usageMap[sub.technique_id]
                      ? 'border-violet-400/40 bg-violet-400/10'
                      : 'border-navy-500 bg-navy-700'
                  }`}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-violet-400 font-semibold">
                      {sub.technique_id}
                    </span>
                    {usageMap[sub.technique_id] > 0 && (
                      <span className="text-violet-400/70">{usageMap[sub.technique_id]}×</span>
                    )}
                  </div>
                  <div className={`mt-0.5 leading-tight ${
                    usageMap[sub.technique_id] ? 'text-slate-200' : 'text-slate-500'
                  }`}>
                    {sub.name}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <a href={mitrUrl} target="_blank" rel="noreferrer"
          className="flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300
                     transition-colors">
          <ExternalLink size={12} />
          View on MITRE ATT&CK
        </a>
      </div>
    </div>
  )
}

export default function ATTACKMatrix() {
  const [selected, setSelected]   = useState(null)
  const [search, setSearch]       = useState('')

  const { data: techData, isLoading } = useQuery({
    queryKey: ['techniques'],
    queryFn: () => fetchTechniques({ limit: 1000 }),
    staleTime: 10 * 60 * 1000,
  })
  const { data: usageData } = useQuery({
    queryKey: ['ttp-usage'],
    queryFn: fetchTTPUsage,
  })

  const techniques = techData?.data ?? []
  const usageMap   = useMemo(() => {
    const m = {}
    ;(usageData?.data ?? []).forEach(u => { m[u.technique_id] = u.count })
    return m
  }, [usageData])

  // Separate parents from sub-techniques
  const { parents, subMap, byTactic } = useMemo(() => {
    const parents = []
    const subMap  = {}   // parentId → [sub, ...]
    const byTactic = {}  // tactic → [parents]

    for (const t of techniques) {
      const hasDot = t.technique_id?.includes('.')
      if (hasDot) {
        const parentId = t.technique_id.split('.')[0]
        if (!subMap[parentId]) subMap[parentId] = []
        subMap[parentId].push(t)
      } else {
        parents.push(t)
      }
    }

    for (const p of parents) {
      const tacticList = (p.tactic || 'Unknown').split(',').map(s => s.trim())
      for (const tactic of tacticList) {
        if (!byTactic[tactic]) byTactic[tactic] = []
        byTactic[tactic].push(p)
      }
    }

    return { parents, subMap, byTactic }
  }, [techniques])

  const orderedTactics = [
    ...TACTIC_ORDER.filter(t => byTactic[t]),
    ...Object.keys(byTactic).filter(t => !TACTIC_ORDER.includes(t)),
  ]

  // Search mode
  const searchResults = useMemo(() => {
    if (!search) return []
    const q = search.toLowerCase()
    return techniques.filter(t =>
      t.technique_id?.toLowerCase().includes(q) ||
      t.name?.toLowerCase().includes(q) ||
      t.description?.toLowerCase().includes(q)
    )
  }, [search, techniques])

  if (isLoading) return <LoadingSpinner text="Loading ATT&CK techniques…" />

  const totalObserved = parents.filter(p =>
    usageMap[p.technique_id] || (subMap[p.technique_id] || []).some(s => usageMap[s.technique_id])
  ).length

  return (
    <div className="space-y-4" style={{ marginRight: selected ? '384px' : 0, transition: 'margin 0.2s' }}>
      {/* Stats bar */}
      <div className="flex flex-wrap items-center gap-4 text-xs text-slate-600">
        <span className="text-slate-400 font-medium">{parents.length} techniques</span>
        <span>·</span>
        <span>{Object.values(subMap).reduce((s, a) => s + a.length, 0)} sub-techniques</span>
        <span>·</span>
        <span className="text-violet-400">{totalObserved} observed in reports</span>
        <input
          className="input ml-auto w-64"
          placeholder="Search technique ID or name…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-[11px] text-slate-600">
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm bg-violet-400/20 border border-violet-400/50 inline-block" />
          Observed in threat reports
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-sm bg-navy-700 border border-navy-500 inline-block" />
          Not yet observed
        </span>
      </div>

      {/* Search results */}
      {search ? (
        <div className="card">
          <p className="section-title">Search Results ({searchResults.length})</p>
          <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
            {searchResults.map(t => {
              const isParent = !t.technique_id?.includes('.')
              const observed = usageMap[t.technique_id] || 0
              return (
                <div key={t.technique_id}
                  onClick={() => setSelected(isParent ? t : (parents.find(p => p.technique_id === t.technique_id.split('.')[0]) ?? t))}
                  className="flex gap-3 p-2.5 rounded-lg bg-navy-700 border border-navy-500
                             cursor-pointer hover:border-violet-400/30 transition-colors">
                  <span className={`font-mono text-xs font-bold shrink-0 w-24 ${
                    observed ? 'text-violet-400' : 'text-slate-500'
                  }`}>{t.technique_id}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-slate-300 text-xs font-medium">{t.name}</p>
                    {t.tactic && <p className="text-slate-600 text-[11px]">{t.tactic}</p>}
                  </div>
                  {observed > 0 && (
                    <span className="text-violet-400 text-xs shrink-0">{observed}× observed</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      ) : (
        /* ATT&CK Matrix — horizontal scroll, one column per tactic */
        <div className="overflow-x-auto pb-2" style={{ scrollbarWidth: 'thin' }}>
          <div className="flex gap-2" style={{ minWidth: `${orderedTactics.length * 175}px` }}>
            {orderedTactics.map(tactic => {
              const techs = (byTactic[tactic] ?? []).slice().sort((a, b) => {
                // Observed techniques first
                const ao = usageMap[a.technique_id] || 0
                const bo = usageMap[b.technique_id] || 0
                if (bo !== ao) return bo - ao
                return a.technique_id.localeCompare(b.technique_id)
              })

              const observedCount = techs.filter(t => usageMap[t.technique_id]).length
              const headerColor = TACTIC_COLORS[tactic] || '#1a2d3d'

              return (
                <div key={tactic} className="flex flex-col shrink-0" style={{ width: 170 }}>
                  {/* Tactic header */}
                  <div
                    className="px-2 py-2 rounded-t-lg border border-navy-500 mb-1"
                    style={{ background: headerColor }}
                  >
                    <div className="text-[11px] font-bold text-slate-200 leading-tight">{tactic}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      {techs.length} techs
                      {observedCount > 0 && (
                        <span className="text-violet-400 ml-1">· {observedCount} observed</span>
                      )}
                    </div>
                  </div>

                  {/* Techniques */}
                  <div className="space-y-1 flex-1">
                    {techs.map(t => (
                      <TechniqueCard
                        key={t.technique_id}
                        tech={t}
                        observed={usageMap[t.technique_id] || 0}
                        subCount={(subMap[t.technique_id] || []).length}
                        onClick={setSelected}
                        expanded={selected?.technique_id === t.technique_id}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Detail panel */}
      <DetailPanel
        tech={selected}
        subTechniques={selected ? (subMap[selected.technique_id] || []) : []}
        usageMap={usageMap}
        onClose={() => setSelected(null)}
      />
    </div>
  )
}
