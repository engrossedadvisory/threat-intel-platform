import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { fetchOperationalActors } from '../api/client'
import ActorBarChart from '../components/charts/ActorBarChart'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { ChevronDown, ChevronRight, Users, BookOpen } from 'lucide-react'

function ActorCard({ actor, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)

  const conf = actor.avg_conf ?? 0
  const confColor = conf >= 80 ? '#ff4d6d' : conf >= 60 ? '#38bdf8' : '#3d5a80'

  return (
    <div className="border border-navy-500 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-navy-700 hover:bg-navy-600
                   transition-colors text-left"
      >
        {open ? <ChevronDown size={14} className="text-sky-400 shrink-0" />
               : <ChevronRight size={14} className="text-slate-600 shrink-0" />}
        <span className="font-semibold text-slate-200 flex-1">{actor.threat_actor}</span>
        <div className="flex items-center gap-3 shrink-0">
          {actor.origin && (
            <span className="text-xs text-slate-600 hidden md:block">{actor.origin}</span>
          )}
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-navy-500"
                style={{ color: confColor }}>
            {actor.report_count} report{actor.report_count !== 1 ? 's' : ''}
          </span>
          <span className="text-xs text-slate-600 font-mono">{conf}% conf</span>
        </div>
      </button>

      {open && (
        <div className="px-4 py-4 bg-navy-800 space-y-3">
          {/* Meta row */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
            {actor.origin && (
              <div>
                <span className="text-slate-600 block">Country of Origin</span>
                <span className="text-slate-300 font-medium">{actor.origin}</span>
              </div>
            )}
            {actor.aliases && (
              <div className="col-span-2">
                <span className="text-slate-600 block">Also Known As</span>
                <span className="text-slate-400">{actor.aliases}</span>
              </div>
            )}
            {actor.target_industry && actor.target_industry !== 'Unknown' && (
              <div className="col-span-2">
                <span className="text-slate-600 block">Target Industries</span>
                <span className="text-slate-400">{actor.target_industry}</span>
              </div>
            )}
          </div>

          {/* Feed tags */}
          {actor.feeds?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {actor.feeds.map(f => (
                <span key={f} className="feed-tag">{f.toUpperCase()}</span>
              ))}
            </div>
          )}

          {/* TTPs */}
          {actor.ttps?.length > 0 && (
            <div>
              <span className="text-xs text-slate-600 block mb-1">Observed TTPs</span>
              <div className="flex flex-wrap gap-1">
                {actor.ttps.map(t => (
                  <span key={t}
                    className="text-xs px-2 py-0.5 rounded bg-violet-400/10 text-violet-400
                               border border-violet-400/20 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* CVEs */}
          {actor.cves?.length > 0 && (
            <div>
              <span className="text-xs text-slate-600 block mb-1">Associated CVEs</span>
              <div className="flex flex-wrap gap-1">
                {actor.cves.map(c => (
                  <a key={c}
                    href={`https://nvd.nist.gov/vuln/detail/${c}`}
                    target="_blank" rel="noreferrer"
                    className="text-xs px-2 py-0.5 rounded bg-yellow-400/10 text-yellow-400
                               border border-yellow-400/20 font-mono hover:bg-yellow-400/20">
                    {c}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Description */}
          {actor.description && (
            <div
              className="text-xs text-slate-400 p-3 rounded-lg
                         bg-sky-400/5 border-l-2 border-sky-400/30 leading-relaxed">
              {actor.description}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Actors() {
  const [searchParams] = useSearchParams()
  const pinnedActor = searchParams.get('actor') || ''
  const [search, setSearch] = useState(pinnedActor)
  const [tab, setTab] = useState('active')

  const { data, isLoading } = useQuery({
    queryKey: ['actors-operational'],
    queryFn: fetchOperationalActors,
  })

  if (isLoading) return <LoadingSpinner text="Loading actor intelligence…" />

  const active   = (data?.active   ?? [])
  const profiles = (data?.profiles ?? [])

  const filteredActive = active.filter(a =>
    !search ||
    a.threat_actor?.toLowerCase().includes(search.toLowerCase()) ||
    a.aliases?.toLowerCase().includes(search.toLowerCase()) ||
    a.origin?.toLowerCase().includes(search.toLowerCase())
  )

  const filteredProfiles = profiles.filter(a =>
    !search ||
    a.threat_actor?.toLowerCase().includes(search.toLowerCase()) ||
    a.aliases?.toLowerCase().includes(search.toLowerCase()) ||
    a.origin?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-5">
      {/* Summary metrics */}
      <div className="grid grid-cols-3 gap-3">
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-sky-400">{active.length}</div>
          <div className="text-xs text-slate-600 uppercase tracking-wider mt-1">Active Actors</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-violet-400">{profiles.length}</div>
          <div className="text-xs text-slate-600 uppercase tracking-wider mt-1">Reference Profiles</div>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-black font-mono text-slate-300">
            {active.reduce((s, a) => s + (a.report_count ?? 0), 0).toLocaleString()}
          </div>
          <div className="text-xs text-slate-600 uppercase tracking-wider mt-1">Total Reports</div>
        </div>
      </div>

      {/* Active actors chart */}
      {active.length > 0 && (
        <div className="card">
          <p className="section-title">Active Threat Actors — Operational Report Count</p>
          <ActorBarChart data={active} />
        </div>
      )}

      {/* Search + tabs */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          className="input flex-1 min-w-[200px]"
          placeholder="Search actors, aliases, origin…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex rounded-lg border border-navy-500 overflow-hidden">
          <button
            onClick={() => setTab('active')}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors ${
              tab === 'active'
                ? 'bg-sky-400/15 text-sky-400'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <Users size={13} /> Active ({filteredActive.length})
          </button>
          <button
            onClick={() => setTab('profiles')}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors border-l border-navy-500 ${
              tab === 'profiles'
                ? 'bg-violet-400/15 text-violet-400'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <BookOpen size={13} /> Library ({filteredProfiles.length})
          </button>
        </div>
      </div>

      {/* Actor list */}
      <div className="space-y-2">
        {tab === 'active' && (
          filteredActive.length === 0
            ? <div className="card text-center text-slate-600 py-12">
                No active actors found. Data populates as feeds run and AI attributes reports.
              </div>
            : filteredActive.map(a => (
                <ActorCard
                  key={a.threat_actor}
                  actor={a}
                  defaultOpen={a.threat_actor === pinnedActor}
                />
              ))
        )}

        {tab === 'profiles' && (
          filteredProfiles.length === 0
            ? <div className="card text-center text-slate-600 py-12">No profiles match.</div>
            : filteredProfiles.map(a => (
                <ActorCard key={a.threat_actor} actor={a} />
              ))
        )}
      </div>
    </div>
  )
}
