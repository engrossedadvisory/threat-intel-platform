import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { fetchStats, fetchDashboard, fetchIOCsByType } from '../api/client'
import MetricCard from '../components/ui/MetricCard'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import ActivityAreaChart from '../components/charts/ActivityAreaChart'
import RiskPieChart from '../components/charts/RiskPieChart'
import ActorBarChart from '../components/charts/ActorBarChart'
import TTPBarChart from '../components/charts/TTPBarChart'
import IOCPieChart from '../components/charts/IOCPieChart'
import GeoMap from '../components/charts/GeoMap'
import {
  ShieldAlert, Crosshair, FileWarning, Radio,
  Bell, Bug, Eye, Cpu,
} from 'lucide-react'

export default function Dashboard() {
  const navigate = useNavigate()

  const { data: stats }              = useQuery({ queryKey: ['stats'],       queryFn: fetchStats })
  const { data: dash, isLoading }    = useQuery({ queryKey: ['dashboard'],   queryFn: fetchDashboard })
  const { data: iocTypes }           = useQuery({ queryKey: ['iocs-by-type'], queryFn: fetchIOCsByType })

  const counts = stats?.counts ?? {}

  if (isLoading) return <LoadingSpinner text="Loading intelligence data…" />

  const activity     = dash?.activity      ?? []
  const riskDist     = dash?.risk_dist     ?? []
  const topActors    = dash?.top_actors    ?? []
  const topTTPs      = dash?.top_ttps      ?? []
  const feedBreakdown= dash?.feed_breakdown ?? []
  const recentAlerts = dash?.recent_alerts  ?? []
  const iocByType    = iocTypes?.data       ?? []

  return (
    <div className="space-y-4">
      {/* ── Metric row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        <MetricCard label="Reports"     value={(counts.threat_reports    ?? 0).toLocaleString()} icon={FileWarning}  accent="blue"   className="col-span-2" />
        <MetricCard label="IOCs"        value={(counts.iocs              ?? 0).toLocaleString()} icon={Crosshair}   accent="red"    className="col-span-2" />
        <MetricCard label="CVEs"        value={(counts.cve_records       ?? 0).toLocaleString()} icon={Bug}         accent="yellow" className="col-span-2" />
        <MetricCard label="Open Alerts" value={(counts.watchlist_hits    ?? 0).toLocaleString()} icon={Bell}        accent="red"    className="col-span-2" />
        <MetricCard label="Watchlist"   value={(counts.watched_assets    ?? 0).toLocaleString()} icon={Eye}         accent="purple" className="col-span-2" />
        <MetricCard label="Techniques"  value={(counts.mitre_techniques  ?? 0).toLocaleString()} icon={ShieldAlert} accent="purple" className="col-span-2" />
        <MetricCard label="Dark Web"    value={(counts.dark_web_mentions ?? 0).toLocaleString()} icon={Radio}       accent="red"    className="col-span-2" />
        <MetricCard label="GitHub Hits" value={(counts.github_findings   ?? 0).toLocaleString()} icon={Cpu}         accent="blue"   className="col-span-2" />
      </div>

      {/* ── Row 1: Activity + IOC breakdown ────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card lg:col-span-2">
          <p className="section-title">IOC &amp; Report Activity — Last 30 Days</p>
          <ActivityAreaChart data={activity} />
        </div>
        <div className="card">
          <p className="section-title">IOC Type Breakdown</p>
          {iocByType.length > 0
            ? <IOCPieChart data={iocByType} />
            : <p className="text-slate-600 text-sm text-center py-12">
                Populates as IOCs are collected
              </p>
          }
        </div>
      </div>

      {/* ── Row 2: Geo Map ──────────────────────────────────────────────────── */}
      <div className="card">
        <p className="section-title">Threat Actor Geographic Origin</p>
        <GeoMap />
      </div>

      {/* ── Row 3: Top Actors + Risk Distribution ──────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card lg:col-span-2">
          <p className="section-title">Top Threat Actors by Report Count</p>
          {topActors.length > 0
            ? <ActorBarChart
                data={topActors}
                onSelect={row => row && navigate(`/actors?actor=${encodeURIComponent(row.threat_actor)}`)}
              />
            : feedBreakdown.length > 0
              ? (
                <div>
                  <p className="text-xs text-slate-600 mb-3">
                    Actor attribution accumulating — showing reports by feed
                  </p>
                  <div className="space-y-2">
                    {feedBreakdown.slice(0, 10).map(f => (
                      <div key={f.feed} className="flex items-center gap-2">
                        <span className="text-slate-400 text-xs w-36 truncate shrink-0">{f.feed}</span>
                        <div className="flex-1 bg-navy-700 rounded-full h-2">
                          <div
                            className="h-2 rounded-full bg-sky-400/60"
                            style={{ width: `${Math.min(100, (f.count / feedBreakdown[0].count) * 100)}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs text-slate-500 w-12 text-right">
                          {f.count.toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )
              : <p className="text-slate-600 text-sm text-center py-12">
                  Accumulates as feeds run and AI attributes reports
                </p>
          }
        </div>
        <div className="card">
          <p className="section-title">Risk Distribution</p>
          {riskDist.length > 0
            ? <RiskPieChart data={riskDist} />
            : <p className="text-slate-600 text-sm text-center py-12">
                Populates as confidence scores accumulate
              </p>
          }
        </div>
      </div>

      {/* ── Row 4: Top TTPs ─────────────────────────────────────────────────── */}
      <div className="card">
        <p className="section-title">Top Observed ATT&amp;CK Techniques</p>
        {topTTPs.length > 0
          ? <TTPBarChart data={topTTPs} />
          : <p className="text-slate-600 text-sm text-center py-8">
              Populates as AI analysis extracts TTPs from reports ({(counts.mitre_techniques ?? 0).toLocaleString()} techniques loaded)
            </p>
        }
      </div>

      {/* ── Row 5: Recent Alerts ─────────────────────────────────────────────── */}
      {recentAlerts.length > 0 && (
        <div className="card">
          <p className="section-title">Recent Watchlist Alerts</p>
          <div className="space-y-2">
            {recentAlerts.slice(0, 8).map((alert, i) => (
              <div key={i}
                className="flex items-start gap-3 p-2.5 rounded-lg bg-navy-700 border border-navy-500">
                <span className={
                  alert.severity === 'high'   ? 'badge-high mt-0.5' :
                  alert.severity === 'medium' ? 'badge-medium mt-0.5' : 'badge-low mt-0.5'
                }>
                  {alert.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-slate-300 text-xs font-medium truncate">
                    {alert.asset_value || alert.label}
                  </p>
                  <p className="text-slate-600 text-xs truncate">{alert.context}</p>
                </div>
                <span className="text-slate-600 text-xs shrink-0 font-mono">
                  {alert.found_at ? new Date(alert.found_at).toLocaleDateString() : ''}
                </span>
              </div>
            ))}
          </div>
          {recentAlerts.length > 8 && (
            <button onClick={() => navigate('/watchlist')}
              className="mt-2 text-xs text-sky-400 hover:text-sky-300 transition-colors">
              View all {recentAlerts.length} alerts →
            </button>
          )}
        </div>
      )}
    </div>
  )
}
