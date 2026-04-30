import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Radio, Users, Search, Shield,
  AlertTriangle, Globe, Eye, Bot, Activity, ChevronLeft, ChevronRight,
} from 'lucide-react'
import clsx from 'clsx'

const NAV = [
  { to: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/feeds',       icon: Radio,           label: 'Threat Feeds' },
  { to: '/actors',      icon: Users,           label: 'Actors' },
  { to: '/ioc-hunt',    icon: Search,          label: 'IOC Hunt' },
  { to: '/attack',      icon: Shield,          label: 'ATT&CK' },
  { to: '/cves',        icon: AlertTriangle,   label: 'CVEs' },
  { to: '/darkweb',     icon: Globe,           label: 'Dark Web' },
  { to: '/watchlist',   icon: Eye,             label: 'Watchlist' },
  { to: '/ai-analyst',  icon: Bot,             label: 'AI Analyst' },
  { to: '/feed-health', icon: Activity,        label: 'Feed Health' },
]

export default function Sidebar({ collapsed, onToggle }) {
  return (
    <aside
      className={clsx(
        'flex flex-col bg-navy-900 border-r border-navy-500 transition-all duration-200 shrink-0',
        collapsed ? 'w-14' : 'w-52'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 border-b border-navy-500 min-h-[60px]">
        <span className="text-2xl">⬡</span>
        {!collapsed && (
          <span className="font-black text-base tracking-wider">
            <span className="text-white drop-shadow-[0_0_8px_#38bdf8]">VAN</span>
            <span className="bg-gradient-to-r from-sky-400 via-violet-400 to-fuchsia-400
                             bg-clip-text text-transparent">TELLIGENCE</span>
          </span>
        )}
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 mx-1 rounded-lg text-sm transition-all duration-150',
                isActive
                  ? 'bg-sky-400/10 text-sky-400 border border-sky-400/20'
                  : 'text-slate-500 hover:text-slate-300 hover:bg-navy-700'
              )
            }
          >
            <Icon size={17} className="shrink-0" />
            {!collapsed && <span className="truncate font-medium">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={onToggle}
        className="flex items-center justify-center p-3 border-t border-navy-500
                   text-slate-600 hover:text-slate-300 transition-colors"
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </aside>
  )
}
