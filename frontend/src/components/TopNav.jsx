import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Radio, Users, Search, Shield,
  AlertTriangle, Globe, Eye, Bot, Activity, Settings,
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
  { to: '/admin',       icon: Settings,        label: 'Admin',      separator: true },
]

export default function TopNav() {
  return (
    <nav
      className="flex items-center bg-navy-900 border-b border-navy-500 shrink-0
                 overflow-x-auto"
      style={{ scrollbarWidth: 'none' }}
    >
      {NAV.map(({ to, icon: Icon, label, separator }) => (
        <React.Fragment key={to}>
          {separator && <div className="w-px h-5 bg-navy-600 shrink-0 mx-1" />}
          <NavLink
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium whitespace-nowrap',
                'border-b-2 transition-all duration-150 shrink-0',
                isActive
                  ? 'border-sky-400 text-sky-400 bg-sky-400/5'
                  : separator
                    ? 'border-transparent text-slate-600 hover:text-slate-300 hover:bg-navy-700'
                    : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-navy-700'
              )
            }
          >
            <Icon size={13} className="shrink-0" />
            {label}
          </NavLink>
        </React.Fragment>
      ))}
    </nav>
  )
}
