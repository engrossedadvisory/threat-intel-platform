import React from 'react'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const COLORS = {
  Critical: '#ff4d6d',
  High:     '#f97316',
  Medium:   '#fbbf24',
  Low:      '#4ade80',
  Info:     '#38bdf8',
}

const TOOLTIP_STYLE = {
  backgroundColor: '#080e1c',
  border: '1px solid #0f2040',
  borderRadius: 8,
  fontSize: 12,
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div style={TOOLTIP_STYLE} className="px-3 py-2">
      <p style={{ color: d.payload.fill }} className="text-xs font-semibold">{d.name}</p>
      <p className="text-slate-400 text-xs font-mono">
        {d.value?.toLocaleString()} ({d.payload.pct}%)
      </p>
    </div>
  )
}

const renderLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, pct }) => {
  if (pct < 5) return null
  const RADIAN = Math.PI / 180
  const r = innerRadius + (outerRadius - innerRadius) * 0.55
  const x = cx + r * Math.cos(-midAngle * RADIAN)
  const y = cy + r * Math.sin(-midAngle * RADIAN)
  return (
    <text x={x} y={y} fill="#c8d8f0" textAnchor="middle" dominantBaseline="central"
          fontSize={10} fontWeight="600">
      {pct}%
    </text>
  )
}

export default function RiskPieChart({ data = [] }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  const enriched = data.map(d => ({
    ...d,
    pct: total ? Math.round((d.value / total) * 100) : 0,
    fill: COLORS[d.name] || '#3d5a80',
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={enriched}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          dataKey="value"
          labelLine={false}
          label={renderLabel}
        >
          {enriched.map((entry, i) => (
            <Cell key={i} fill={entry.fill} stroke="none" />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: 11, color: '#3d5a80', paddingTop: 4 }}
          formatter={(val, entry) => (
            <span style={{ color: entry.color }}>{val}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
