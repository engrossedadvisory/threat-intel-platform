import React from 'react'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const TYPE_COLORS = {
  ip:           '#38bdf8',
  'ip:port':    '#0ea5e9',
  domain:       '#a78bfa',
  url:          '#c084fc',
  hash_sha256:  '#ff4d6d',
  hash_md5:     '#f87171',
  hash_sha1:    '#fca5a5',
  email:        '#4ade80',
  cidr:         '#facc15',
}

const TOOLTIP_STYLE = {
  backgroundColor: '#080e1c',
  border: '1px solid #0f2040',
  borderRadius: 8,
  fontSize: 12,
}

export default function IOCPieChart({ data = [] }) {
  const enriched = data.map(d => ({
    ...d,
    fill: TYPE_COLORS[d.ioc_type] || '#3d5a80',
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={enriched}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={2}
          dataKey="count"
          nameKey="ioc_type"
        >
          {enriched.map((entry, i) => (
            <Cell key={i} fill={entry.fill} stroke="none" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelStyle={{ color: '#c8d8f0' }}
          itemStyle={{ color: '#38bdf8' }}
          formatter={(val) => [val.toLocaleString(), 'IOCs']}
        />
        <Legend
          wrapperStyle={{ fontSize: 10, color: '#3d5a80' }}
          formatter={(val, entry) => (
            <span style={{ color: entry.color }}>{val}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
