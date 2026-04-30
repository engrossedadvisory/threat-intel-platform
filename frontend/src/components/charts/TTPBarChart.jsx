import React from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts'

const TOOLTIP_STYLE = {
  backgroundColor: '#080e1c',
  border: '1px solid #0f2040',
  borderRadius: 8,
  fontSize: 12,
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={TOOLTIP_STYLE} className="px-3 py-2">
      <p className="text-violet-400 text-xs font-mono font-semibold">{label}</p>
      {payload[0].payload?.name && (
        <p className="text-slate-400 text-xs mb-1">{payload[0].payload.name}</p>
      )}
      <p className="text-slate-300 text-xs font-mono">
        {payload[0].value?.toLocaleString()} occurrences
      </p>
    </div>
  )
}

export default function TTPBarChart({ data = [] }) {
  const sorted = [...data].sort((a, b) => a.count - b.count).slice(-12)

  return (
    <ResponsiveContainer width="100%" height={Math.max(240, sorted.length * 26)}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 4, right: 40, left: 4, bottom: 4 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#0f2040" horizontal={false} />
        <XAxis
          type="number"
          tick={{ fill: '#3d5a80', fontSize: 10 }}
          axisLine={{ stroke: '#0f2040' }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="technique_id"
          width={80}
          tick={{ fill: '#a78bfa', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: '#0f2040' }} />
        <Bar dataKey="count" fill="#a78bfa" radius={[0, 4, 4, 0]} opacity={0.85} />
      </BarChart>
    </ResponsiveContainer>
  )
}
