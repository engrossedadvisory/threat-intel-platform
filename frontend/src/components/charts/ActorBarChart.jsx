import React from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
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
      <p className="text-slate-300 text-xs font-semibold mb-1">{label}</p>
      <p className="text-sky-400 text-xs font-mono">
        {payload[0].value?.toLocaleString()} reports
      </p>
      {payload[0].payload?.avg_conf !== undefined && (
        <p className="text-slate-500 text-xs">
          Avg confidence: {Math.round(payload[0].payload.avg_conf)}%
        </p>
      )}
    </div>
  )
}

function confidenceColor(conf) {
  if (conf >= 80) return '#ff4d6d'
  if (conf >= 60) return '#38bdf8'
  return '#1e3a5f'
}

export default function ActorBarChart({ data = [], onSelect }) {
  const sorted = [...data].sort((a, b) => a.report_count - b.report_count).slice(-15)

  return (
    <ResponsiveContainer width="100%" height={Math.max(260, sorted.length * 28)}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 4, right: 40, left: 4, bottom: 4 }}
        onClick={e => e?.activePayload && onSelect?.(e.activePayload[0]?.payload)}
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
          dataKey="threat_actor"
          width={140}
          tick={{ fill: '#8fb0d0', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: '#0f2040' }} />
        <Bar dataKey="report_count" radius={[0, 4, 4, 0]}>
          {sorted.map((entry, i) => (
            <Cell
              key={i}
              fill={confidenceColor(entry.avg_conf ?? 50)}
              cursor="pointer"
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
