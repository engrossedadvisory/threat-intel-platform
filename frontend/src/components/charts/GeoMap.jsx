import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ComposableMap, Geographies, Geography } from 'react-simple-maps'
import { fetchGeoSummary } from '../../api/client'

// Free, CDN-hosted world topojson (ISO 3166-1 numeric IDs)
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

function threatColor(count, max) {
  if (!count || count === 0) return '#0a1628'
  const t = count / max
  if (t >= 0.7) return '#ff4d6d'  // critical — red
  if (t >= 0.4) return '#f97316'  // high — orange
  if (t >= 0.15) return '#fbbf24' // medium — amber
  return '#38bdf8'                  // low — sky
}

export default function GeoMap() {
  const [tooltip, setTooltip] = useState(null)

  const { data, isLoading } = useQuery({
    queryKey: ['geo-summary'],
    queryFn: fetchGeoSummary,
    staleTime: 5 * 60 * 1000,
  })

  const rows   = data?.data ?? []
  const byCode = {}
  rows.forEach(r => { byCode[String(r.numeric)] = r })
  const maxCount = rows.reduce((m, r) => Math.max(m, r.count), 1)

  return (
    <div className="relative select-none">
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-slate-600">
          Loading map…
        </div>
      )}

      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 118, center: [10, 15] }}
        style={{ width: '100%', height: 280, background: 'transparent' }}
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map(geo => {
              const code = String(geo.id)
              const d    = byCode[code]
              return (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill={threatColor(d?.count, maxCount)}
                  stroke="#050810"
                  strokeWidth={0.4}
                  onMouseEnter={() => {
                    if (d) setTooltip(`${d.country}: ${d.count} actor${d.count !== 1 ? 's' : ''}`)
                  }}
                  onMouseLeave={() => setTooltip(null)}
                  style={{
                    default:  { outline: 'none', transition: 'fill 0.2s' },
                    hover:    { fill: '#a78bfa', outline: 'none' },
                    pressed:  { outline: 'none' },
                  }}
                />
              )
            })
          }
        </Geographies>
      </ComposableMap>

      {/* Tooltip */}
      {tooltip && (
        <div className="absolute top-2 right-2 bg-navy-800 border border-navy-500
                        rounded px-2.5 py-1 text-xs text-slate-200 pointer-events-none
                        shadow-lg z-10">
          {tooltip}
        </div>
      )}

      {/* Legend */}
      <div className="flex items-center gap-4 mt-1 text-[11px] text-slate-600">
        {[
          { color: '#ff4d6d', label: 'High activity' },
          { color: '#f97316', label: 'Medium' },
          { color: '#fbbf24', label: 'Low' },
          { color: '#38bdf8', label: 'Minimal' },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ background: color }} />
            {label}
          </span>
        ))}
        {rows.length === 0 && !isLoading && (
          <span className="ml-auto text-slate-700">
            Populates from actor origin attribution
          </span>
        )}
      </div>
    </div>
  )
}
