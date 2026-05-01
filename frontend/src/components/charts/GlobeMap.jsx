/**
 * CyberMap — Kaspersky-style 3-D threat globe
 *
 * Inspired by cybermap.kaspersky.com:
 *   • earth-night.jpg  — dark globe with city-light texture
 *   • Hex-polygon grid — dot-matrix country overlay (the signature Kaspersky look)
 *   • Animated neon arcs — red origin → teal destination, fast-moving dashes
 *   • Expanding pulse rings at active attack origins
 *   • Glowing point markers on hotspot countries
 *   • Live stats sidebar — top origin countries with activity bars
 *   • Auto-rotation, drag to reorient, smooth damping
 */
import React, {
  useRef, useEffect, useMemo, useState, useCallback, lazy, Suspense,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchGeoSummary } from '../../api/client'

// Heavy Three.js bundle — lazy-loaded so it doesn't block page paint
const Globe = lazy(() => import('react-globe.gl'))

// ─── GeoJSON for hex polygons ─────────────────────────────────────────────────
const COUNTRIES_URL =
  'https://raw.githubusercontent.com/vasturiano/react-globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson'

// ─── Country centroids (ISO-2 → [lat, lng]) ───────────────────────────────────
const CENTROIDS = {
  AF:[33.9,67.7],AL:[41.2,20.2],DZ:[28.0,2.6],AO:[-11.2,17.9],
  AR:[-38.4,-63.6],AM:[40.1,45.0],AU:[-25.3,133.8],AT:[47.5,14.6],
  AZ:[40.1,47.6],BD:[23.7,90.4],BY:[53.7,28.0],BE:[50.5,4.5],
  BG:[42.7,25.5],BR:[-14.2,-51.9],CA:[56.1,-106.3],CL:[-35.7,-71.5],
  CN:[35.9,104.2],CO:[4.6,-74.1],HR:[45.1,15.2],CZ:[49.8,15.5],
  CD:[-4.0,21.8],DK:[56.3,9.5],EG:[26.8,30.8],ET:[9.1,40.5],
  FI:[61.9,25.7],FR:[46.2,2.2],DE:[51.2,10.5],GH:[7.9,-1.0],
  GR:[39.1,21.8],HU:[47.2,19.5],IN:[20.6,79.0],ID:[-0.8,113.9],
  IR:[32.4,53.7],IQ:[33.2,43.7],IE:[53.4,-8.2],IL:[31.0,34.9],
  IT:[41.9,12.6],JP:[36.2,138.3],KZ:[48.0,68.0],KP:[40.3,127.5],
  KR:[35.9,127.8],KW:[29.3,47.5],LB:[33.9,35.5],LY:[26.3,17.2],
  MY:[4.2,108.0],MX:[23.6,-102.6],MA:[31.8,-7.1],MM:[21.9,95.9],
  NG:[9.1,8.7],NL:[52.1,5.3],NZ:[-40.9,174.9],NO:[60.5,8.5],
  PK:[30.4,69.3],PE:[-9.2,-75.0],PH:[12.9,121.8],PL:[51.9,19.1],
  PT:[39.4,-8.2],QA:[25.4,51.2],RO:[45.9,25.0],RU:[61.5,105.3],
  SA:[23.9,45.1],RS:[44.0,21.0],SG:[1.4,103.8],ZA:[-30.6,22.9],
  ES:[40.5,-3.7],SE:[60.1,18.6],CH:[46.8,8.2],SY:[34.8,39.0],
  TW:[23.7,121.0],TH:[15.9,100.9],TN:[33.9,9.5],TR:[38.9,35.2],
  UA:[48.4,31.2],AE:[23.4,53.8],GB:[55.4,-3.4],US:[37.1,-95.7],
  UZ:[41.4,64.6],VN:[14.1,108.3],YE:[15.6,48.5],
}

// ─── Common attack targets ────────────────────────────────────────────────────
const TARGETS = [
  { lat:37.1, lng:-95.7, label:'US'  },
  { lat:51.5, lng:-0.1,  label:'GB'  },
  { lat:48.9, lng:2.4,   label:'FR'  },
  { lat:52.5, lng:13.4,  label:'DE'  },
  { lat:35.7, lng:139.7, label:'JP'  },
  { lat:37.6, lng:126.9, label:'KR'  },
  { lat:25.2, lng:55.3,  label:'AE'  },
  { lat:1.4,  lng:103.8, label:'SG'  },
  { lat:48.2, lng:16.4,  label:'AT'  },
  { lat:52.4, lng:4.9,   label:'NL'  },
]

// ─── Demo data (used when no real intel data exists yet) ──────────────────────
const DEMO_ROWS = [
  { country:'China',       iso2:'CN', count:95 },
  { country:'Russia',      iso2:'RU', count:78 },
  { country:'North Korea', iso2:'KP', count:54 },
  { country:'Iran',        iso2:'IR', count:41 },
  { country:'Ukraine',     iso2:'UA', count:27 },
  { country:'Vietnam',     iso2:'VN', count:18 },
  { country:'Nigeria',     iso2:'NG', count:14 },
  { country:'Brazil',      iso2:'BR', count:11 },
  { country:'Turkey',      iso2:'TR', count:8  },
  { country:'Pakistan',    iso2:'PK', count:6  },
]

// ─── Hex-polygon colour (the Kaspersky signature look) ───────────────────────
function hexColor(feat, countByIso2, countByName, max) {
  const iso   = feat?.properties?.ISO_A2 || feat?.properties?.iso_a2 || ''
  const name  = feat?.properties?.ADMIN  || feat?.properties?.NAME  || ''
  const count = countByIso2[iso] ?? countByName[name] ?? 0
  if (count === 0) return 'rgba(20,100,200,0.10)'   // faint blue grid — inactive land
  const t = count / max
  if (t >= 0.7) return 'rgba(255,45,45,0.95)'       // red  — critical
  if (t >= 0.4) return 'rgba(255,140,20,0.90)'      // orange — high
  if (t >= 0.15) return 'rgba(255,210,0,0.85)'      // yellow — medium
  return 'rgba(0,240,160,0.80)'                      // cyan-green — low
}

// ─── Build animated attack arcs ───────────────────────────────────────────────
function buildArcs(rows, max) {
  const arcs = []
  const top  = rows
    .filter(r => r.iso2 && CENTROIDS[r.iso2])
    .sort((a, b) => b.count - a.count)
    .slice(0, 15)

  top.forEach(r => {
    const [lat, lng] = CENTROIDS[r.iso2]
    const t          = r.count / max
    const numTargets = t >= 0.6 ? 4 : t >= 0.3 ? 2 : 1
    const shuffled   = [...TARGETS].sort(() => Math.random() - 0.5)

    shuffled.slice(0, numTargets).forEach(tgt => {
      if (Math.abs(lat - tgt.lat) < 3 && Math.abs(lng - tgt.lng) < 3) return
      arcs.push({
        startLat: lat, startLng: lng,
        endLat: tgt.lat, endLng: tgt.lng,
        t,
        label: `${r.country} → ${tgt.label}`,
        // Gradient: red at source, teal at destination (Kaspersky palette)
        colors: ['rgba(255,40,40,0.95)', 'rgba(0,220,180,0.95)'],
      })
    })
  })
  return arcs
}

// ─── Build pulse rings at attack origins ──────────────────────────────────────
function buildRings(rows, max) {
  return rows
    .filter(r => r.iso2 && CENTROIDS[r.iso2] && r.count > 0)
    .slice(0, 10)
    .map(r => {
      const [lat, lng] = CENTROIDS[r.iso2]
      const t = r.count / max
      return {
        lat, lng,
        maxR:           3 + t * 4,
        propagationSpeed: 1.8 + t,
        repeatPeriod:   600 + Math.random() * 400,
        color:          t >= 0.6 ? 'rgba(255,45,45,' : 'rgba(255,160,30,',
      }
    })
}

// ─── Build glowing origin markers ─────────────────────────────────────────────
function buildPoints(rows, max) {
  return rows
    .filter(r => r.iso2 && CENTROIDS[r.iso2] && r.count > 0)
    .map(r => {
      const [lat, lng] = CENTROIDS[r.iso2]
      const t = r.count / max
      return {
        lat, lng,
        radius: 0.3 + t * 0.8,
        color:  t >= 0.6 ? '#ff2828' : t >= 0.3 ? '#ff8c00' : '#00f0a0',
        label:  `${r.country}: ${r.count} actor${r.count !== 1 ? 's' : ''}`,
      }
    })
}

// ─── Side stats panel ─────────────────────────────────────────────────────────
function StatsPanel({ rows, isDemo }) {
  const top5 = rows.slice(0, 6)
  const maxCount = top5[0]?.count ?? 1

  return (
    <div className="absolute right-3 top-10 z-20 w-44 rounded-lg overflow-hidden"
         style={{ background: 'rgba(0,8,20,0.80)', border: '1px solid rgba(0,200,200,0.18)', backdropFilter: 'blur(8px)' }}>
      <div className="px-3 py-2" style={{ borderBottom: '1px solid rgba(0,200,200,0.15)' }}>
        <p style={{ fontSize: 9, fontWeight: 700, color: '#00ddcc', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
          Top Threat Origins
        </p>
        {isDemo && (
          <p style={{ fontSize: 8, color: 'rgba(100,150,200,0.6)', marginTop: 2 }}>
            demo data — populates from feeds
          </p>
        )}
      </div>
      {top5.map((r, i) => (
        <div key={r.country} className="flex items-center gap-1.5 px-2.5 py-1.5"
             style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
          <span style={{ fontSize: 9, color: 'rgba(150,170,200,0.6)', width: 10, flexShrink: 0 }}>{i + 1}</span>
          <span style={{ fontSize: 10, color: '#c8d8e8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {r.country}
          </span>
          <div className="flex items-center gap-1">
            <div style={{
              height: 3, borderRadius: 2,
              width: Math.max(6, (r.count / maxCount) * 36),
              background: r.count / maxCount >= 0.6 ? '#ff3030' : r.count / maxCount >= 0.3 ? '#ff8c00' : '#00d496',
            }} />
            <span style={{ fontSize: 9, color: 'rgba(200,200,220,0.7)', fontFamily: 'monospace' }}>{r.count}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Inner Globe (rendered inside <Suspense>) ─────────────────────────────────
function GlobeRenderer({ rows, max, countries, dims }) {
  const globeRef = useRef()

  const countByIso2 = useMemo(() => {
    const m = {}; rows.forEach(r => { if (r.iso2) m[r.iso2] = r.count }); return m
  }, [rows])

  const countByName = useMemo(() => {
    const m = {}; rows.forEach(r => { if (r.country) m[r.country] = r.count }); return m
  }, [rows])

  const arcs   = useMemo(() => buildArcs(rows, max),  [rows, max])
  const rings  = useMemo(() => buildRings(rows, max),  [rows, max])
  const points = useMemo(() => buildPoints(rows, max), [rows, max])

  const getHexColor  = useCallback(feat => hexColor(feat, countByIso2, countByName, max), [countByIso2, countByName, max])
  const getHexLabel  = useCallback(feat => {
    const name  = feat?.properties?.ADMIN || feat?.properties?.NAME || 'Unknown'
    const iso   = feat?.properties?.ISO_A2 || ''
    const count = countByIso2[iso] ?? countByName[name] ?? 0
    return count > 0
      ? `<div style="font:11px system-ui;background:rgba(0,8,20,0.9);color:#e2e8f0;border:1px solid rgba(0,220,180,0.4);padding:4px 8px;border-radius:4px"><b>${name}</b>: ${count} actors</div>`
      : `<div style="font:11px system-ui;background:rgba(0,8,20,0.9);color:#64748b;border:1px solid #1e3a5f;padding:4px 8px;border-radius:4px">${name}</div>`
  }, [countByIso2, countByName])

  // Initialise rotation and camera on mount
  useEffect(() => {
    const g = globeRef.current
    if (!g) return
    const ctrl = g.controls()
    ctrl.autoRotate      = true
    ctrl.autoRotateSpeed = 0.45
    ctrl.enableDamping   = true
    ctrl.dampingFactor   = 0.08
    ctrl.minDistance     = 200
    ctrl.maxDistance     = 600
    g.pointOfView({ lat: 22, lng: 15, altitude: 2.1 }, 0)
  }, [])

  return (
    <Globe
      ref={globeRef}
      width={dims.w}
      height={dims.h}
      backgroundColor="rgba(0,0,0,0)"
      atmosphereColor="rgba(20,80,255,0.85)"
      atmosphereAltitude={0.22}
      globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"

      /* ── Kaspersky hex-dot grid ── */
      hexPolygonsData={countries.features}
      hexPolygonResolution={3}
      hexPolygonMargin={0.35}
      hexPolygonColor={getHexColor}
      hexPolygonLabel={getHexLabel}
      hexPolygonAltitude={0.004}

      /* ── Attack arcs ── */
      arcsData={arcs}
      arcColor={d => d.colors}
      arcAltitude={0.30}
      arcStroke={0.55}
      arcDashLength={0.30}
      arcDashGap={0.70}
      arcDashAnimateTime={1100}
      arcLabel={d => d.label}

      /* ── Pulse rings ── */
      ringsData={rings}
      ringColor={d => t => `${d.color}${(1 - t ** 0.5).toFixed(2)})`}
      ringMaxRadius={d => d.maxR}
      ringPropagationSpeed={d => d.propagationSpeed}
      ringRepeatPeriod={d => d.repeatPeriod}
      ringAltitude={0.002}

      /* ── Origin markers ── */
      pointsData={points}
      pointColor={d => d.color}
      pointAltitude={0.03}
      pointRadius={d => d.radius}
      pointLabel={d => d.label}
    />
  )
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function GlobeMap() {
  const containerRef = useRef()
  const [dims, setDims]           = useState({ w: 800, h: 420 })
  const [countries, setCountries] = useState({ features: [] })
  const [geoReady, setGeoReady]   = useState(false)

  const { data, isLoading } = useQuery({
    queryKey:  ['geo-summary'],
    queryFn:   fetchGeoSummary,
    staleTime: 5 * 60 * 1000,
    retry: 1,
  })

  // Use real data if available, fall back to demo rows so globe always looks live
  const rawRows = data?.data ?? []
  const isDemo  = rawRows.length === 0
  const rows    = isDemo ? DEMO_ROWS : rawRows
  const max     = rows.reduce((m, r) => Math.max(m, r.count), 1)

  // Fetch countries GeoJSON
  useEffect(() => {
    fetch(COUNTRIES_URL)
      .then(r => r.json())
      .then(d => { setCountries(d); setGeoReady(true) })
      .catch(() => setGeoReady(true))
  }, [])

  // Responsive sizing
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.floor(entry.contentRect.width)
      setDims({ w, h: Math.min(480, Math.max(300, Math.floor(w * 0.40))) })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  return (
    <div ref={containerRef} className="relative w-full"
         style={{ minHeight: dims.h }}>

      {/* Dramatic edge vignette */}
      <div className="pointer-events-none absolute inset-0 z-10"
           style={{ background: 'radial-gradient(ellipse at 50% 50%, transparent 48%, #030712 94%)' }} />

      {/* Main globe */}
      <Suspense fallback={
        <div className="flex items-center justify-center text-xs text-slate-600"
             style={{ height: dims.h }}>
          Loading 3D globe…
        </div>
      }>
        {geoReady && (
          <div style={{ filter: 'saturate(1.15) brightness(1.1)' }}>
            <GlobeRenderer rows={rows} max={max} countries={countries} dims={dims} />
          </div>
        )}
      </Suspense>

      {/* Stats panel */}
      {rows.length > 0 && <StatsPanel rows={rows} isDemo={isDemo} />}

      {/* Live indicator */}
      <div className="absolute top-2 left-10 z-20 flex items-center gap-1.5"
           style={{ fontSize: 10, color: 'rgba(0,220,180,0.8)', background: 'rgba(0,8,20,0.6)',
                    border: '1px solid rgba(0,200,200,0.2)', borderRadius: 20,
                    padding: '3px 10px', backdropFilter: 'blur(4px)' }}>
        <span className="w-1.5 h-1.5 rounded-full animate-pulse"
              style={{ background: '#ff3030', boxShadow: '0 0 6px #ff3030' }} />
        LIVE THREAT MAP
        {!isDemo && <span style={{ marginLeft: 4, color: 'rgba(150,170,200,0.5)' }}>· {rows.length} countries</span>}
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 z-20 flex flex-wrap items-center gap-3"
           style={{ fontSize: 10, color: 'rgba(150,170,200,0.7)',
                    background: 'rgba(0,8,20,0.65)', border: '1px solid rgba(0,200,200,0.15)',
                    borderRadius: 8, padding: '5px 10px', backdropFilter: 'blur(6px)' }}>
        {[
          { color: '#ff2d2d', label: 'Critical' },
          { color: '#ff8c00', label: 'High' },
          { color: '#ffd200', label: 'Medium' },
          { color: '#00f0a0', label: 'Low' },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1">
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: color,
                           boxShadow: `0 0 5px ${color}`, display: 'inline-block' }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  )
}
