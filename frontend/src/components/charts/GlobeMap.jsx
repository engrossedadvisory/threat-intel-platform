/**
 * GlobeMap — 3-D spinning threat-origin globe
 *
 * Uses react-globe.gl (Three.js / WebGL) to render:
 *   • Country polygons coloured by actor-origin count
 *   • Animated arc paths from top source countries to common targets
 *   • Glowing point markers on high-activity countries
 *   • Auto-rotation with mouse-drag override
 */
import React, { useRef, useEffect, useMemo, useState, useCallback, lazy, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ComposableMap, Geographies, Geography } from 'react-simple-maps'
import { fetchGeoSummary } from '../../api/client'

// Lazy-load the heavy 3-D globe so it doesn't block initial page render
const Globe = lazy(() => import('react-globe.gl'))

// ─── GeoJSON for globe polygons (Natural Earth 110m, ~250 KB) ─────────────────
const COUNTRIES_URL =
  'https://raw.githubusercontent.com/vasturiano/react-globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson'

// ─── Country centroids (ISO 3166-1 alpha-2 → [lat, lng]) ─────────────────────
const CENTROIDS = {
  AF:[33.9,67.7],AL:[41.2,20.2],DZ:[28.0,2.6],AO:[-11.2,17.9],
  AR:[-38.4,-63.6],AM:[40.1,45.0],AU:[-25.3,133.8],AT:[47.5,14.6],
  AZ:[40.1,47.6],BD:[23.7,90.4],BY:[53.7,28.0],BE:[50.5,4.5],
  BG:[42.7,25.5],BR:[-14.2,-51.9],CA:[56.1,-106.3],CL:[-35.7,-71.5],
  CN:[35.9,104.2],CO:[4.6,-74.1],HR:[45.1,15.2],CZ:[49.8,15.5],
  CD:[-4.0,21.8],DK:[56.3,9.5],EG:[26.8,30.8],ET:[9.1,40.5],
  FI:[61.9,25.7],FR:[46.2,2.2],DE:[51.2,10.5],GH:[7.9,-1.0],
  GR:[39.1,21.8],GT:[15.8,-90.2],HU:[47.2,19.5],IN:[20.6,79.0],
  ID:[-0.8,113.9],IR:[32.4,53.7],IQ:[33.2,43.7],IE:[53.4,-8.2],
  IL:[31.0,34.9],IT:[41.9,12.6],JP:[36.2,138.3],JO:[30.6,36.2],
  KZ:[48.0,68.0],KE:[-0.0,37.9],KP:[40.3,127.5],KR:[35.9,127.8],
  KW:[29.3,47.5],LB:[33.9,35.5],LY:[26.3,17.2],MY:[4.2,108.0],
  MX:[23.6,-102.6],MA:[31.8,-7.1],MM:[21.9,95.9],NG:[9.1,8.7],
  NL:[52.1,5.3],NZ:[-40.9,174.9],NO:[60.5,8.5],PK:[30.4,69.3],
  PE:[-9.2,-75.0],PH:[12.9,121.8],PL:[51.9,19.1],PT:[39.4,-8.2],
  QA:[25.4,51.2],RO:[45.9,25.0],RU:[61.5,105.3],SA:[23.9,45.1],
  SN:[14.5,-14.5],RS:[44.0,21.0],SG:[1.4,103.8],ZA:[-30.6,22.9],
  ES:[40.5,-3.7],LK:[7.9,80.8],SE:[60.1,18.6],CH:[46.8,8.2],
  SY:[34.8,39.0],TW:[23.7,121.0],TZ:[-6.4,34.9],TH:[15.9,100.9],
  TN:[33.9,9.5],TR:[38.9,35.2],UA:[48.4,31.2],AE:[23.4,53.8],
  GB:[55.4,-3.4],US:[37.1,-95.7],UZ:[41.4,64.6],VE:[6.4,-66.6],
  VN:[14.1,108.3],YE:[15.6,48.5],ZM:[-13.1,27.8],ZW:[-20.0,30.0],
}

// ─── Target countries that receive arc attacks ────────────────────────────────
const TARGETS = [
  { lat: 37.1, lng: -95.7,  label: 'US' },
  { lat: 51.5, lng: -0.1,   label: 'GB' },
  { lat: 48.9, lng: 2.4,    label: 'FR' },
  { lat: 52.5, lng: 13.4,   label: 'DE' },
  { lat: 35.7, lng: 139.7,  label: 'JP' },
  { lat: 37.6, lng: 126.9,  label: 'KR' },
  { lat: 25.2, lng: 55.3,   label: 'AE' },
  { lat: 1.4,  lng: 103.8,  label: 'SG' },
]

// ─── Flat fallback map (react-simple-maps, works without WebGL) ───────────────
const FLAT_GEO = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

function flatColor(count, max) {
  if (!count || count === 0) return '#1c2620'   // dark charcoal-green — land
  const t = count / max
  if (t >= 0.7) return '#ef4444'   // red
  if (t >= 0.4) return '#f97316'   // orange
  if (t >= 0.15) return '#eab308'  // yellow
  return '#4ade80'                  // green — minimal
}

function FlatMap({ rows, max }) {
  const byNumeric = useMemo(() => {
    const m = {}
    rows.forEach(r => { m[String(r.numeric)] = r })
    return m
  }, [rows])

  return (
    <ComposableMap
      projection="geoMercator"
      projectionConfig={{ scale: 118, center: [10, 15] }}
      style={{ width: '100%', height: 280, background: 'transparent' }}
    >
      <Geographies geography={FLAT_GEO}>
        {({ geographies }) =>
          geographies.map(geo => {
            const d = byNumeric[String(geo.id)]
            return (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill={flatColor(d?.count, max)}
                stroke="#050810"
                strokeWidth={0.4}
                style={{
                  default: { outline: 'none', transition: 'fill 0.2s' },
                  hover:   { fill: '#a78bfa', outline: 'none' },
                  pressed: { outline: 'none' },
                }}
              />
            )
          })
        }
      </Geographies>
    </ComposableMap>
  )
}

// ─── Colour helpers ───────────────────────────────────────────────────────────
// The globe texture (earth-dark.jpg) renders ocean as blue.
// Polygon overlays cover ONLY land — so we paint land dark and let the
// blue ocean texture show through unobstructed around the edges.
// Inactive land: solid dark charcoal — clearly NOT ocean-blue.
// Threat countries: fully opaque red/orange/yellow so they pop.
function polyFill(count, max) {
  if (!count || count === 0) return '#1c2620'   // very dark forest — land, zero ambiguity with blue ocean
  const t = count / max
  if (t >= 0.7) return '#ef4444'    // red — critical
  if (t >= 0.4) return '#f97316'    // orange — high
  if (t >= 0.15) return '#eab308'   // yellow — medium
  return '#4ade80'                   // green — minimal/observed
}

function arcColors(t) {
  if (t >= 0.7) return ['rgba(239,68,68,0.9)',  'rgba(239,68,68,0.03)']
  if (t >= 0.4) return ['rgba(249,115,22,0.85)', 'rgba(249,115,22,0.03)']
  return ['rgba(250,204,21,0.75)', 'rgba(250,204,21,0.03)']
}

// ─── Build arc dataset ────────────────────────────────────────────────────────
function buildArcs(rows, max) {
  const arcs = []
  const top  = rows
    .filter(r => r.iso2 && CENTROIDS[r.iso2])
    .sort((a, b) => b.count - a.count)
    .slice(0, 12)

  top.forEach(r => {
    const [lat, lng] = CENTROIDS[r.iso2]
    const t          = r.count / max
    const numTargets = t >= 0.5 ? 3 : t >= 0.2 ? 2 : 1
    const shuffled   = [...TARGETS].sort(() => Math.random() - 0.5)
    shuffled.slice(0, numTargets).forEach(tgt => {
      if (Math.abs(lat - tgt.lat) < 3 && Math.abs(lng - tgt.lng) < 3) return
      arcs.push({ startLat: lat, startLng: lng, endLat: tgt.lat, endLng: tgt.lng, t, label: `${r.country} → ${tgt.label}` })
    })
  })
  return arcs
}

// ─── Build point markers ──────────────────────────────────────────────────────
function buildPoints(rows, max) {
  return rows
    .filter(r => r.iso2 && CENTROIDS[r.iso2] && r.count > 0)
    .map(r => {
      const [lat, lng] = CENTROIDS[r.iso2]
      const t = r.count / max
      return {
        lat, lng,
        size:  0.4 + t * 1.2,
        color: t >= 0.7 ? '#ef4444' : t >= 0.4 ? '#f97316' : '#facc15',
        label: `${r.country}: ${r.count} actor${r.count !== 1 ? 's' : ''}`,
      }
    })
}

// ─── Inner Globe renderer (rendered inside Suspense) ─────────────────────────
function GlobeRenderer({ rows, max, countries, dims }) {
  const globeRef = useRef()

  // Country lookup maps
  const countByIso2 = useMemo(() => {
    const m = {}
    rows.forEach(r => { if (r.iso2) m[r.iso2] = r.count })
    return m
  }, [rows])

  const countByName = useMemo(() => {
    const m = {}
    rows.forEach(r => { if (r.country) m[r.country] = r.count })
    return m
  }, [rows])

  const arcs   = useMemo(() => buildArcs(rows, max),  [rows, max])
  const points = useMemo(() => buildPoints(rows, max), [rows, max])

  // Initialise rotation after mount
  useEffect(() => {
    const g = globeRef.current
    if (!g) return
    const ctrl = g.controls()
    ctrl.autoRotate      = true
    ctrl.autoRotateSpeed = 0.55
    ctrl.enableDamping   = true
    ctrl.dampingFactor   = 0.12
    g.pointOfView({ lat: 20, lng: 10, altitude: 2.2 }, 0)
  }, [])

  const polyColor = useCallback(feat => {
    const iso   = feat.properties?.ISO_A2 || feat.properties?.iso_a2 || ''
    const name  = feat.properties?.ADMIN  || feat.properties?.NAME  || ''
    const count = countByIso2[iso] ?? countByName[name] ?? 0
    return polyFill(count, max)
  }, [countByIso2, countByName, max])

  const polyLabel = useCallback(feat => {
    const name  = feat.properties?.ADMIN || feat.properties?.NAME || 'Unknown'
    const iso   = feat.properties?.ISO_A2 || ''
    const count = countByIso2[iso] ?? countByName[name] ?? 0
    const style = `font:12px/1.4 system-ui,sans-serif;background:#0d1b2e;color:${count > 0 ? '#e2e8f0' : '#64748b'};border:1px solid #1e3a5f;padding:4px 8px;border-radius:4px;pointer-events:none`
    return count > 0
      ? `<div style="${style}"><b>${name}</b><br>${count} threat actor${count !== 1 ? 's' : ''}</div>`
      : `<div style="${style}">${name}</div>`
  }, [countByIso2, countByName])

  return (
    <Globe
      ref={globeRef}
      width={dims.w}
      height={dims.h}
      backgroundColor="rgba(0,0,0,0)"
      atmosphereColor="#1d4ed8"
      atmosphereAltitude={0.16}
      globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
      bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
      polygonsData={countries.features}
      polygonCapColor={polyColor}
      polygonSideColor={() => '#111816'}
      polygonStrokeColor={() => '#0d1f3c'}
      polygonLabel={polyLabel}
      polygonAltitude={0.006}
      arcsData={arcs}
      arcColor={d => arcColors(d.t)}
      arcAltitude={0.25}
      arcStroke={0.45}
      arcDashLength={0.45}
      arcDashGap={0.55}
      arcDashAnimateTime={2000}
      arcLabel={d => d.label}
      pointsData={points}
      pointColor={d => d.color}
      pointAltitude={0.04}
      pointRadius={d => d.size}
      pointLabel={d => d.label}
    />
  )
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function GlobeMap() {
  const containerRef = useRef()
  const [dims, setDims]       = useState({ w: 760, h: 380 })
  const [countries, setCountries] = useState({ features: [] })
  const [geoReady, setGeoReady]   = useState(false)
  const [use3D, setUse3D]     = useState(true)

  const { data, isLoading } = useQuery({
    queryKey:  ['geo-summary'],
    queryFn:   fetchGeoSummary,
    staleTime: 5 * 60 * 1000,
  })

  const rows = data?.data ?? []
  const max  = rows.reduce((m, r) => Math.max(m, r.count), 1)

  // Fetch GeoJSON for globe polygons
  useEffect(() => {
    fetch(COUNTRIES_URL)
      .then(r => r.json())
      .then(d => { setCountries(d); setGeoReady(true) })
      .catch(() => setGeoReady(true))
  }, [])

  // Responsive container sizing
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.floor(entry.contentRect.width)
      setDims({ w, h: Math.min(440, Math.max(280, Math.floor(w * 0.44))) })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  const legend = [
    { color: '#ef4444', label: 'Critical' },
    { color: '#f97316', label: 'High' },
    { color: '#eab308', label: 'Medium' },
    { color: '#86efac', label: 'Low' },
    { color: '#374151', label: 'No activity' },
  ]

  return (
    <div ref={containerRef} className="relative w-full" style={{ minHeight: dims.h }}>

      {/* Mode toggle */}
      <button
        onClick={() => setUse3D(v => !v)}
        className="absolute top-2 left-2 z-30 text-[10px] px-2 py-1 rounded
                   bg-navy-800/80 border border-navy-500/60 text-slate-500
                   hover:text-slate-300 transition-colors backdrop-blur-sm"
      >
        {use3D ? '⬜ Flat' : '🌐 3D'}
      </button>

      {use3D ? (
        <>
          {/* Edge vignette */}
          <div className="pointer-events-none absolute inset-0 z-10"
               style={{ background: 'radial-gradient(ellipse at 50% 50%, transparent 52%, #030712 100%)' }} />

          <Suspense fallback={
            <div className="flex items-center justify-center text-xs text-slate-600"
                 style={{ height: dims.h }}>
              Loading 3D globe…
            </div>
          }>
            {geoReady && (
              <GlobeRenderer
                rows={rows}
                max={max}
                countries={countries}
                dims={dims}
              />
            )}
          </Suspense>

          {/* Arc count badge */}
          {rows.length > 0 && (
            <div className="absolute top-2 right-2 z-20 flex items-center gap-1.5 text-[11px]
                            bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-full
                            px-2.5 py-1 backdrop-blur-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              Live threat activity
            </div>
          )}
        </>
      ) : (
        <FlatMap rows={rows} max={max} />
      )}

      {/* Legend (shown in both modes) */}
      <div className="flex flex-wrap items-center gap-3 mt-2 text-[11px] text-slate-500">
        {legend.map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full inline-block" style={{ background: color }} />
            {label}
          </span>
        ))}
        {rows.length === 0 && !isLoading && (
          <span className="ml-auto text-slate-700 italic">
            Populates from actor origin attribution
          </span>
        )}
        {rows.length > 0 && (
          <span className="ml-auto text-slate-700">{rows.length} countries tracked</span>
        )}
      </div>
    </div>
  )
}
