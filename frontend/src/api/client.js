/**
 * VANTELLIGENCE API client
 * All requests go through /api/v1/ — nginx proxies to FastAPI in production,
 * Vite dev proxy handles it in development.
 */

const BASE = '/api/v1'

// Retrieve stored API key (set from Admin → API Keys tab after first key creation)
export function getStoredApiKey() {
  return localStorage.getItem('vntl_api_key') || ''
}
export function setStoredApiKey(key) {
  if (key) localStorage.setItem('vntl_api_key', key)
  else localStorage.removeItem('vntl_api_key')
}

async function req(path, options = {}) {
  const apiKey = getStoredApiKey()
  const headers = {
    'Content-Type': 'application/json',
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    ...options.headers,
  }
  const res = await fetch(`${BASE}${path}`, { headers, ...options })
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
  return res.json()
}

// ── Stats & Dashboard ─────────────────────────────────────────────────────────
export const fetchStats         = ()           => req('/stats')
export const fetchDashboard     = ()           => req('/dashboard')
export const fetchFeedStatus    = ()           => req('/feed-status')

// ── Reports ───────────────────────────────────────────────────────────────────
export const fetchReports       = (params = {}) =>
  req(`/reports?${new URLSearchParams(params)}`)
export const fetchReport        = (id)         => req(`/reports/${id}`)

// ── IOCs ──────────────────────────────────────────────────────────────────────
export const fetchIOCs          = (params = {}) =>
  req(`/iocs?${new URLSearchParams(params)}`)
export const searchIOC          = (value)      =>
  req('/iocs/search', { method: 'POST', body: JSON.stringify({ value }) })
export const fetchIOCsByType    = ()           => req('/iocs/by-type')
export const fetchIOCActivity   = ()           => req('/iocs/activity')

// ── CVEs ──────────────────────────────────────────────────────────────────────
export const fetchCVEs          = (params = {}) =>
  req(`/cves?${new URLSearchParams(params)}`)

// ── Actors ────────────────────────────────────────────────────────────────────
export const fetchActors        = ()           => req('/actors')
export const fetchOperationalActors = ()       => req('/actors/operational')

// ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
export const fetchTechniques    = (params = {}) =>
  req(`/techniques?${new URLSearchParams(params)}`)
export const fetchTTPUsage      = ()           => req('/ttps/usage')

// ── Watchlist ─────────────────────────────────────────────────────────────────
export const fetchWatchlist     = ()           => req('/watchlist')
export const addWatchlistItem   = (body)       =>
  req('/watchlist', { method: 'POST', body: JSON.stringify(body) })
export const deleteWatchlistItem = (id)        =>
  req(`/watchlist/${id}`, { method: 'DELETE' })
export const fetchWatchlistHits = (params = {}) =>
  req(`/alerts?${new URLSearchParams(params)}`)

// ── Geo ───────────────────────────────────────────────────────────────────────
export const fetchGeoSummary    = ()           => req('/geo/summary')

// ── Dark Web ──────────────────────────────────────────────────────────────────
export const fetchDarkWeb       = (params = {}) =>
  req(`/darkweb?${new URLSearchParams(params)}`)

// ── AI ────────────────────────────────────────────────────────────────────────
export const aiQuery            = (prompt)     =>
  req('/ai/query', { method: 'POST', body: JSON.stringify({ prompt }) })
export const aiAnalyze          = (text, context = '') =>
  req('/ai/analyze', { method: 'POST', body: JSON.stringify({ text, context }) })

// ── Admin — settings ──────────────────────────────────────────────────────────
export const fetchAdminSettings    = ()            => req('/admin/settings')
export const saveAdminSettings     = (settings)    =>
  req('/admin/settings', { method: 'PUT', body: JSON.stringify(settings) })
export const fetchBootstrapStatus  = ()            => req('/admin/bootstrap')

// ── Admin — API keys ──────────────────────────────────────────────────────────
export const fetchApiKeys          = ()            => req('/admin/api-keys')
export const createApiKey          = (body)        =>
  req('/admin/api-keys', { method: 'POST', body: JSON.stringify(body) })
export const revokeApiKey          = (id)          =>
  req(`/admin/api-keys/${id}`, { method: 'DELETE' })
export const reactivateApiKey      = (id)          =>
  req(`/admin/api-keys/${id}/activate`, { method: 'POST' })
