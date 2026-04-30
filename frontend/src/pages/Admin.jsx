import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchAdminSettings, saveAdminSettings,
  fetchApiKeys, createApiKey, revokeApiKey, reactivateApiKey,
  fetchBootstrapStatus, setStoredApiKey, getStoredApiKey,
} from '../api/client'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import {
  Globe, Key, Zap, Save, Plus, Trash2, RefreshCw,
  Eye, EyeOff, Copy, CheckCircle, AlertTriangle, ShieldAlert,
} from 'lucide-react'

// ─── Tabs ────────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'darkweb',     label: 'Dark Web',      icon: Globe },
  { id: 'apikeys',     label: 'API Keys',       icon: Key },
  { id: 'integrations',label: 'Integrations',   icon: Zap },
  { id: 'alerts',      label: 'Alerts',         icon: ShieldAlert },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

function useCopy() {
  const [copied, setCopied] = useState(false)
  const copy = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return { copy, copied }
}

// ─── Field components ────────────────────────────────────────────────────────

function ToggleField({ label, value, onChange, description }) {
  const on = value === 'true' || value === true || value === '1'
  return (
    <div className="flex items-start justify-between gap-4 py-3 border-b border-navy-600">
      <div>
        <p className="text-sm text-slate-300 font-medium">{label}</p>
        {description && <p className="text-xs text-slate-600 mt-0.5">{description}</p>}
      </div>
      <button
        type="button"
        onClick={() => onChange(on ? 'false' : 'true')}
        className={`relative shrink-0 w-11 h-6 rounded-full transition-colors duration-200 ${
          on ? 'bg-sky-500' : 'bg-navy-500'
        }`}
      >
        <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full
                          shadow transition-transform duration-200 ${on ? 'translate-x-5' : ''}`} />
      </button>
    </div>
  )
}

function TextField({ label, value, onChange, placeholder, type = 'text', source }) {
  const [show, setShow] = useState(false)
  const isSecret = type === 'secret'
  return (
    <div className="py-3 border-b border-navy-600">
      <div className="flex items-center justify-between mb-1">
        <label className="text-sm text-slate-300 font-medium">{label}</label>
        {source === 'env' && (
          <span className="text-[10px] text-slate-600 border border-navy-500 rounded px-1.5 py-0.5">
            from env
          </span>
        )}
        {source === 'db' && (
          <span className="text-[10px] text-sky-400/70 border border-sky-400/20 rounded px-1.5 py-0.5">
            saved in DB
          </span>
        )}
      </div>
      <div className="relative">
        <input
          type={isSecret && !show ? 'password' : 'text'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder || (isSecret ? '••••••••••••' : '')}
          className="input w-full pr-10 font-mono text-sm"
          autoComplete={isSecret ? 'new-password' : 'off'}
        />
        {isSecret && (
          <button type="button" onClick={() => setShow(s => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-600
                       hover:text-slate-400 transition-colors">
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
      </div>
    </div>
  )
}

function MultilineField({ label, value, onChange, placeholder, source }) {
  // Normalize: comma-separated → one per line for editing
  const asLines = (v) => (v || '').split(',').map(s => s.trim()).filter(Boolean).join('\n')
  const asComma = (v) => v.split('\n').map(s => s.trim()).filter(Boolean).join(',')
  const [local, setLocal] = useState(asLines(value))

  useEffect(() => { setLocal(asLines(value)) }, [value])

  return (
    <div className="py-3 border-b border-navy-600">
      <div className="flex items-center justify-between mb-1">
        <label className="text-sm text-slate-300 font-medium">{label}</label>
        {source === 'env' && (
          <span className="text-[10px] text-slate-600 border border-navy-500 rounded px-1.5 py-0.5">from env</span>
        )}
        {source === 'db' && (
          <span className="text-[10px] text-sky-400/70 border border-sky-400/20 rounded px-1.5 py-0.5">saved in DB</span>
        )}
      </div>
      <textarea
        rows={4}
        value={local}
        onChange={e => { setLocal(e.target.value); onChange(asComma(e.target.value)) }}
        placeholder={placeholder}
        className="input w-full resize-y font-mono text-xs"
      />
      <p className="text-[11px] text-slate-600 mt-1">One per line</p>
    </div>
  )
}

function SelectField({ label, value, onChange, options, source }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3 border-b border-navy-600">
      <div className="flex items-center gap-2">
        <label className="text-sm text-slate-300 font-medium">{label}</label>
        {source === 'env' && (
          <span className="text-[10px] text-slate-600 border border-navy-500 rounded px-1.5 py-0.5">from env</span>
        )}
        {source === 'db' && (
          <span className="text-[10px] text-sky-400/70 border border-sky-400/20 rounded px-1.5 py-0.5">saved in DB</span>
        )}
      </div>
      <select className="input" value={value} onChange={e => onChange(e.target.value)}>
        {(options || []).map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  )
}

// ─── Settings section ─────────────────────────────────────────────────────────

function SettingsSection({ schema, settings, onChange, group }) {
  const fields = schema.filter(s => s.group === group)
  return (
    <div className="space-y-0">
      {fields.map(s => {
        const entry = settings[s.key] || {}
        const value = entry.value ?? ''
        const source = entry.source || 'env'
        const handle = (v) => onChange(s.key, v)

        if (s.type === 'bool')
          return <ToggleField key={s.key} label={s.label} value={value} onChange={handle}
                              description={s.description} />
        if (s.type === 'multiline')
          return <MultilineField key={s.key} label={s.label} value={value} onChange={handle}
                                 placeholder={s.placeholder} source={source} />
        if (s.type === 'select')
          return <SelectField key={s.key} label={s.label} value={value} onChange={handle}
                              options={s.options} source={source} />
        // text or secret
        return <TextField key={s.key} label={s.label} value={value} onChange={handle}
                          placeholder={s.placeholder} type={s.type} source={source} />
      })}
    </div>
  )
}

// ─── Dark Web tab ─────────────────────────────────────────────────────────────

function DarkWebTab({ schema, settings, onSave, saving }) {
  const [local, setLocal] = useState(settings)
  const [dirty, setDirty] = useState(false)

  useEffect(() => { setLocal(settings); setDirty(false) }, [settings])

  const handle = (key, val) => {
    setLocal(p => ({ ...p, [key]: { ...p[key], value: val } }))
    setDirty(true)
  }

  const save = () => onSave(
    Object.fromEntries(
      schema.filter(s => s.group === 'darkweb').map(s => [s.key, local[s.key]?.value ?? ''])
    )
  )

  const enabled = local['dark_web_enabled']?.value
  const isOn = enabled === 'true' || enabled === true || enabled === '1'

  return (
    <div className="space-y-4">
      <div className={`card border-l-4 ${isOn ? 'border-green-400/50' : 'border-slate-700'}`}>
        <div className="flex items-center gap-2 mb-1">
          <Globe size={15} className={isOn ? 'text-green-400' : 'text-slate-600'} />
          <p className="text-sm font-semibold text-slate-300">Dark Web Monitor</p>
          <span className={`ml-auto text-xs px-2 py-0.5 rounded-full ${
            isOn ? 'bg-green-400/10 text-green-400 border border-green-400/30'
                 : 'bg-navy-600 text-slate-500 border border-navy-500'
          }`}>{isOn ? 'Enabled' : 'Disabled'}</span>
        </div>
        <p className="text-xs text-slate-600">
          Monitors Tor hidden services and dark web indexes for keyword mentions.
          Uses Ahmia.fi (clearnet) by default; direct .onion access requires a working Tor proxy.
        </p>
      </div>

      <div className="card">
        <SettingsSection schema={schema} settings={local} onChange={handle} group="darkweb" />
        <div className="mt-4 flex justify-end">
          <button
            onClick={save}
            disabled={!dirty || saving}
            className="btn-primary flex items-center gap-2"
          >
            {saving ? <RefreshCw size={13} className="animate-spin" /> : <Save size={13} />}
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
        </div>
      </div>

      <div className="card border border-navy-500">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
          Tor Proxy Status
        </p>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <AlertTriangle size={13} className="text-amber-500 shrink-0" />
          <span>
            Tor requires outbound port 443 and 9001/9030. If the tor-proxy container is stuck
            bootstrapping, check that your server's firewall allows outbound Tor traffic.
            Ahmia.fi clearnet search works without Tor.
          </span>
        </div>
      </div>
    </div>
  )
}

// ─── API Keys tab ─────────────────────────────────────────────────────────────

function APIKeysTab() {
  const qc = useQueryClient()
  const [newLabel, setNewLabel] = useState('')
  const [newPerms, setNewPerms] = useState(['read'])
  const [freshKey, setFreshKey] = useState(null)   // shown once after creation
  const [storedKey, setStored] = useState(getStoredApiKey())
  const { copy, copied } = useCopy()

  const { data, isLoading } = useQuery({ queryKey: ['admin-api-keys'], queryFn: fetchApiKeys })
  const keys = data?.keys ?? []
  const bootstrap = data?.bootstrap_mode ?? true

  const createMut = useMutation({
    mutationFn: createApiKey,
    onSuccess: (result) => {
      setFreshKey(result)
      setNewLabel('')
      qc.invalidateQueries({ queryKey: ['admin-api-keys'] })
    },
  })

  const revokeMut = useMutation({
    mutationFn: revokeApiKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-api-keys'] }),
  })

  const reactivateMut = useMutation({
    mutationFn: reactivateApiKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-api-keys'] }),
  })

  const handleStore = (key) => {
    setStoredApiKey(key)
    setStored(key)
  }

  if (isLoading) return <LoadingSpinner />

  return (
    <div className="space-y-4">
      {/* Bootstrap banner */}
      {bootstrap && (
        <div className="card border border-amber-500/30 bg-amber-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle size={16} className="text-amber-500 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-amber-400">Bootstrap Mode Active</p>
              <p className="text-xs text-slate-500 mt-0.5">
                No API keys exist yet. All endpoints are open. Create your first key below to
                enable authentication, then save it in your browser to authorize future requests.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Active key in browser */}
      <div className="card">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
          Browser Session Key
        </p>
        <div className="flex items-center gap-2">
          <input
            type="password"
            value={storedKey}
            onChange={e => setStored(e.target.value)}
            placeholder="Paste API key to authenticate this browser session…"
            className="input flex-1 font-mono text-xs"
          />
          <button onClick={() => handleStore(storedKey)} className="btn-primary text-xs">
            Use Key
          </button>
          {storedKey && (
            <button onClick={() => { setStoredApiKey(''); setStored('') }}
              className="btn-ghost text-xs text-rose-500">
              Clear
            </button>
          )}
        </div>
        {storedKey && (
          <p className="text-xs text-green-400 mt-1 flex items-center gap-1">
            <CheckCircle size={11} /> Active — all requests include this key
          </p>
        )}
      </div>

      {/* Fresh key alert */}
      {freshKey && (
        <div className="card border border-green-400/40 bg-green-400/5">
          <div className="flex items-start gap-3">
            <CheckCircle size={16} className="text-green-400 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-green-400">Key Created — Copy It Now</p>
              <p className="text-xs text-slate-500 mt-0.5 mb-2">
                This key will not be shown again. Store it securely.
              </p>
              <div className="flex items-center gap-2 bg-navy-800 rounded border border-green-400/30 px-3 py-2">
                <code className="text-green-300 text-xs font-mono flex-1 break-all">{freshKey.key}</code>
                <button onClick={() => copy(freshKey.key)}
                  className="text-slate-500 hover:text-green-400 transition-colors shrink-0">
                  {copied ? <CheckCircle size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <button
                onClick={() => handleStore(freshKey.key)}
                className="mt-2 text-xs text-sky-400 hover:text-sky-300 transition-colors"
              >
                → Use this key for my browser session
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create form */}
      <div className="card">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Generate New Key
        </p>
        <div className="flex flex-wrap gap-2 items-end">
          <input
            className="input flex-1 min-w-[200px]"
            placeholder="Label (e.g. SIEM Integration, Dashboard)"
            value={newLabel}
            onChange={e => setNewLabel(e.target.value)}
          />
          <div className="flex gap-1">
            {['read', 'write', 'admin'].map(p => (
              <button key={p} type="button"
                onClick={() => setNewPerms(prev =>
                  prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]
                )}
                className={`text-xs px-2.5 py-1.5 rounded border transition-colors ${
                  newPerms.includes(p)
                    ? 'border-sky-400/50 text-sky-400 bg-sky-400/10'
                    : 'border-navy-500 text-slate-600 hover:text-slate-400'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
          <button
            onClick={() => createMut.mutate({ label: newLabel || 'Unnamed key', permissions: newPerms })}
            disabled={createMut.isPending}
            className="btn-primary flex items-center gap-1.5"
          >
            {createMut.isPending
              ? <RefreshCw size={13} className="animate-spin" />
              : <Plus size={13} />
            }
            Generate
          </button>
        </div>
      </div>

      {/* Key list */}
      <div className="card">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {keys.length} Key{keys.length !== 1 ? 's' : ''}
        </p>
        {keys.length === 0
          ? <p className="text-slate-600 text-sm text-center py-6">No keys yet.</p>
          : (
            <div className="divide-y divide-navy-600">
              {keys.map(k => (
                <div key={k.id} className="flex items-center gap-3 py-3">
                  <div className="w-2 h-2 rounded-full shrink-0 mt-0.5"
                       style={{ background: k.active ? '#4ade80' : '#3d5a80' }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-slate-200 text-sm font-medium">{k.label}</span>
                      {(k.permissions || []).map(p => (
                        <span key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-navy-600
                                                  border border-navy-500 text-slate-500">{p}</span>
                      ))}
                      {!k.active && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/10
                                         border border-rose-500/30 text-rose-400">revoked</span>
                      )}
                    </div>
                    <div className="text-xs text-slate-600 font-mono mt-0.5">
                      {k.key_prefix}… · Created {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}
                      {k.last_used && ` · Last used ${new Date(k.last_used).toLocaleDateString()}`}
                    </div>
                  </div>
                  {k.active
                    ? (
                      <button
                        onClick={() => window.confirm('Revoke this key?') && revokeMut.mutate(k.id)}
                        disabled={revokeMut.isPending}
                        className="text-slate-600 hover:text-rose-500 transition-colors p-1"
                        title="Revoke key"
                      >
                        <Trash2 size={14} />
                      </button>
                    ) : (
                      <button
                        onClick={() => reactivateMut.mutate(k.id)}
                        disabled={reactivateMut.isPending}
                        className="text-slate-600 hover:text-green-400 transition-colors p-1 text-xs"
                        title="Re-activate key"
                      >
                        <RefreshCw size={14} />
                      </button>
                    )
                  }
                </div>
              ))}
            </div>
          )
        }
      </div>
    </div>
  )
}

// ─── Generic settings tab ─────────────────────────────────────────────────────

function GenericSettingsTab({ group, schema, settings, onSave, saving, description }) {
  const [local, setLocal] = useState(settings)
  const [dirty, setDirty] = useState(false)

  useEffect(() => { setLocal(settings); setDirty(false) }, [settings])

  const handle = (key, val) => {
    setLocal(p => ({ ...p, [key]: { ...p[key], value: val } }))
    setDirty(true)
  }

  const save = () => onSave(
    Object.fromEntries(
      schema.filter(s => s.group === group).map(s => [s.key, local[s.key]?.value ?? ''])
    )
  )

  return (
    <div className="card">
      {description && (
        <p className="text-xs text-slate-600 mb-4 pb-3 border-b border-navy-600">{description}</p>
      )}
      <SettingsSection schema={schema} settings={local} onChange={handle} group={group} />
      <div className="mt-4 flex justify-end">
        <button
          onClick={save}
          disabled={!dirty || saving}
          className="btn-primary flex items-center gap-2"
        >
          {saving ? <RefreshCw size={13} className="animate-spin" /> : <Save size={13} />}
          {saving ? 'Saving…' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

// ─── Main Admin page ──────────────────────────────────────────────────────────

export default function Admin() {
  const [tab, setTab] = useState('darkweb')
  const [saveSuccess, setSaveSuccess] = useState(false)
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['admin-settings'],
    queryFn: fetchAdminSettings,
  })

  const saveMut = useMutation({
    mutationFn: saveAdminSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-settings'] })
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 3000)
    },
  })

  if (isLoading) return <LoadingSpinner text="Loading admin settings…" />

  const settings = data?.settings ?? {}
  const schema   = data?.schema   ?? []

  return (
    <div className="max-w-3xl space-y-5">
      {/* Save success toast */}
      {saveSuccess && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-green-400/10 border
                        border-green-400/30 rounded-lg text-green-400 text-sm">
          <CheckCircle size={14} />
          Settings saved successfully — changes take effect on next collector run.
        </div>
      )}

      {/* Tab strip */}
      <div className="flex rounded-lg border border-navy-500 overflow-hidden w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors
                        border-l border-navy-500 first:border-l-0 ${
              tab === id
                ? 'bg-sky-400/15 text-sky-400'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <Icon size={13} />{label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'darkweb' && (
        <DarkWebTab
          schema={schema}
          settings={settings}
          onSave={saveMut.mutate}
          saving={saveMut.isPending}
        />
      )}

      {tab === 'apikeys' && <APIKeysTab />}

      {tab === 'integrations' && (
        <GenericSettingsTab
          group="feeds"
          schema={schema}
          settings={settings}
          onSave={saveMut.mutate}
          saving={saveMut.isPending}
          description="External API keys for threat intelligence feeds and IOC enrichment. Values are stored encrypted in the database and applied to feed collectors without restarting containers."
        />
      )}

      {tab === 'alerts' && (
        <GenericSettingsTab
          group="alerts"
          schema={schema}
          settings={settings}
          onSave={saveMut.mutate}
          saving={saveMut.isPending}
          description="Configure SMTP email alerts for watchlist hits. Alerts are sent when a watched asset is found in a threat feed."
        />
      )}
    </div>
  )
}
