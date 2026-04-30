import React, { useState, useRef, useEffect } from 'react'
import { aiQuery } from '../api/client'
import { Bot, Send, Trash2, User } from 'lucide-react'
import { InlineSpinner } from '../components/ui/LoadingSpinner'

const QUICK_PROMPTS = [
  'What are the top active ransomware groups right now?',
  'Summarize current threat landscape based on collected intelligence.',
  'What TTPs are most frequently observed in recent reports?',
  'Which industries are being most targeted based on current data?',
  'List any critical CVEs that have been actively exploited.',
]

export default function AIAnalyst() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: '# VANTELLIGENCE AI Analyst\n\nI\'m powered by your local AI models and can help you analyze threat intelligence, research specific actors, or summarize patterns across collected data.\n\nAsk me anything about current threats, or use a quick prompt below.',
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async (text) => {
    const q = (text || input).trim()
    if (!q || loading) return
    setInput('')
    setMessages(m => [...m, { role: 'user', content: q }])
    setLoading(true)
    try {
      const result = await aiQuery(q)
      const answer = typeof result === 'string'
        ? result
        : result?.response || result?.summary || result?.analysis || JSON.stringify(result, null, 2)
      setMessages(m => [...m, { role: 'assistant', content: answer }])
    } catch (err) {
      setMessages(m => [...m, {
        role: 'assistant',
        content: `⚠️ **AI backend unavailable.** ${err.message}\n\nEnsure Ollama is running with your configured model (OLLAMA_PRIMARY_MODEL).`,
      }])
    } finally {
      setLoading(false)
    }
  }

  const renderContent = (text) => {
    // Basic markdown: bold, code blocks, headers
    return text
      .replace(/^### (.+)$/gm, '<h3 class="text-slate-200 font-semibold text-sm mt-3 mb-1">$1</h3>')
      .replace(/^## (.+)$/gm, '<h2 class="text-slate-100 font-bold text-base mt-4 mb-2">$1</h2>')
      .replace(/^# (.+)$/gm, '<h1 class="text-sky-400 font-black text-lg mt-4 mb-2">$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-200">$1</strong>')
      .replace(/`([^`]+)`/g, '<code class="bg-navy-600 text-sky-400 px-1 py-0.5 rounded text-xs font-mono">$1</code>')
      .replace(/\n/g, '<br/>')
  }

  return (
    <div className="flex flex-col h-[calc(100vh-120px)] gap-4">
      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
              msg.role === 'assistant'
                ? 'bg-sky-400/15 border border-sky-400/30 text-sky-400'
                : 'bg-violet-400/15 border border-violet-400/30 text-violet-400'
            }`}>
              {msg.role === 'assistant' ? <Bot size={15} /> : <User size={15} />}
            </div>
            <div className={`max-w-[80%] px-4 py-3 rounded-xl text-sm leading-relaxed ${
              msg.role === 'assistant'
                ? 'bg-navy-800 border border-navy-500 text-slate-300'
                : 'bg-violet-400/10 border border-violet-400/20 text-slate-200'
            }`}>
              <div dangerouslySetInnerHTML={{ __html: renderContent(msg.content) }} />
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                            bg-sky-400/15 border border-sky-400/30 text-sky-400">
              <Bot size={15} />
            </div>
            <div className="px-4 py-3 rounded-xl bg-navy-800 border border-navy-500
                            flex items-center gap-2 text-slate-500 text-sm">
              <InlineSpinner /> Analyzing…
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick prompts */}
      <div className="flex flex-wrap gap-2">
        {QUICK_PROMPTS.map((p, i) => (
          <button key={i}
            onClick={() => send(p)}
            disabled={loading}
            className="text-xs px-3 py-1.5 rounded-full border border-sky-400/30
                       text-sky-400/70 hover:text-sky-400 hover:border-sky-400/60
                       hover:bg-sky-400/5 transition-all disabled:opacity-40"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input */}
      <form onSubmit={e => { e.preventDefault(); send() }}
        className="flex gap-3 items-end">
        <div className="flex-1 relative">
          <textarea
            className="input w-full resize-none pr-12"
            rows={2}
            placeholder="Ask about threat actors, IOCs, campaigns, CVEs…"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
            }}
          />
        </div>
        <button type="submit" className="btn-primary h-10 flex items-center gap-2"
          disabled={loading || !input.trim()}>
          <Send size={14} /> Send
        </button>
        <button type="button"
          onClick={() => setMessages(msgs => msgs.slice(0, 1))}
          className="btn-ghost h-10 flex items-center gap-1.5 text-slate-600"
          title="Clear chat"
        >
          <Trash2 size={13} />
        </button>
      </form>
    </div>
  )
}
