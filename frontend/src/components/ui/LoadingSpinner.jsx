import React from 'react'

export default function LoadingSpinner({ text = 'Loading…' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div className="w-8 h-8 border-2 border-navy-400 border-t-sky-400 rounded-full animate-spin" />
      <span className="text-sm text-slate-600">{text}</span>
    </div>
  )
}

export function InlineSpinner() {
  return <div className="w-4 h-4 border-2 border-navy-400 border-t-sky-400 rounded-full animate-spin inline-block" />
}
