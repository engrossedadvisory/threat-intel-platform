import React, { useState } from 'react'
import clsx from 'clsx'

export default function DataTable({ columns, data, pageSize = 25, className }) {
  const [page, setPage] = useState(0)
  const total = data?.length ?? 0
  const pages = Math.ceil(total / pageSize)
  const slice = data?.slice(page * pageSize, (page + 1) * pageSize) ?? []

  return (
    <div className={clsx('flex flex-col gap-2', className)}>
      <div className="overflow-x-auto rounded-lg border border-navy-500">
        <table className="w-full text-xs text-slate-400 border-collapse">
          <thead>
            <tr className="bg-navy-700">
              {columns.map(col => (
                <th key={col.key}
                  className="text-left px-3 py-2.5 font-semibold uppercase tracking-wider
                             text-slate-600 border-b border-navy-500 whitespace-nowrap">
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((row, i) => (
              <tr key={i}
                className="border-b border-navy-600 hover:bg-navy-700/50 transition-colors">
                {columns.map(col => (
                  <td key={col.key} className="px-3 py-2 align-top">
                    {col.render ? col.render(row[col.key], row) : (
                      <span className="font-mono">{String(row[col.key] ?? '—')}</span>
                    )}
                  </td>
                ))}
              </tr>
            ))}
            {slice.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-3 py-8 text-center text-slate-600">
                  No data
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="flex items-center justify-between text-xs text-slate-600">
          <span>{total.toLocaleString()} total rows</span>
          <div className="flex items-center gap-1">
            <button
              disabled={page === 0}
              onClick={() => setPage(p => p - 1)}
              className="px-2 py-1 rounded bg-navy-700 hover:bg-navy-600 disabled:opacity-30 transition-colors"
            >← Prev</button>
            <span className="px-2">
              {page + 1} / {pages}
            </span>
            <button
              disabled={page >= pages - 1}
              onClick={() => setPage(p => p + 1)}
              className="px-2 py-1 rounded bg-navy-700 hover:bg-navy-600 disabled:opacity-30 transition-colors"
            >Next →</button>
          </div>
        </div>
      )}
    </div>
  )
}
