import React, { useEffect, useRef, useState } from 'react'
import { WINDOWS } from '../api.js'

export function Card({ title, right, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      <header><h2>{title}</h2><div>{right}</div></header>
      <div className="body">{children}</div>
    </section>
  )
}

export function WindowSelect({ value, onChange }) {
  return (
    <select className="window" value={value} onChange={(e) => onChange(e.target.value)}
      aria-label="time window">
      {WINDOWS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
    </select>
  )
}

export const scoreClass = (s) => (s >= 70 ? 'hot' : s >= 35 ? 'warn' : 'dim')

export const Score = ({ value }) => (
  <span className={`score ${scoreClass(value)}`}>{Math.round(value ?? 0)}</span>
)

export const Tag = ({ children, tone }) => <span className={`tag ${tone || children}`}>{children}</span>

export function Ip({ ip, onPick }) {
  if (!onPick) return <span className="ip">{ip}</span>
  return <button className="ip link" onClick={() => onPick(ip)}>{ip}</button>
}

export function Empty({ children = 'nothing yet' }) {
  return <div className="empty">{children}</div>
}

// Load data now and every `every` ms; re-load when deps change.
export function usePoll(load, deps, every = 60000) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const fn = useRef(load)
  fn.current = load
  useEffect(() => {
    let alive = true
    const run = () => fn.current()
      .then((d) => { if (alive) { setData(d); setError(null) } })
      .catch((e) => { if (alive) setError(e) })
    run()
    const t = setInterval(run, every)
    return () => { alive = false; clearInterval(t) }
  }, deps) // eslint-disable-line react-hooks/exhaustive-deps
  return [data, error]
}
