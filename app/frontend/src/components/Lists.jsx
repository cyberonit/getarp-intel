import React, { useState } from 'react'
import { api, num, stamp } from '../api.js'
import { Card, Empty, Ip, Score, Tag, WindowSelect, usePoll } from './ui.jsx'

const SEVERITY = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' }

function evidence(f) {
  const d = f.detail || {}
  switch (f.type) {
    case 'bruteforce':
    case 'credential_stuffing':
      return `${d.attempts} attempts · ${(d.usernames || []).slice(0, 4).join(', ')}`
    case 'access': return `logged in as ${d.username ?? '?'}`
    case 'command_exec': return d.command
    case 'malware_download': return d.url
    case 'ids_alert': return d.signature
    default: return ''
  }
}

function Page({ title, load, render, empty }) {
  const [w, setW] = useState('24h')
  const [rows, error] = usePoll(() => load(w), [w])
  return (
    <Card title={title} right={<><span className="count">{rows ? num(rows.length) : ''}</span>
      <WindowSelect value={w} onChange={setW} /></>}>
      {error && <Empty>could not load: {error.message}</Empty>}
      {rows && !rows.length && <Empty>{empty}</Empty>}
      {rows?.length > 0 && render(rows)}
    </Card>
  )
}

export function Scans({ onPick }) {
  return (
    <Page title="scans" empty="no scans in this window" load={(w) => api.findings('scan', w)}
      render={(rows) => (
        <table>
          <thead><tr><th>time</th><th>ip</th><th>type</th><th>ports</th><th>country</th>
            <th>as</th><th>sensor</th></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}><td className="faint">{stamp(r.ts)}</td><td><Ip ip={r.ip} onPick={onPick} /></td>
              <td><Tag tone="scanner">{r.type.replace('_', ' ')}</Tag></td>
              <td className="faint">{(r.detail?.ports || []).join(' ')}</td>
              <td>{r.country || '—'}</td><td className="org">{r.as_org || '—'}</td>
              <td className="faint">{r.sensor}</td></tr>
          ))}</tbody>
        </table>
      )} />
  )
}

export function Attacks({ onPick }) {
  return (
    <Page title="attacks" empty="no attacks in this window" load={(w) => api.findings('attack', w)}
      render={(rows) => (
        <table>
          <thead><tr><th>time</th><th>ip</th><th>type</th><th>service</th><th>severity</th>
            <th>evidence</th><th>sensor</th></tr></thead>
          <tbody>{rows.map((r, i) => (
            <tr key={i}><td className="faint">{stamp(r.ts)}</td><td><Ip ip={r.ip} onPick={onPick} /></td>
              <td><Tag tone="attack">{r.type.replace('_', ' ')}</Tag></td>
              <td>{r.service || '—'}</td>
              <td><span className={`sev s${r.severity}`}>{SEVERITY[r.severity]}</span></td>
              <td className="evidence" title={evidence(r)}>{evidence(r)}</td>
              <td className="faint">{r.sensor}</td></tr>
          ))}</tbody>
        </table>
      )} />
  )
}

export function Behavior({ onPick }) {
  return (
    <Page title="behaviour" empty="no intruder activity in this window" load={(w) => api.behavior(w)}
      render={(rows) => (
        <table>
          <thead><tr><th>ip</th><th>score</th><th>class</th><th>country</th>
            <th className="n">sessions</th><th className="n">commands</th><th>tooling</th>
            <th>tactics</th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.ip}><td><Ip ip={r.ip} onPick={onPick} /></td><td><Score value={r.score} /></td>
              <td><Tag>{r.class}</Tag></td><td>{r.country || '—'}</td>
              <td className="n">{r.sessions}</td><td className="n">{r.commands}</td>
              <td className="faint">{(r.tooling || []).join(', ') || '—'}</td>
              <td className="faint">{(r.tactics || []).join(', ') || '—'}</td></tr>
          ))}</tbody>
        </table>
      )} />
  )
}
