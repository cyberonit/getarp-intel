import React, { useEffect, useState } from 'react'
import { api, num, stamp } from '../api.js'
import { Empty, Score, Tag } from './ui.jsx'

export default function IpDetail({ ip, onClose }) {
  const [d, setD] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setD(null)
    api.ipDetail(ip).then(setD).catch(setError)
    const esc = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [ip, onClose])

  const i = d?.info
  return (
    <div className="scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label={`details for ${ip}`}>
        <header>
          <h2>{ip}</h2>
          <button className="close" onClick={onClose} aria-label="close">×</button>
        </header>
        {error && <Empty>could not load: {error.detail || error.message}</Empty>}
        {!d && !error && <Empty>loading…</Empty>}
        {i && (
          <>
            <dl className="facts">
              <dt>score</dt><dd><Score value={i.score} /></dd>
              <dt>class</dt><dd><Tag>{i.class}</Tag></dd>
              <dt>country</dt><dd>{i.country || '—'}</dd>
              <dt>network</dt><dd>{i.asn ? `AS${i.asn} · ${i.as_org || ''}` : '—'}</dd>
              <dt>reputation</dt><dd>{i.reputation || 'not checked'}</dd>
              <dt>first seen</dt><dd>{stamp(i.first_seen)}</dd>
              <dt>last seen</dt><dd>{stamp(i.last_seen)}</dd>
              <dt>events</dt><dd>{num(i.events)}</dd>
              <dt>services</dt><dd>{i.services.join(', ') || '—'}</dd>
              <dt>ports</dt><dd>{i.ports.join(' ') || '—'}</dd>
              <dt>sensors</dt><dd>{i.sensors.join(', ')}</dd>
            </dl>

            {d.profile && (
              <>
                <h3>after getting in · {d.profile.sessions} session{d.profile.sessions === 1 ? '' : 's'}</h3>
                {d.profile.tooling.length > 0 && (
                  <p className="faint">tooling: {d.profile.tooling.join(', ')} · tactics: {d.profile.tactics.join(', ')}</p>
                )}
                <pre className="cmds">{d.profile.commands.join('\n') || '(no commands)'}</pre>
              </>
            )}

            <h3>findings</h3>
            {!d.findings.length ? <Empty>none</Empty> : (
              <table><tbody>{d.findings.map((f, k) => (
                <tr key={k}><td className="faint">{stamp(f.ts)}</td>
                  <td><Tag tone={f.kind}>{f.type.replace('_', ' ')}</Tag></td>
                  <td>{f.service || ''}</td><td className="faint">{f.sensor}</td></tr>
              ))}</tbody></table>
            )}

            <h3>latest events</h3>
            <table><tbody>{d.events.map((e, k) => (
              <tr key={k}><td className="faint">{stamp(e.ts)}</td><td>{e.event_type}</td>
                <td>{e.service || ''}{e.dst_port ? `:${e.dst_port}` : ''}</td>
                <td className="evidence" title={e.command || e.signature || ''}>
                  {e.username != null ? `${e.username} / ${e.password ?? ''}` : (e.command || e.signature || '')}
                </td></tr>
            ))}</tbody></table>
          </>
        )}
      </aside>
    </div>
  )
}
