import React, { useEffect, useState } from 'react'
import { api, clock, num } from '../api.js'
import { Card, Empty, Ip, Score, Tag, WindowSelect, usePoll } from './ui.jsx'

const FEED_LABEL = {
  service_sweep: 'sweep', bruteforce: 'brute force', credential_stuffing: 'cred stuffing',
  access: 'logged in', command_exec: 'commands', malware_download: 'malware', ids_alert: 'ids alert',
}

function Stat({ label, value, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="k">{label}</div>
      <div className="v">{num(value)}</div>
      <div className="rule" />
    </div>
  )
}

export default function Overview({ onPick }) {
  const [status, setStatus] = useState({})
  const [feed, setFeed] = useState([])
  const [cw, setCw] = useState('1h')
  const [aw, setAw] = useState('1h')
  const [ips] = usePoll(() => api.ips(25), [])
  const [countries] = usePoll(() => api.topCountries(cw), [cw])
  const [asns] = usePoll(() => api.topAs(aw), [aw])

  useEffect(() => {
    let alive = true
    const load = () => api.status().then((s) => {
      if (!alive) return
      setStatus(s)
      setFeed((f) => (f.length ? f : (s.recent || []).map((r) => ({ ...r, src_ip: r.ip, label: r.type }))))
    }).catch(() => {})
    load()
    const t = setInterval(load, 60000)
    const stop = api.live((m) => {
      if (m.type === 'status') setStatus((s) => ({ ...s, ...m }))
      if (m.type === 'finding') setFeed((f) => [m, ...f].slice(0, 30))
    })
    return () => { alive = false; clearInterval(t); stop() }
  }, [])

  const level = status.threat_level || 'low'
  const maxIps = Math.max(1, ...(countries || []).map((c) => c.ips))

  return (
    <>
      <div className="stats">
        <Stat label="live attackers · 5m" value={status.live_attackers} tone="hot" />
        <Stat label="new ips · 5m" value={status.new_ips_5m} tone="ok" />
        <Stat label="events / min" value={status.events_per_min} tone="warn" />
        <Stat label="new ips · 24h" value={status.new_ips_24h} />
        <Stat label="tracked hosts" value={status.tracked_hosts} />
      </div>

      <div className="threat">
        <span className={`dot ${level}`} />
        <span className="lvl">threat level — {level}</span>
        <span className="meta">
          {status.sensors_active != null && `${status.sensors_active} sensor${status.sensors_active === 1 ? '' : 's'} active · `}
          snapshot every minute · live feed via websocket
        </span>
      </div>

      <Card title="live feed" right="realtime" className="feed">
        {feed.length === 0 && <Empty>waiting for activity…</Empty>}
        {feed.map((e, i) => (
          <div key={i} className={`row sev${e.severity || 1}`}>
            <span className="t">{clock(e.ts)}</span>
            <Tag tone={e.kind}>{FEED_LABEL[e.label] || e.label}</Tag>
            <Ip ip={e.src_ip} onPick={onPick} />
            <span className="faint">{e.service || ''}</span>
            <span className="faint right">{e.sensor}</span>
          </div>
        ))}
      </Card>

      <div className="split">
        <Card title="top attackers" right="by threat score">
          {!ips?.length ? <Empty /> : (
            <table>
              <thead><tr><th>ip</th><th>score</th><th>class</th><th>country</th><th>as</th>
                <th className="n">svcs</th><th className="n">events</th></tr></thead>
              <tbody>{ips.map((r) => (
                <tr key={r.ip}>
                  <td><Ip ip={r.ip} onPick={onPick} /></td>
                  <td><Score value={r.score} /></td>
                  <td><Tag>{r.class}</Tag></td>
                  <td>{r.country || '—'}</td>
                  <td className="org">{r.as_org || '—'}</td>
                  <td className="n">{r.services}</td>
                  <td className="n">{num(r.events)}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>

        <div className="stack">
          <Card title="top countries" right={<WindowSelect value={cw} onChange={setCw} />}>
            {!countries?.length ? <Empty /> : countries.map((c) => (
              <div key={c.country} className="bar">
                <span className="cc">{c.country}</span>
                <span className="track"><span style={{ width: `${(c.ips / maxIps) * 100}%` }} /></span>
                <span className="n">{num(c.ips)}</span>
              </div>
            ))}
          </Card>
          <Card title="top AS" right={<WindowSelect value={aw} onChange={setAw} />}>
            {!asns?.length ? <Empty /> : (
              <table>
                <thead><tr><th>asn</th><th>org</th><th className="n">events</th></tr></thead>
                <tbody>{asns.map((a) => (
                  <tr key={a.asn}><td>{a.asn}</td><td className="org">{a.org || '—'}</td>
                    <td className="n">{num(a.events)}</td></tr>
                ))}</tbody>
              </table>
            )}
          </Card>
        </div>
      </div>
    </>
  )
}
