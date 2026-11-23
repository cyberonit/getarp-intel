import React, { useEffect, useState } from 'react'
import { api } from './api.js'
import Overview from './components/Overview.jsx'
import { Attacks, Behavior, Scans } from './components/Lists.jsx'
import IpDetail from './components/IpDetail.jsx'
import Login from './components/Login.jsx'

const PAGES = [
  ['overview', 'Overview'],
  ['scans', 'Scans'],
  ['attacks', 'Attacks'],
  ['behavior', 'Behavior'],
]

export default function App() {
  const [page, setPage] = useState(() => location.hash.slice(1) || 'overview')
  const [who, setWho] = useState({ mode: 'public', user: null })
  const [pick, setPick] = useState(null)
  const [showLogin, setShowLogin] = useState(false)

  useEffect(() => { api.mode().then(setWho) }, [])
  useEffect(() => {
    const onHash = () => setPage(location.hash.slice(1) || 'overview')
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // Per-IP detail exists only on the admin site, after logging in.
  const onPick = who.mode === 'admin' ? setPick : null
  const go = (k) => { location.hash = k === 'overview' ? '' : k; setPage(k) }

  return (
    <div className="shell">
      <nav className="rail">
        <div className="brand">
          <div className="logo"><b>getarp</b> grid</div>
          <div className="sub">deception intel</div>
        </div>
        {PAGES.map(([k, label]) => (
          <button key={k} className={`nav ${page === k ? 'active' : ''}`} onClick={() => go(k)}>
            {label}
          </button>
        ))}
        <div className="grow" />
        {who.mode === 'guest' && (
          <button className="nav" onClick={() => setShowLogin(true)}>Sign in</button>
        )}
        {who.mode === 'admin' && (
          <button className="nav" onClick={async () => { await api.logout(); setWho({ mode: 'guest' }) }}>
            Sign out <span className="faint">{who.user}</span>
          </button>
        )}
        <div className="foot">
          getarp.net · v2.0<br />
          <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP data by DB-IP</a>
        </div>
      </nav>

      <main className="main">
        {page === 'overview' && <Overview onPick={onPick} />}
        {page === 'scans' && <Scans onPick={onPick} />}
        {page === 'attacks' && <Attacks onPick={onPick} />}
        {page === 'behavior' && <Behavior onPick={onPick} />}
      </main>

      {pick && <IpDetail ip={pick} onClose={() => setPick(null)} />}
      {showLogin && (
        <Login onClose={() => setShowLogin(false)}
          onDone={(user) => { setWho({ mode: 'admin', user }); setShowLogin(false) }} />
      )}
    </div>
  )
}
