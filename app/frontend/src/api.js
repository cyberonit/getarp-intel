// Talks to the getarp API on the same site. The session is an HttpOnly cookie,
// so nothing secret is ever kept in the page.

async function call(method, path, body) {
  const r = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) {
    const err = new Error(`HTTP ${r.status}`)
    err.status = r.status
    try { err.detail = (await r.json()).detail } catch { /* not JSON */ }
    throw err
  }
  return r.json()
}

const get = (path) => call('GET', path)

export const api = {
  status: () => get('/status'),
  ips: (limit = 50) => get(`/ips?order=score&limit=${limit}`),
  topCountries: (w) => get(`/top-countries?window=${w}`),
  topAs: (w) => get(`/top-as?window=${w}`),
  findings: (kind, w) => get(`/findings?kind=${kind}&window=${w}`),
  behavior: (w) => get(`/behavior?window=${w}`),
  ipDetail: (ip) => get(`/ips/${encodeURIComponent(ip)}`),

  // "public": the public site (log-in routes do not exist there)
  // "guest": the admin site, not logged in   "admin": logged in
  async mode() {
    try {
      const me = await get('/me')
      return { mode: 'admin', user: me.user }
    } catch (e) {
      return { mode: e.status === 401 ? 'guest' : 'public', user: null }
    }
  },
  login: (username, password) => call('POST', '/auth/login', { username, password }),
  logout: () => call('POST', '/auth/logout'),

  // Live updates. Reconnects by itself; returns a function that stops it.
  live(onMessage) {
    let ws, stopped = false, delay = 1000
    const open = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${location.host}/api/ws`)
      ws.onopen = () => { delay = 1000 }
      ws.onmessage = (e) => {
        try {
          const m = JSON.parse(e.data)
          if (m.type !== 'ping') onMessage(m)
        } catch { /* ignore */ }
      }
      ws.onclose = () => {
        if (!stopped) setTimeout(open, delay)
        delay = Math.min(delay * 2, 30000)
      }
    }
    open()
    return () => { stopped = true; ws && ws.close() }
  },
}

export const WINDOWS = [['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']]

export function ago(ts) {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000)
  if (s < 60) return `${Math.round(s)}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export const clock = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false })
export const stamp = (ts) => new Date(ts).toLocaleString([], { hour12: false })
export const num = (n) => (n == null ? '—' : Number(n).toLocaleString('en-US'))
