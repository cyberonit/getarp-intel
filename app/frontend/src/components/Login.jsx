import React, { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onDone, onClose }) {
  const [user, setUser] = useState('')
  const [pw, setPw] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api.login(user, pw)
      onDone(r.user)
    } catch (err) {
      setError(err.detail || 'could not sign in')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="scrim" onClick={onClose}>
      <form className="login" onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h2>sign in</h2>
        <label>user<input value={user} onChange={(e) => setUser(e.target.value)} autoFocus
          autoComplete="username" /></label>
        <label>password<input type="password" value={pw} onChange={(e) => setPw(e.target.value)}
          autoComplete="current-password" /></label>
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={busy || !user || !pw}>{busy ? '…' : 'sign in'}</button>
      </form>
    </div>
  )
}
