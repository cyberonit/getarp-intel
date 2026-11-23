import React from 'react'

// Deterministic angle from an IP string so a host keeps its position between renders.
function hash(s) { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619) } return (h >>> 0) }

const color = (cls) => ({
  exploiter: 'var(--hot)', intruder: 'var(--hot)', bruteforcer: 'var(--warn)',
  scanner: 'var(--ours)', prober: 'var(--text-dim)',
}[cls] || 'var(--text-dim)')

// Attackers plotted on a sweep grid: closer to centre = higher threat ("inbound").
export default function Radar({ ips = [], onPick }) {
  const W = 520, H = 320, cx = W / 2, cy = H / 2, R = 140
  return (
    <svg className="radar" viewBox={`0 0 ${W} ${H}`}>
      {[0.33, 0.66, 1].map((f, i) => (
        <circle key={i} cx={cx} cy={cy} r={R * f} fill="none"
          stroke="var(--line)" strokeWidth="1" />
      ))}
      <line x1={cx - R} y1={cy} x2={cx + R} y2={cy} stroke="var(--line-soft)" />
      <line x1={cx} y1={cy - R} x2={cx} y2={cy + R} stroke="var(--line-soft)" />
      <text x={cx} y={cy + R + 18} textAnchor="middle"
        style={{ fontFamily: 'var(--mono)', fontSize: 9, fill: 'var(--text-faint)' }}>
        proximity = threat score
      </text>
      {ips.slice(0, 120).map((ip) => {
        const a = (hash(ip.src_ip) % 360) * Math.PI / 180
        const score = ip.threat_score || 5
        const r = R * (1 - Math.min(score, 100) / 100) * 0.92 + 6
        const x = cx + r * Math.cos(a), y = cy + r * Math.sin(a)
        const rad = 2 + Math.min(score, 100) / 22
        return (
          <g key={ip.src_ip} onClick={() => onPick && onPick(ip.src_ip)}
             style={{ cursor: 'pointer' }}>
            <circle cx={x} cy={y} r={rad} fill={color(ip.classification)}
              fillOpacity="0.85">
              {score >= 70 && (
                <animate attributeName="r" values={`${rad};${rad + 4};${rad}`}
                  dur="2s" repeatCount="indefinite" />
              )}
            </circle>
          </g>
        )
      })}
      <circle cx={cx} cy={cy} r="3" fill="var(--ours)" />
    </svg>
  )
}
