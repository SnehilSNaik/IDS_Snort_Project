import React from 'react';
import { Radar, SearchCheck, ShieldCheck, Ban, GitMerge, Clock3 } from 'lucide-react';

const iconFor = {
  DETECTED: Radar,
  THREAT_INTEL: SearchCheck,
  CORRELATED: GitMerge,
  BLOCKED: Ban,
};

export function AttackTimeline({ events, onRefresh }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '19px', fontWeight: 800 }}>Attack Timeline</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '4px' }}>Detection → intelligence → correlation → containment</p>
        </div>
        <button className="btn" onClick={onRefresh}><Clock3 size={15} /> Refresh</button>
      </div>
      <div className="glass-panel" style={{ padding: '18px' }}>
        {(events || []).length ? events.map((event) => {
          const Icon = iconFor[event.stage] || ShieldCheck;
          const color = event.stage === 'BLOCKED' ? '#d96b73' : event.stage === 'THREAT_INTEL' ? '#d4a36a' : '#79b9c7';
          return <div key={event.id} style={{ display: 'grid', gridTemplateColumns: '34px minmax(130px, 165px) 1fr', gap: '14px', padding: '14px 0', borderBottom: '1px solid var(--glass-border)' }}>
            <div style={{ width: '30px', height: '30px', borderRadius: '50%', background: `${color}22`, color, display: 'grid', placeItems: 'center' }}><Icon size={15} /></div>
            <div><div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{event.timestamp}</div><div style={{ marginTop: '4px', fontSize: '11px', color, fontWeight: 800 }}>{event.stage.replace('_', ' ')}</div></div>
            <div><strong style={{ fontSize: '14px' }}>{event.title}</strong><div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '4px' }}>{event.detail}</div><div style={{ marginTop: '5px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--accent-blue)' }}>{event.src_ip}</div></div>
          </div>;
        }) : <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>No events yet. Start the IDS engine and run a safe demonstration scenario.</div>}
      </div>
    </div>
  );
}
