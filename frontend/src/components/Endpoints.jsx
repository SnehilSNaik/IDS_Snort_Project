import React from 'react';
import { MonitorDot, Wifi, WifiOff, Server } from 'lucide-react';

export function Endpoints({ endpoints, summary, onRefresh }) {
  return <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><div><h2 style={{ fontSize: '19px', fontWeight: 800 }}>Endpoint Dashboard</h2><p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '4px' }}>{summary?.online || 0} of {summary?.total || 0} agents online</p></div><button className="btn" onClick={onRefresh}>Refresh</button></div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
      {(endpoints || []).length ? endpoints.map(endpoint => { const online = endpoint.status === 'online'; return <div key={endpoint.endpoint_id} className="glass-panel" style={{ padding: '19px', borderTop: `3px solid ${online ? '#74b59a' : '#71838b'}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><div style={{ display: 'flex', gap: '9px', alignItems: 'center' }}><MonitorDot color={online ? '#74b59a' : '#aabdc4'} /><strong>{endpoint.name}</strong></div><span style={{ color: online ? '#74b59a' : '#aabdc4', fontSize: '11px', fontWeight: 800 }}>{online ? <><Wifi size={12}/> ONLINE</> : <><WifiOff size={12}/> OFFLINE</>}</span></div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '18px', fontSize: '12px' }}><div><span style={{ color: 'var(--text-muted)' }}>IP</span><div style={{ fontFamily: 'var(--font-mono)', marginTop: '3px' }}>{endpoint.ip}</div></div><div><span style={{ color: 'var(--text-muted)' }}>Operating system</span><div style={{ marginTop: '3px' }}>{endpoint.os}</div></div><div><span style={{ color: 'var(--text-muted)' }}>Last heartbeat</span><div style={{ marginTop: '3px' }}>{endpoint.last_seen}</div></div><div><span style={{ color: 'var(--text-muted)' }}>Reported alerts</span><div style={{ marginTop: '3px', fontWeight: 800 }}>{endpoint.alert_count || 0}</div></div></div>
        <div style={{ marginTop: '15px', color: 'var(--text-muted)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '5px' }}><Server size={12}/> Agent {endpoint.agent_version || 'Unknown'} · {endpoint.hostname}</div>
      </div>; }) : <div className="glass-panel" style={{ padding: '32px', color: 'var(--text-muted)' }}>No endpoint agents are enrolled. Run <code>agent.py --server &lt;IDS-IP&gt; --name Lab-PC-01</code> on a lab endpoint.</div>}
    </div>
  </div>;
}
