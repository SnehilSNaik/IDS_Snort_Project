import React from 'react';
import { Database, ShieldCheck, AlertOctagon, RefreshCw, Hash } from 'lucide-react';

export function AuditLog({ summary, verifyStatus, onVerify, onRefresh }) {
  const records = summary?.recent_records || [];
  const valid = verifyStatus?.valid ?? summary?.valid ?? true;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'linear-gradient(135deg, #527f91, #6d9fad)', display: 'grid', placeItems: 'center', color: '#fff' }}><Database size={20} /></div>
          <div><h2 style={{ fontSize: 18, fontWeight: 700 }}>Hash-Chained Audit Log</h2><p style={{ fontSize: 12, color: '#94a3b8' }}>SQLite records linked with SHA-256 hashes — simple, local, and tamper-evident.</p></div>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ padding: '8px 12px', borderRadius: 10, fontSize: 12, fontWeight: 700, color: valid ? '#10b981' : '#f43f5e', background: valid ? 'rgba(16,185,129,.1)' : 'rgba(244,63,94,.1)' }}>{valid ? <ShieldCheck size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} /> : <AlertOctagon size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />}{valid ? 'INTEGRITY VERIFIED' : 'INTEGRITY FAILED'}</span>
          <button className="btn" onClick={onVerify}><Hash size={14} /> Verify hashes</button><button className="btn" onClick={onRefresh}><RefreshCw size={14} /> Refresh</button>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        <div className="glass-panel" style={{ padding: 16, textAlign: 'center' }}><div style={{ fontSize: 32, fontWeight: 800, color: '#6d9fad' }}>{summary?.total_records ?? 0}</div><div style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Audit records</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: 'center' }}><div style={{ fontSize: 32, fontWeight: 800, color: '#10b981' }}>{valid ? 'OK' : 'CHECK'}</div><div style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase' }}>Hash-chain state</div></div>
      </div>
      <div className="glass-panel" style={{ padding: 20, overflowX: 'auto' }}>
        <h3 style={{ fontSize: 15, marginBottom: 14 }}>Recent security audit events</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 620 }}><thead><tr style={{ textAlign: 'left', borderBottom: '1px solid var(--glass-border)' }}><th>Time</th><th>Action</th><th>Subject</th><th>Detail</th><th>SHA-256</th></tr></thead><tbody>{records.length ? records.map(record => <tr key={record.id} style={{ borderBottom: '1px solid var(--glass-border)' }}><td style={{ padding: 10, fontSize: 12 }}>{record.timestamp}</td><td style={{ padding: 10, fontWeight: 700 }}>{record.action}</td><td style={{ padding: 10, fontFamily: 'var(--font-mono)' }}>{record.subject}</td><td style={{ padding: 10 }}>{record.detail}</td><td style={{ padding: 10, fontFamily: 'var(--font-mono)', color: '#6d9fad' }}>{record.record_hash?.slice(0, 16)}…</td></tr>) : <tr><td colSpan="5" style={{ padding: 20, color: '#94a3b8', textAlign: 'center' }}>New alerts and firewall blocks will appear here.</td></tr>}</tbody></table>
      </div>
    </div>
  );
}
