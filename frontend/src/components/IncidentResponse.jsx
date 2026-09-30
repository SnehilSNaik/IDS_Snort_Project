import React, { useState } from 'react';
import { ShieldAlert, Ban, CheckCircle2, RefreshCw, Lock, Terminal, FileText } from 'lucide-react';

export function IncidentResponse({ scores, incidents, playbooks, blockedIPsList, onBlockIP, onUnblockIP, onRefresh }) {
  const [activeSubTab, setActiveSubTab] = useState('scores');
  const [manualIP, setManualIP] = useState('');
  const [manualReason, setManualReason] = useState('');
  const [test, setTest] = useState({ source: '', target: '', note: '', result: '' });
  const [testMessage, setTestMessage] = useState('');
  const [savingTest, setSavingTest] = useState(false);

  const saveTest = async (event) => {
    event.preventDefault();
    setSavingTest(true);
    try {
      const response = await fetch(`/api/firewall/reachability/${encodeURIComponent(test.source)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_ip: test.target.trim(), note: test.note.trim(), reachable: test.result === 'reachable' }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Could not save test');
      setTestMessage(test.result === 'reachable' ? 'Block ineffective: operator-reported access succeeded. Alert suppression is disabled for this target.' : 'Unreachable result recorded. This does not by itself prove the firewall caused it.');
      onRefresh();
    } catch (error) { setTestMessage(error.message); }
    finally { setSavingTest(false); }
  };

  const handleManualBlock = (e) => {
    e.preventDefault();
    if (!manualIP) return;
    onBlockIP(manualIP, manualReason || 'Manual block', 'HIGH', 'MANUAL');
    setManualIP('');
    setManualReason('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* IR Sub Navigation */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'linear-gradient(135deg, #0ea5e9, #6366f1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff' }}>
              <ShieldAlert size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 700 }}>Automated Incident Response</h2>
              <p style={{ fontSize: '12px', color: '#94a3b8' }}>Playbook engine rule enforcement & per-IP threat score leaderboard</p>
            </div>
          </div>
          <button className="btn" onClick={onRefresh}>
            <RefreshCw size={14} /> Refresh IR Data
          </button>
        </div>

        <div style={{ display: 'flex', gap: '8px', background: 'rgba(0,0,0,0.2)', padding: '4px', borderRadius: '10px', width: 'fit-content' }}>
          <button
            className="btn"
            style={{ border: 'none', background: activeSubTab === 'scores' ? 'rgba(56,189,248,0.2)' : 'transparent', color: activeSubTab === 'scores' ? '#38bdf8' : '#94a3b8' }}
            onClick={() => setActiveSubTab('scores')}
          >
            📊 Threat Scores
          </button>
          <button
            className="btn"
            style={{ border: 'none', background: activeSubTab === 'incidents' ? 'rgba(56,189,248,0.2)' : 'transparent', color: activeSubTab === 'incidents' ? '#38bdf8' : '#94a3b8' }}
            onClick={() => setActiveSubTab('incidents')}
          >
            📋 Incident Log
          </button>
          <button
            className="btn"
            style={{ border: 'none', background: activeSubTab === 'playbooks' ? 'rgba(56,189,248,0.2)' : 'transparent', color: activeSubTab === 'playbooks' ? '#38bdf8' : '#94a3b8' }}
            onClick={() => setActiveSubTab('playbooks')}
          >
            📜 Playbook Rules
          </button>
        </div>
      </div>

      {/* Sub-Tab 1: Threat Scores */}
      {activeSubTab === 'scores' && (
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '16px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px' }}>
            Per-IP Threat Leaderboard
          </h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--glass-border)', textAlign: 'left' }}>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>#</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Attacker IP</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Threat Score</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Alerts</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Severity</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Last Seen</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {scores && scores.length > 0 ? (
                  scores.map((s, i) => {
                    const danger = s.score >= 10;
                    return (
                      <tr key={s.ip} style={{ borderBottom: '1px solid var(--glass-border)' }}>
                        <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>{i + 1}</td>
                        <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: danger ? '#f43f5e' : '#f8fafc' }}>{s.ip}</td>
                        <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '16px', fontWeight: 800, color: danger ? '#f43f5e' : '#38bdf8' }}>
                          {s.score} {danger && <span style={{ fontSize: '10px', color: '#f43f5e', background: 'rgba(244,63,94,0.15)', padding: '2px 8px', borderRadius: '10px', marginLeft: '8px' }}>QUARANTINE</span>}
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'var(--font-mono)' }}>{s.alerts}</td>
                        <td style={{ padding: '12px' }}><span className={`sev-badge sev-${s.severity || 'LOW'}`}>{s.severity || 'LOW'}</span></td>
                        <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#94a3b8' }}>{s.last_seen}</td>
                        <td style={{ padding: '12px' }}>
                          <button className="btn-block" onClick={() => onBlockIP(s.ip, 'Threat score quarantine', 'HIGH', 'THREAT_SCORE')}><Ban size={12} /> Block</button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr><td colSpan="7" style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>No threat scores recorded yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 2: Incident Log */}
      {activeSubTab === 'incidents' && (
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '16px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px' }}>
            Automated Execution History
          </h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--glass-border)', textAlign: 'left' }}>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>#</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Timestamp</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Playbook</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Trigger</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Source IP</th>
                  <th style={{ padding: '12px', fontSize: '11px', color: '#94a3b8' }}>Actions Taken</th>
                </tr>
              </thead>
              <tbody>
                {incidents && incidents.length > 0 ? (
                  incidents.map((inc) => (
                    <tr key={inc.incident_id} style={{ borderBottom: '1px solid var(--glass-border)' }}>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>{inc.incident_id}</td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#94a3b8' }}>{inc.timestamp}</td>
                      <td style={{ padding: '12px' }}>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: '#38bdf8' }}>{inc.playbook_id}</div>
                        <div style={{ fontSize: '11px', color: '#94a3b8' }}>{inc.playbook_name}</div>
                      </td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{inc.trigger_type}</td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{inc.src_ip}</td>
                      <td style={{ padding: '12px' }}>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {inc.actions_taken?.map((act) => (
                            <span key={act} style={{ padding: '2px 8px', borderRadius: '6px', fontSize: '10px', fontWeight: 700, background: 'rgba(99,102,241,0.15)', color: '#6366f1' }}>{act}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr><td colSpan="6" style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>No automated incidents logged.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: Playbook Rules */}
      {activeSubTab === 'playbooks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {playbooks && playbooks.length > 0 ? (
            playbooks.map((pb) => (
              <div key={pb.id} className="glass-panel" style={{ padding: '18px 24px', display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700, padding: '4px 10px', borderRadius: '6px', background: 'rgba(56,189,248,0.1)', color: '#38bdf8' }}>
                  {pb.id}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '15px', fontWeight: 700, marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {pb.name} <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 700 }}>● ACTIVE</span>
                  </div>
                  <div style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '8px' }}>{pb.description}</div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {pb.actions?.map((act) => (
                      <span key={act} style={{ padding: '2px 10px', borderRadius: '8px', fontSize: '10px', fontWeight: 700, background: 'rgba(99,102,241,0.15)', color: '#6366f1' }}>{act}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="glass-panel" style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>No playbooks configured.</div>
          )}
        </div>
      )}

      {/* Firewall Panel */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Lock size={18} color="#f43f5e" /> IP Firewall — Monitoring PC
        </h3>
        <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>Rules apply to inbound traffic on this PC. Separate victims need their own firewall or an enforcing gateway. Rule checks confirm configuration; test service access from Kali to check effectiveness.</p>
        
        <form onSubmit={handleManualBlock} style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="IP Address to block (e.g. 1.2.3.4)"
            value={manualIP}
            onChange={(e) => setManualIP(e.target.value)}
            style={{ flex: 1, minWidth: '220px', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.3)', color: '#fff', fontFamily: 'var(--font-mono)' }}
          />
          <input
            type="text"
            placeholder="Reason (optional)"
            value={manualReason}
            onChange={(e) => setManualReason(e.target.value)}
            style={{ flex: 1, minWidth: '200px', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.3)', color: '#fff' }}
          />
          <button type="submit" className="btn-block" style={{ padding: '10px 20px' }}>Block IP</button>
        </form>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--glass-border)', textAlign: 'left' }}>
                <th style={{ padding: '10px 14px', fontSize: '11px', color: '#94a3b8' }}>Blocked IP</th>
                <th style={{ padding: '10px 14px', fontSize: '11px', color: '#94a3b8' }}>Blocked At</th>
                <th style={{ padding: '10px 14px', fontSize: '11px', color: '#94a3b8' }}>Reason</th>
                <th style={{ padding: '10px 14px', fontSize: '11px', color: '#94a3b8' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {blockedIPsList && blockedIPsList.length > 0 ? (
                blockedIPsList.map((e) => (
                  <tr key={e.ip} style={{ borderBottom: '1px solid var(--glass-border)', background: 'rgba(244,63,94,0.04)' }}>
                    <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f43f5e' }}>{e.ip}</td>
                    <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#94a3b8' }}>{e.blocked_at}</td>
                    <td style={{ padding: '10px 14px', fontSize: '12px', color: '#94a3b8' }}>{e.reason}<div style={{ marginTop: 5, color: e.firewall_rule ? '#10b981' : '#f59e0b' }}>{e.firewall_rule ? 'Inbound rule verified on monitoring PC' : 'OS rule unverified — alerts remain enabled'}</div>{Object.entries(e.reachability_checks || {}).map(([ip, result]) => <div key={ip} style={{ marginTop: 5, color: result.reachable ? '#f43f5e' : '#94a3b8' }}>{ip}: {result.reachable ? 'Block ineffective' : 'Service unreachable'} (operator reported) · {result.note} · {result.checked_at}</div>)}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <button className="btn-unblock" onClick={() => onUnblockIP(e.ip)}><CheckCircle2 size={12} /> Unblock</button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="4" style={{ padding: '20px', textAlign: 'center', color: '#94a3b8' }}>No IPs currently blocked in Firewall.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <form onSubmit={saveTest} style={{ marginTop: 20, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <strong style={{ width: '100%' }}>Record a test performed from Kali</strong>
          <select aria-label="Test attacker IP" required value={test.source} onChange={e => setTest({ ...test, source: e.target.value })}><option value="">Select attacker IP</option>{(blockedIPsList || []).map(e => <option key={e.ip} value={e.ip}>{e.ip}</option>)}</select>
          <input aria-label="Test target monitoring PC IP" required placeholder="Monitoring PC IP" value={test.target} onChange={e => setTest({ ...test, target: e.target.value })} />
          <input aria-label="Tested service and evidence" required maxLength={500} placeholder="Service/port and result evidence" value={test.note} onChange={e => setTest({ ...test, note: e.target.value })} />
          <select aria-label="Service reachability result" required value={test.result} onChange={e => setTest({ ...test, result: e.target.value })}><option value="">Choose observed result</option><option value="reachable">Access succeeded after block</option><option value="unreachable">Service unreachable after block</option></select>
          <button className="btn" type="submit" disabled={savingTest}>{savingTest ? 'Saving…' : 'Save test result'}</button>
          {testMessage && <div role="status" style={{ width: '100%', color: '#f59e0b' }}>{testMessage}</div>}
        </form>
      </div>
    </div>
  );
}
