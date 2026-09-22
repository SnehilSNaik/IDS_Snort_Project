import React, { useState } from 'react';
import { Shield, ShieldAlert, AlertTriangle, ShieldCheck, Activity, RefreshCw, Trash2, Ban, CheckCircle2, ChevronDown, ChevronUp } from 'lucide-react';

export function LiveRadar({ stats, alerts, onRefresh, onClearAlerts, onBlockIP, onUnblockIP, blockedIPs, endpoints, endpointSummary, mlMetrics }) {
  const [expandedAlert, setExpandedAlert] = useState(null);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Metric Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '13px', fontWeight: 600 }}>
            <span>TOTAL ATTACKS</span>
            <Shield size={18} color="#38bdf8" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '38px', fontWeight: 800 }}>{stats.total || 0}</div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px', borderLeft: '4px solid #f43f5e' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '13px', fontWeight: 600 }}>
            <span>HIGH SEVERITY</span>
            <ShieldAlert size={18} color="#f43f5e" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '38px', fontWeight: 800, color: '#f43f5e' }}>{stats.high || 0}</div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '13px', fontWeight: 600 }}>
            <span>MEDIUM SEVERITY</span>
            <AlertTriangle size={18} color="#f59e0b" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '38px', fontWeight: 800, color: '#f59e0b' }}>{stats.medium || 0}</div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px', borderLeft: '4px solid #10b981' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '13px', fontWeight: 600 }}>
            <span>LOW SEVERITY</span>
            <ShieldCheck size={18} color="#10b981" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '38px', fontWeight: 800, color: '#10b981' }}>{stats.low || 0}</div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px', borderLeft: '4px solid #c084fc' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#94a3b8', fontSize: '13px', fontWeight: 600 }}>
            <span>AVG CONFIDENCE</span>
            <Activity size={18} color="#c084fc" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '38px', fontWeight: 800 }}>
            {stats.avg_confidence || 0}<span style={{ fontSize: '20px', color: '#94a3b8' }}>%</span>
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <div><strong>ML evaluation — held-out benchmark test set</strong><div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>{mlMetrics?.status === 'ok' ? `${mlMetrics.model} · ${mlMetrics.mode} · ${mlMetrics.test_samples} test flows · trained ${mlMetrics.trained_at}` : 'Metrics appear here after the next model-training run.'}</div>{mlMetrics?.status === 'ok' && <div style={{ fontSize: 11, color: '#aabdc4', marginTop: 4 }}>{mlMetrics.evaluation_scope || 'Benchmark results are not a guarantee of live-network performance.'}</div>}</div>
          {mlMetrics?.status === 'ok' && <div style={{ display: 'flex', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 13 }}><span>Precision <b style={{ color: '#38bdf8' }}>{mlMetrics.precision}%</b></span><span>Recall <b style={{ color: '#10b981' }}>{mlMetrics.recall}%</b></span><span>F1 <b style={{ color: '#c084fc' }}>{mlMetrics.f1}%</b></span><span>Accuracy <b>{mlMetrics.accuracy}%</b></span><span style={{ color: '#94a3b8' }}>FP {mlMetrics.confusion_matrix?.fp} · FN {mlMetrics.confusion_matrix?.fn}</span></div>}
        </div>
      </div>

      <div>
        <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#94a3b8', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
          Endpoint Fleet — {endpointSummary?.online || 0}/{endpointSummary?.total || 0} online
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
          {(endpoints || []).length ? endpoints.map(endpoint => (
            <div key={endpoint.endpoint_id} className="glass-panel" style={{ padding: '14px', borderLeft: `4px solid ${endpoint.status === 'online' ? '#10b981' : '#64748b'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                <strong style={{ fontSize: '14px' }}>{endpoint.name}</strong>
                <span style={{ color: endpoint.status === 'online' ? '#10b981' : '#94a3b8', fontSize: '11px', fontWeight: 800, textTransform: 'uppercase' }}>{endpoint.status}</span>
              </div>
              <div style={{ marginTop: '7px', color: '#94a3b8', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{endpoint.ip} · {endpoint.os}</div>
              <div style={{ marginTop: '5px', color: '#94a3b8', fontSize: '11px' }}>Last seen: {endpoint.last_seen} · Alerts: {endpoint.alert_count || 0}</div>
            </div>
          )) : <div style={{ color: '#94a3b8', fontSize: '13px' }}>No endpoint agents registered yet. Start an agent with <code>--server &lt;IDS-IP&gt;</code>.</div>}
        </div>
      </div>

      {/* Triggered Protocols */}
      <div>
        <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#94a3b8', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
          Protocols Triggered
        </h3>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {stats.protocols && Object.keys(stats.protocols).length > 0 ? (
            Object.entries(stats.protocols).map(([proto, count]) => (
              <div key={proto} className="glass-panel" style={{ padding: '10px 18px', display: 'flex', alignItems: 'center', gap: '12px', borderRadius: '12px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 800, color: '#38bdf8' }}>{count}</span>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#94a3b8', letterSpacing: '1px' }}>{proto}</span>
              </div>
            ))
          ) : (
            <div style={{ color: '#94a3b8', fontSize: '13px' }}>No protocol activity recorded.</div>
          )}
        </div>
      </div>

      {/* Live Alert Table Header & Actions */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Activity size={20} color="#38bdf8" /> Live Alert Stream
          </h2>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn" onClick={onRefresh}>
              <RefreshCw size={14} /> Refresh
            </button>
            <button className="btn btn-danger" onClick={onClearAlerts}>
              <Trash2 size={14} /> Clear All
            </button>
          </div>
        </div>

        {/* Live Table */}
        <div className="glass-panel" style={{ overflowX: 'auto', borderRadius: '16px' }}>
          <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--glass-border)', background: 'rgba(0,0,0,0.2)' }}>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Timestamp</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Severity</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Type</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Protocol</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Source IP</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Dest IP</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Detected By</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>MITRE ATT&CK</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Confidence</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Threat Intel</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Message</th>
                  <th style={{ padding: '14px 18px', fontSize: '11px', color: '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts && alerts.length > 0 ? (
                  alerts.map((a) => {
                    const isBlocked = blockedIPs.has(a.src_ip);
                    const hasFlowDetails = Boolean(a.flow_features);
                    const isExpanded = expandedAlert === a.id;
                    return (
                      <React.Fragment key={a.id || Math.random()}><tr style={{ borderBottom: '1px solid var(--glass-border)', background: isBlocked ? 'rgba(244,63,94,0.06)' : 'transparent' }}>
                        <td style={{ padding: '12px 18px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#94a3b8' }}>{a.timestamp}</td>
                        <td style={{ padding: '12px 18px' }}><span className={`sev-badge sev-${a.severity}`}>{a.severity}</span></td>
                        <td style={{ padding: '12px 18px' }}>
                          <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '6px', background: 'rgba(99,102,241,0.15)', color: '#6366f1' }}>
                            {a.type}
                          </span>
                          {a.protected_asset && <div style={{ marginTop: 5, color: '#79b9c7', fontSize: 10, fontWeight: 700 }}>Asset: {a.protected_asset}</div>}
                        </td>
                        <td style={{ padding: '12px 18px' }}>
                          <span style={{ color: '#38bdf8', fontSize: '12px', fontWeight: 700, background: 'rgba(56,189,248,0.1)', padding: '2px 8px', borderRadius: '6px' }}>{a.protocol}</span>
                        </td>
                        <td style={{ padding: '12px 18px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: isBlocked ? '#f43f5e' : '#f8fafc' }}>
                          {a.src_ip} {isBlocked && <span style={{ fontSize: '10px', color: '#f43f5e', background: 'rgba(244,63,94,0.15)', padding: '2px 6px', borderRadius: '8px', marginLeft: '6px' }}>Blocked</span>}
                        </td>
                        <td style={{ padding: '12px 18px', fontFamily: 'var(--font-mono)', fontSize: '13px', color: '#94a3b8' }}>{a.dst_ip}</td>
                        <td style={{ padding: '12px 18px', fontSize: '12px', color: '#94a3b8' }}>{a.victim_name ? `Endpoint: ${a.victim_name}` : 'Network IDS'}</td>
                        <td style={{ padding: '12px 18px', minWidth: '170px' }}>
                          {a.mitre_technique_id ? <div><div style={{ color: '#79b9c7', fontFamily: 'var(--font-mono)', fontWeight: 800, fontSize: '11px' }}>{a.mitre_technique_id}</div><div style={{ color: '#edf4f5', fontSize: '11px', marginTop: '3px' }}>{a.mitre_technique}</div><div style={{ color: '#aabdc4', fontSize: '10px', marginTop: '2px' }}>{a.mitre_tactic}</div></div> : <span style={{ color: '#aabdc4', fontSize: '11px' }}>Not mapped</span>}
                        </td>
                        <td style={{ padding: '12px 18px', fontFamily: 'var(--font-mono)' }}>{a.confidence}%</td>
                        <td style={{ padding: '12px 18px' }}>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {a.ti_confirmed && <span className="ti-badge ti-confirmed">TI CONFIRMED</span>}
                            {a.ti_country && <span className="ti-badge ti-country">🌍 {a.ti_country}</span>}
                            {a.ti_org && <span className="ti-badge" style={{ background: 'rgba(14,165,233,0.1)', color: '#0ea5e9' }}>🏢 {a.ti_org.slice(0, 18)}</span>}
                            {a.ti_abuse_score !== undefined && <span className="ti-badge ti-abuse-med">🎯 {a.ti_abuse_score}%</span>}
                          </div>
                        </td>
                        <td style={{ padding: '12px 18px', fontSize: '12px', color: '#94a3b8', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.message}>
                          {a.message}
                        </td>
                        <td style={{ padding: '12px 18px' }}>
                          {hasFlowDetails && <button className="btn" style={{ padding: '5px 8px', marginRight: 6, fontSize: 11 }} onClick={() => setExpandedAlert(isExpanded ? null : a.id)}>{isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />} Flow</button>}
                          {isBlocked ? (
                            <button className="btn-unblock" onClick={() => onUnblockIP(a.src_ip)}><CheckCircle2 size={12} /> Unblock</button>
                          ) : (
                            <button className="btn-block" onClick={() => onBlockIP(a.src_ip, 'Blocked from Live Stream', a.severity, a.type)}><Ban size={12} /> Block</button>
                          )}
                        </td>
                      </tr>{isExpanded && <tr><td colSpan="13" style={{ padding: '0 18px 14px' }}><div style={{ padding: 14, borderRadius: 10, background: 'rgba(56,189,248,.07)', color: '#dbeafe', fontSize: 12 }}><strong>CIC-IDS flow evidence</strong><div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: '8px 16px', fontFamily: 'var(--font-mono)' }}><span>5-tuple: {a.src_ip} → {a.dst_ip}:{a.flow_features.destination_port} ({a.protocol})</span><span>Duration: {a.flow_duration_seconds}s / {a.flow_features.duration_us} μs</span><span>Forward: {a.flow_features.forward_packets} packets, {a.flow_features.forward_bytes} B</span><span>Rate: {a.flow_features.packets_per_second} pkt/s, {a.flow_features.bytes_per_second} B/s</span><span>TCP flags: SYN {a.flow_features.syn_flags}, PSH {a.flow_features.psh_flags}, ACK {a.flow_features.ack_flags}</span></div></div></td></tr>}</React.Fragment>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan="12" style={{ textAlign: 'center', padding: '48px', color: '#94a3b8' }}>
                      No threat activity recorded yet. Radar clear.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
