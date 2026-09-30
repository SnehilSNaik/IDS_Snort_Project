import React, { useState, useEffect, useRef } from 'react';
import { Activity, ShieldAlert, Database, Route, Monitor } from 'lucide-react';
import { Header } from './components/Header';
import { LiveRadar } from './components/LiveRadar';
import { IncidentResponse } from './components/IncidentResponse';
import { AuditLog } from './components/AuditLog';
import { AttackTimeline } from './components/AttackTimeline';
import { Endpoints } from './components/Endpoints';
import { soundEngine } from './utils/soundEngine';

export default function App() {
  const [activeTab, setActiveTab] = useState('radar');
  const [isEngineRunning, setIsEngineRunning] = useState(false);
  const [lastSync, setLastSync] = useState('');
  
  // Data states
  const [stats, setStats] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState(new Set());
  const [blockedIPsList, setBlockedIPsList] = useState([]);
  const [threatScores, setThreatScores] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [auditSummary, setAuditSummary] = useState({ total_records: 0, recent_records: [], valid: true });
  const [verifyStatus, setVerifyStatus] = useState({ valid: true });
  const [endpoints, setEndpoints] = useState([]);
  const [endpointSummary, setEndpointSummary] = useState({ total: 0, online: 0 });
  const [timeline, setTimeline] = useState([]);
  const [mlMetrics, setMlMetrics] = useState({ status: 'not_trained' });

  const knownAlertIds = useRef(new Set());

  // Polling functions
  const fetchStats = async () => {
    try {
      const res = await fetch('/api/stats');
      const data = await res.json();
      setStats(data);
      setLastSync(new Date().toLocaleTimeString());
    } catch (e) {}
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts');
      const data = await res.json();
      const newAlerts = data.alerts || [];

      // Check for sound triggers on newly arrived alerts
      let hasCorrelated = false;
      let worstSev = null;
      let isNewArrival = false;

      newAlerts.forEach(a => {
        if (!knownAlertIds.current.has(a.id)) {
          knownAlertIds.current.add(a.id);
          isNewArrival = true;
          if (a.type === 'CORRELATED_ATTACK') hasCorrelated = true;
          if (a.type === 'CORRELATED_ATTACK' || a.severity === 'HIGH') worstSev = 'HIGH';
          else if (a.severity === 'MEDIUM' && worstSev !== 'HIGH') worstSev = 'MEDIUM';
        }
      });

      if (isNewArrival) {
        if (hasCorrelated) soundEngine.playCorrelated();
        else if (worstSev === 'HIGH') soundEngine.playHigh();
        else if (worstSev === 'MEDIUM') soundEngine.playMedium();
      }

      setAlerts(newAlerts);
    } catch (e) {}
  };

  const fetchBlockedIPs = async () => {
    try {
      const res = await fetch('/api/firewall/blocked');
      const data = await res.json();
      if (data.status === 'ok') {
        setBlockedIPs(new Set(data.blocked_ips || []));
        setBlockedIPsList(data.blocked || []);
      }
    } catch (e) {}
  };

  const fetchIRData = async () => {
    try {
      const [scoresRes, incRes, pbRes] = await Promise.all([
        fetch('/api/response/threat_scores'),
        fetch('/api/response/incidents'),
        fetch('/api/response/playbooks')
      ]);
      const scoresData = await scoresRes.json();
      const incData = await incRes.json();
      const pbData = await pbRes.json();

      if (scoresData.status === 'ok') setThreatScores(scoresData.scores || []);
      if (incData.status === 'ok') setIncidents(incData.incidents || []);
      if (pbData.status === 'ok') setPlaybooks(pbData.playbooks || []);
    } catch (e) {}
  };

  const fetchAuditData = async () => {
    try {
      const res = await fetch('/api/audit/stats');
      const data = await res.json();
      if (data.status === 'ok') {
        setAuditSummary(data);
      }
    } catch (e) {}
  };

  const fetchEndpoints = async () => {
    try {
      const res = await fetch('/api/endpoints');
      const data = await res.json();
      if (data.status === 'ok') {
        setEndpoints(data.endpoints || []);
        setEndpointSummary({ total: data.total || 0, online: data.online || 0 });
      }
    } catch (e) {}
  };

  const fetchTimeline = async () => {
    try {
      const res = await fetch('/api/timeline?limit=120');
      const data = await res.json();
      if (data.status === 'ok') setTimeline(data.events || []);
    } catch (e) {}
  };

  const fetchMlMetrics = async () => {
    try {
      const res = await fetch('/api/ml/metrics');
      setMlMetrics(await res.json());
    } catch (e) {}
  };

  const verifyAudit = async () => {
    try {
      const res = await fetch('/api/audit/verify');
      const data = await res.json();
      setVerifyStatus(data);
      if (!data.valid) soundEngine.playTamper();
    } catch (e) {}
  };

  // User Actions
  const handleStartEngine = async () => {
    try {
      const res = await fetch('/api/start_engine', { method: 'POST' });
      const data = await res.json();
      if (data.status === 'ok') setIsEngineRunning(true);
    } catch (e) {}
  };

  const handleStopEngine = async () => {
    try {
      const res = await fetch('/api/stop_engine', { method: 'POST' });
      const data = await res.json();
      if (data.status === 'ok') setIsEngineRunning(false);
    } catch (e) {}
  };

  const handleClearAlerts = async () => {
    if (!window.confirm('Purge all active alerts from log?')) return;
    try {
      await fetch('/api/clear', { method: 'POST' });
      knownAlertIds.current.clear();
      fetchAlerts();
      fetchStats();
    } catch (e) {}
  };

  const handleResetAllData = async () => {
    if (!window.confirm('⚠️ RESET ALL DEMO DATA?\n\nThis clears alerts, incident data, the threat-intelligence cache, and the local hash-chained audit log for a fresh demo.')) return;
    try {
      const res = await fetch('/api/reset_all_data', { method: 'POST' });
      const data = await res.json();
      if (data.status === 'ok') {
        knownAlertIds.current.clear();
        fetchStats();
        fetchAlerts();
        fetchBlockedIPs();
        fetchIRData();
        fetchAuditData();
        fetchEndpoints();
        fetchTimeline();
        verifyAudit();
      }
    } catch (e) {}
  };

  const handleBlockIP = async (ip, reason, severity, attackType) => {
    if (!ip) return;
    try {
      const res = await fetch(`/api/firewall/block/${encodeURIComponent(ip)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason || 'Blocked from React UI', severity: severity || 'HIGH', attack_type: attackType || 'MANUAL' })
      });
      const data = await res.json();
      if (data.status === 'ok') {
        soundEngine.playBlock();
        fetchBlockedIPs();
        fetchIRData();
        fetchAuditData();
      }
    } catch (e) {}
  };

  const handleUnblockIP = async (ip) => {
    if (!ip) return;
    try {
      const res = await fetch(`/api/firewall/unblock/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.status === 'ok') {
        fetchBlockedIPs();
        fetchIRData();
        fetchAuditData();
      }
    } catch (e) {}
  };

  // Initial & interval polling setup
  useEffect(() => {
    fetchStats();
    fetchAlerts();
    fetchBlockedIPs();
    fetchIRData();
    fetchAuditData();
    fetchEndpoints();
    fetchTimeline();
    fetchMlMetrics();
    verifyAudit();

    const t1 = setInterval(fetchStats, 600);
    const t2 = setInterval(fetchAlerts, 800);
    const t3 = setInterval(() => {
      fetchBlockedIPs();
      fetchIRData();
      fetchAuditData();
      fetchEndpoints();
      fetchTimeline();
    }, 5000);

    return () => {
      clearInterval(t1);
      clearInterval(t2);
      clearInterval(t3);
    };
  }, []);

  return (
    <div className="container">
      <Header
        isEngineRunning={isEngineRunning}
        onStartEngine={handleStartEngine}
        onStopEngine={handleStopEngine}
        onResetAllData={handleResetAllData}
        lastSync={lastSync}
      />

      {/* Main Top Navigation Tabs */}
      <nav style={{ display: 'flex', gap: '12px', borderBottom: '2px solid var(--glass-border)', paddingBottom: '12px' }}>
        <button
          className="btn"
          style={{
            padding: '12px 24px', borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            background: activeTab === 'radar' ? 'linear-gradient(135deg, #527f91, #6d9fad)' : 'rgba(228,241,243,0.055)',
            color: activeTab === 'radar' ? '#fff' : 'var(--text-muted)',
            borderColor: activeTab === 'radar' ? '#79b9c7' : 'var(--glass-border)'
          }}
          onClick={() => setActiveTab('radar')}
        >
          <Activity size={18} /> 📡 Live Security Radar
        </button>

        <button
          className="btn"
          style={{
            padding: '12px 24px', borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            background: activeTab === 'timeline' ? 'linear-gradient(135deg, #527f91, #6d9fad)' : 'rgba(228,241,243,0.055)',
            color: activeTab === 'timeline' ? '#fff' : 'var(--text-muted)',
            borderColor: activeTab === 'timeline' ? '#79b9c7' : 'var(--glass-border)'
          }}
          onClick={() => setActiveTab('timeline')}
        ><Route size={18} /> Attack Timeline</button>

        <button
          className="btn"
          style={{
            padding: '12px 24px', borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            background: activeTab === 'endpoints' ? 'linear-gradient(135deg, #527f91, #6d9fad)' : 'rgba(228,241,243,0.055)',
            color: activeTab === 'endpoints' ? '#fff' : 'var(--text-muted)',
            borderColor: activeTab === 'endpoints' ? '#79b9c7' : 'var(--glass-border)'
          }}
          onClick={() => setActiveTab('endpoints')}
        ><Monitor size={18} /> Endpoints</button>

        <button
          className="btn"
          style={{
            padding: '12px 24px', borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            background: activeTab === 'incident' ? 'linear-gradient(135deg, #527f91, #6d9fad)' : 'rgba(228,241,243,0.055)',
            color: activeTab === 'incident' ? '#fff' : 'var(--text-muted)',
            borderColor: activeTab === 'incident' ? '#79b9c7' : 'var(--glass-border)'
          }}
          onClick={() => setActiveTab('incident')}
        >
          <ShieldAlert size={18} /> 🛡️ Incident Response & Firewall
        </button>

        <button
          className="btn"
          style={{
            padding: '12px 24px', borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            background: activeTab === 'audit' ? 'linear-gradient(135deg, #527f91, #6d9fad)' : 'rgba(228,241,243,0.055)',
            color: activeTab === 'audit' ? '#fff' : 'var(--text-muted)',
            borderColor: activeTab === 'audit' ? '#79b9c7' : 'var(--glass-border)'
          }}
          onClick={() => setActiveTab('audit')}
        >
          <Database size={18} /> Hash-Chained Audit Log
        </button>
      </nav>

      {/* Render Active Tab */}
      <div className="fade-in">
        {activeTab === 'radar' && (
          <LiveRadar
            stats={stats}
            alerts={alerts}
            blockedIPs={blockedIPs}
            onRefresh={() => { fetchStats(); fetchAlerts(); }}
            onClearAlerts={handleClearAlerts}
            onBlockIP={handleBlockIP}
            onUnblockIP={handleUnblockIP}
            endpoints={endpoints}
            endpointSummary={endpointSummary}
            mlMetrics={mlMetrics}
          />
        )}

        {activeTab === 'incident' && (
          <IncidentResponse
            scores={threatScores}
            incidents={incidents}
            playbooks={playbooks}
            blockedIPsList={blockedIPsList}
            onBlockIP={handleBlockIP}
            onUnblockIP={handleUnblockIP}
            onRefresh={() => { fetchIRData(); fetchBlockedIPs(); fetchAlerts(); fetchTimeline(); }}
          />
        )}

        {activeTab === 'audit' && (
          <AuditLog
            summary={auditSummary}
            verifyStatus={verifyStatus}
            blockedIPs={blockedIPs}
            onVerify={verifyAudit}
            onRefresh={fetchAuditData}
          />
        )}

        {activeTab === 'timeline' && <AttackTimeline events={timeline} onRefresh={fetchTimeline} />}

        {activeTab === 'endpoints' && <Endpoints endpoints={endpoints} summary={endpointSummary} onRefresh={fetchEndpoints} />}
      </div>
    </div>
  );
}
