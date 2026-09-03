import React, { useState } from 'react';
import { Play, Square, Volume2, VolumeX, LogOut, ShieldCheck, Activity, RotateCcw } from 'lucide-react';
import { soundEngine } from '../utils/soundEngine';

export function Header({ isEngineRunning, onStartEngine, onStopEngine, onResetAllData, lastSync }) {
  const [isMuted, setIsMuted] = useState(soundEngine.isMuted());

  const handleToggleSound = () => {
    const muted = soundEngine.toggleMute();
    setIsMuted(muted);
  };

  return (
    <header className="header glass-panel" style={{ padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: '44px', height: '44px', borderRadius: '12px',
          background: 'linear-gradient(135deg, #5e8794, #8299bf)',
          display: 'flex', alignItems: 'center', justifyCenter: 'center',
          fontWeight: 800, fontSize: '18px', color: '#fff',
          boxShadow: '0 4px 14px rgba(121, 185, 199, 0.26)'
        }}>
          <ShieldCheck size={26} style={{ margin: 'auto' }} />
        </div>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.5px' }}>
            IDS Security Command Center
          </h1>
          <div style={{ fontSize: '12px', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Activity size={12} color="#10b981" />
            React SOC Frontend | Live Sync: {lastSync || 'Connecting...'}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        {!isEngineRunning ? (
          <button className="btn btn-primary" onClick={onStartEngine}>
            <Play size={16} /> Engage IDS Engine
          </button>
        ) : (
          <button className="btn btn-danger" onClick={onStopEngine}>
            <Square size={16} /> Stop Engine
          </button>
        )}

        <button className="btn" onClick={onResetAllData} title="Reset all attack data, threat scores, incident logs & blockchain ledger" style={{ borderColor: 'rgba(245, 158, 11, 0.4)', color: '#f59e0b', background: 'rgba(245, 158, 11, 0.1)' }}>
          <RotateCcw size={15} /> Reset Demo Data
        </button>

        <button className="btn" onClick={handleToggleSound} title="Toggle Audio Alarms">
          {isMuted ? <VolumeX size={16} color="#f43f5e" /> : <Volume2 size={16} color="#10b981" />}
          <span>{isMuted ? 'Muted' : 'Sound ON'}</span>
        </button>

        <form method="POST" action="/logout" style={{ margin: 0 }}>
          <button type="submit" className="btn" style={{ borderColor: 'rgba(244, 63, 94, 0.3)', color: '#f43f5e' }}>
            <LogOut size={14} /> Logout
          </button>
        </form>
      </div>
    </header>
  );
}
