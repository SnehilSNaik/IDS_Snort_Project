// Web Audio API Sound Engine for IDS React Frontend
let _ctx = null;
let _muted = false;

function getCtx() {
  if (!_ctx) _ctx = new (window.AudioContext || window.webkitAudioContext)();
  if (_ctx.state === 'suspended') _ctx.resume();
  return _ctx;
}

function distort(ctx, amount = 100) {
  const ws = ctx.createWaveShaper();
  const n = 256, curve = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const x = (i * 2) / n - 1;
    curve[i] = ((Math.PI + amount) * x) / (Math.PI + amount * Math.abs(x));
  }
  ws.curve = curve;
  ws.oversample = '4x';
  return ws;
}

function noise(delaySec, duration, vol, loFreq = 800, hiFreq = 3000) {
  if (_muted) return;
  try {
    const ctx = getCtx();
    const rate = ctx.sampleRate;
    const buf  = ctx.createBuffer(1, Math.ceil(rate * duration), rate);
    const d    = buf.getChannelData(0);
    for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1;
    const src  = ctx.createBufferSource(); src.buffer = buf;
    const filt = ctx.createBiquadFilter();
    filt.type = 'bandpass';
    filt.frequency.value = (loFreq + hiFreq) / 2;
    filt.Q.value = 0.6;
    const gain = ctx.createGain();
    const t = ctx.currentTime + delaySec;
    gain.gain.setValueAtTime(0, t);
    gain.gain.linearRampToValueAtTime(vol, t + 0.008);
    gain.gain.exponentialRampToValueAtTime(0.001, t + duration);
    src.connect(filt); filt.connect(gain); gain.connect(ctx.destination);
    src.start(t); src.stop(t + duration + 0.05);
  } catch(e) {}
}

function thud(delaySec, startHz, vol, duration) {
  if (_muted) return;
  try {
    const ctx = getCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    const t = ctx.currentTime + delaySec;
    osc.type = 'sine';
    osc.frequency.setValueAtTime(startHz, t);
    osc.frequency.exponentialRampToValueAtTime(startHz * 0.15, t + duration);
    gain.gain.setValueAtTime(vol, t);
    gain.gain.exponentialRampToValueAtTime(0.001, t + duration);
    osc.connect(gain); gain.connect(ctx.destination);
    osc.start(t); osc.stop(t + duration + 0.05);
  } catch(e) {}
}

function siren(delaySec, centerHz, swingHz, lfoRate, vol, duration, waveType = 'sawtooth', useDistort = true) {
  if (_muted) return;
  try {
    const ctx  = getCtx();
    const osc  = ctx.createOscillator();
    const lfo  = ctx.createOscillator();
    const lfoG = ctx.createGain();
    const gain = ctx.createGain();
    const t = ctx.currentTime + delaySec;
    osc.type = waveType;
    osc.frequency.setValueAtTime(centerHz, t);
    lfo.type = 'sine';
    lfo.frequency.setValueAtTime(lfoRate, t);
    lfoG.gain.setValueAtTime(swingHz, t);
    lfo.connect(lfoG); lfoG.connect(osc.frequency);
    if (useDistort) {
      const dist = distort(ctx, 80);
      osc.connect(dist); dist.connect(gain);
    } else {
      osc.connect(gain);
    }
    gain.connect(ctx.destination);
    gain.gain.setValueAtTime(0, t);
    gain.gain.linearRampToValueAtTime(vol, t + 0.04);
    gain.gain.setValueAtTime(vol, t + duration - 0.12);
    gain.gain.exponentialRampToValueAtTime(0.001, t + duration);
    lfo.start(t); osc.start(t);
    lfo.stop(t + duration + 0.1); osc.stop(t + duration + 0.1);
  } catch(e) {}
}

function klaxon(delaySec, freq, vol, duration) {
  if (_muted) return;
  try {
    const ctx  = getCtx();
    const osc  = ctx.createOscillator();
    const dist = distort(ctx, 150);
    const gain = ctx.createGain();
    const t = ctx.currentTime + delaySec;
    osc.type = 'square';
    osc.frequency.setValueAtTime(freq, t);
    osc.connect(dist); dist.connect(gain); gain.connect(ctx.destination);
    gain.gain.setValueAtTime(0, t);
    gain.gain.linearRampToValueAtTime(vol, t + 0.010);
    gain.gain.setValueAtTime(vol, t + duration * 0.7);
    gain.gain.exponentialRampToValueAtTime(0.001, t + duration);
    osc.start(t); osc.stop(t + duration + 0.05);
  } catch(e) {}
}

export const soundEngine = {
  playHigh() {
    if (_muted) return;
    siren(0.00, 600, 300, 2.5, 0.28, 1.4);
    klaxon(0.00, 950, 0.24, 0.14);
    klaxon(0.18, 750, 0.22, 0.14);
    klaxon(0.36, 950, 0.24, 0.14);
    thud(0.00, 90, 0.65, 0.30);
    thud(0.18, 80, 0.50, 0.25);
    thud(0.36, 90, 0.60, 0.28);
    noise(0.00, 0.10, 0.09, 600, 2400);
  },
  playCorrelated() {
    if (_muted) return;
    [0, 1, 2, 3].forEach(i => {
      const d = i * 0.23;
      klaxon(d, i % 2 === 0 ? 1050 : 680, 0.30, 0.19);
      thud(d, 60, 0.75, 0.22);
      noise(d, 0.08, 0.11, 500, 3000);
    });
    siren(0.92, 700, 350, 3.0, 0.26, 1.0);
    thud(0.00, 45, 0.45, 1.80);
  },
  playMedium() {
    if (_muted) return;
    siren(0.00, 1100, 200, 8, 0.22, 0.22, 'sine', false);
    siren(0.25, 650, 80, 6, 0.16, 0.20, 'sine', false);
    noise(0.00, 0.06, 0.05, 800, 2500);
  },
  playBlock() {
    if (_muted) return;
    thud(0.00, 130, 0.72, 0.28);
    thud(0.04, 65, 0.55, 0.32);
    noise(0.00, 0.07, 0.13, 200, 900);
    klaxon(0.10, 260, 0.12, 0.14);
  },
  playTamper() {
    if (_muted) return;
    siren(0.00, 750, 350, 1.8, 0.28, 0.75, 'sawtooth', true);
    thud(0.00, 110, 0.60, 0.55);
    noise(0.00, 0.18, 0.16, 400, 4000);
  },
  toggleMute() {
    _muted = !_muted;
    if (!_muted) siren(0, 900, 100, 6, 0.10, 0.20, 'sine', false);
    return _muted;
  },
  isMuted: () => _muted
};
