"""Bidirectional 5-tuple flow collector for live CIC-IDS-compatible inference."""

from dataclasses import dataclass, field
import time
import numpy as np


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    started_at: float
    last_seen: float
    forward_packets: list = field(default_factory=list)
    forward_flags: list = field(default_factory=list)
    init_window: int = 0

    def add_forward(self, now, size, syn, psh, ack, window):
        self.forward_packets.append((now, size))
        self.forward_flags.append((syn, psh, ack))
        if not self.init_window:
            self.init_window = window
        self.last_seen = now

    def add_reverse(self, now):
        self.last_seen = now

    def features(self):
        times = [p[0] for p in self.forward_packets]
        sizes = [p[1] for p in self.forward_packets]
        duration_us = max(0.0, (self.last_seen - self.started_at) * 1_000_000)
        duration_s = max(duration_us / 1_000_000, 0.001)
        iats = [(times[i] - times[i - 1]) * 1_000_000 for i in range(1, len(times))]
        syns, pshs, acks = zip(*self.forward_flags) if self.forward_flags else ([], [], [])
        return np.array([[
            float(self.dst_port), duration_us, float(len(sizes)), float(sum(sizes)),
            float(max(sizes)), float(np.mean(sizes)), float(np.std(sizes)) if len(sizes) > 1 else 0.0,
            float(sum(sizes) / duration_s), float(len(sizes) / duration_s),
            float(np.mean(iats)) if iats else 0.0, float(np.mean(sizes)),
            float(sum(syns)), float(sum(pshs)), float(sum(acks)), float(self.init_window),
        ]]), duration_s


class FlowCollector:
    """Collects TCP/UDP packets by bidirectional 5-tuple and finalizes safe snapshots."""
    def __init__(self, idle_seconds=5.0, max_packets=20, min_packets=2):
        self.idle_seconds = idle_seconds
        self.max_packets = max_packets
        self.min_packets = min_packets
        self.flows = {}

    @staticmethod
    def _key(src_ip, dst_ip, src_port, dst_port, protocol):
        endpoints = sorted(((src_ip, src_port), (dst_ip, dst_port)))
        return protocol, endpoints[0], endpoints[1]

    def add(self, src_ip, dst_ip, src_port, dst_port, protocol, size, syn=0, psh=0, ack=0, window=0, fin_or_rst=False, now=None):
        now = now or time.time()
        key = self._key(src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, now, now)
            self.flows[key] = flow
        if (src_ip, src_port) == (flow.src_ip, flow.src_port):
            flow.add_forward(now, size, syn, psh, ack, window)
        else:
            flow.add_reverse(now)
        if fin_or_rst or len(flow.forward_packets) >= self.max_packets:
            return self._finish(key)
        return None

    def flush_idle(self, now=None):
        now = now or time.time()
        completed = []
        for key, flow in list(self.flows.items()):
            if now - flow.last_seen >= self.idle_seconds:
                item = self._finish(key)
                if item:
                    completed.append(item)
        return completed

    def _finish(self, key):
        flow = self.flows.pop(key, None)
        return flow if flow and len(flow.forward_packets) >= self.min_packets else None
