"""
=============================================================
blockchain/blockchain.py  —  IDS_Snort_Project
=============================================================
Tamper-Proof Attacker Ledger using a lightweight Blockchain.

Design:
  - Every alert/attack detected by the IDS is committed as a
    new Block into a persistent chain stored in chain.json.
  - Each Block contains the full attacker record + a SHA-256
    hash that cryptographically links it to the previous block.
  - If ANY past block is modified or deleted, chain validation
    fails immediately — tampering is detected at verification time.
  - Proof-of-Work (difficulty=2) makes retroactive forgery
    computationally expensive while staying sub-millisecond for
    new blocks so the IDS is never slowed down.

Usage:
    from blockchain.blockchain import AttackerBlockchain
    bc = AttackerBlockchain()
    bc.add_block(alert_dict)          # commit an alert
    bc.is_chain_valid()               # True / False
    bc.get_all_records()              # list of all blocks
    bc.get_attacker_summary()         # stats by IP
=============================================================
"""

import hashlib
import json
import os
import time
import threading
from datetime import datetime

# ----------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAIN_FILE    = os.path.join(BASE_DIR, "blockchain", "chain.json")
POW_DIFFICULTY = 2          # number of leading zeros required in hash
                             # (2 zeros = fast mining, still tamper-resistant)


# ----------------------------------------------------------------
# Block
# ----------------------------------------------------------------
class Block:
    """A single block in the attacker ledger chain."""

    def __init__(
        self,
        index: int,
        timestamp: str,
        attacker_data: dict,
        previous_hash: str,
        nonce: int = 0,
        block_hash: str = "",
    ):
        self.index         = index
        self.timestamp     = timestamp
        self.attacker_data = attacker_data
        self.previous_hash = previous_hash
        self.nonce         = nonce
        self.hash          = block_hash or self._compute_hash()

    # ------------------------------------------------------------------
    def _compute_hash(self) -> str:
        """Deterministic SHA-256 over all fields (sorted keys for stability)."""
        block_str = json.dumps(
            {
                "index":         self.index,
                "timestamp":     self.timestamp,
                "attacker_data": self.attacker_data,
                "previous_hash": self.previous_hash,
                "nonce":         self.nonce,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_str.encode()).hexdigest()

    # ------------------------------------------------------------------
    def mine(self) -> None:
        """Proof-of-Work: increment nonce until hash starts with required zeros."""
        prefix = "0" * POW_DIFFICULTY
        while not self._compute_hash().startswith(prefix):
            self.nonce += 1
        self.hash = self._compute_hash()

    # ------------------------------------------------------------------
    def is_valid_pow(self) -> bool:
        """Check this block's hash satisfies the proof-of-work requirement."""
        prefix = "0" * POW_DIFFICULTY
        return self.hash.startswith(prefix) and self.hash == self._compute_hash()

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "attacker_data": self.attacker_data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "hash":          self.hash,
        }

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            index         = d["index"],
            timestamp     = d["timestamp"],
            attacker_data = d["attacker_data"],
            previous_hash = d["previous_hash"],
            nonce         = d["nonce"],
            block_hash    = d["hash"],
        )

    def __repr__(self):
        return (
            f"Block(#{self.index} | {self.attacker_data.get('src_ip','?')} | "
            f"{self.attacker_data.get('severity','?')} | hash={self.hash[:12]}...)"
        )


# ----------------------------------------------------------------
# AttackerBlockchain
# ----------------------------------------------------------------
class AttackerBlockchain:
    """
    Persistent, tamper-proof ledger for attacker records.

    Thread-safe: all public methods acquire a lock.
    Storage: CHAIN_FILE is opened in append mode — records are
             never overwritten or deleted, only added.
    """

    def __init__(self):
        self._lock  = threading.Lock()
        self._chain: list[Block] = []
        self._load_chain()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load_chain(self) -> None:
        """Load existing chain from JSON Lines file on disk."""
        if not os.path.exists(CHAIN_FILE):
            self._chain = [self._make_genesis()]
            self._append_to_file(self._chain[0])
            print("[BLOCKCHAIN] Genesis block created.")
            return

        self._chain = []
        with open(CHAIN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._chain.append(Block.from_dict(json.loads(line)))
                except Exception as e:
                    print(f"[BLOCKCHAIN] Warning: skipped corrupt line — {e}")

        if not self._chain:
            # File existed but was empty / all corrupt — rebuild genesis
            self._chain = [self._make_genesis()]
            self._append_to_file(self._chain[0])
            print("[BLOCKCHAIN] Rebuilt empty chain with Genesis block.")
        else:
            print(f"[BLOCKCHAIN] Loaded {len(self._chain)} block(s) from disk.")

    def _append_to_file(self, block: Block) -> None:
        """Append a single block as one JSON line — NEVER rewrites the file."""
        os.makedirs(os.path.dirname(CHAIN_FILE), exist_ok=True)
        with open(CHAIN_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(block.to_dict(), separators=(",", ":")) + "\n")

    # ------------------------------------------------------------------
    # Genesis
    # ------------------------------------------------------------------
    @staticmethod
    def _make_genesis() -> Block:
        genesis = Block(
            index         = 0,
            timestamp     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            attacker_data = {
                "message": "Genesis Block — IDS Attacker Ledger Initialized",
                "src_ip":  "0.0.0.0",
                "type":    "GENESIS",
                "severity": "INFO",
            },
            previous_hash = "0" * 64,
        )
        genesis.mine()
        return genesis

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def add_block(self, alert_data: dict) -> Block:
        """
        Commit an alert to the chain.
        Mines a new block with proof-of-work and persists it.
        Returns the newly created Block.
        """
        with self._lock:
            prev    = self._chain[-1]
            new_blk = Block(
                index         = prev.index + 1,
                timestamp     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                attacker_data = alert_data,
                previous_hash = prev.hash,
            )
            new_blk.mine()
            self._chain.append(new_blk)
            self._append_to_file(new_blk)
            print(
                f"[BLOCKCHAIN] Block #{new_blk.index} mined — "
                f"IP={alert_data.get('src_ip','?')}  "
                f"hash={new_blk.hash[:16]}..."
            )
            return new_blk

    def is_chain_valid(self) -> tuple[bool, int]:
        """
        Verify the entire chain.
        Returns (True, -1) if valid.
        Returns (False, broken_index) if tampered.
        """
        with self._lock:
            for i in range(1, len(self._chain)):
                curr = self._chain[i]
                prev = self._chain[i - 1]

                # 1. Recompute and compare hash
                if curr.hash != curr._compute_hash():
                    return False, i

                # 2. Verify linkage
                if curr.previous_hash != prev.hash:
                    return False, i

                # 3. Verify proof-of-work
                if not curr.is_valid_pow():
                    return False, i

            return True, -1

    def get_all_records(self) -> list[dict]:
        """Return all blocks (including genesis) as a list of dicts."""
        with self._lock:
            return [b.to_dict() for b in self._chain]

    def get_attacker_records(self, ip: str) -> list[dict]:
        """Return all blocks matching a specific source IP."""
        with self._lock:
            return [
                b.to_dict()
                for b in self._chain
                if b.attacker_data.get("src_ip") == ip
            ]

    def get_attacker_summary(self) -> dict:
        """
        Aggregate stats across the chain.
        Returns:
          total_blocks, unique_attackers, top_attackers list,
          severity_counts, type_counts, last_block_time
        """
        with self._lock:
            # Skip genesis block for stats
            records = [b for b in self._chain if b.index > 0]

            ip_hits: dict[str, dict] = {}
            severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            type_counts: dict[str, int] = {}

            for blk in records:
                data = blk.attacker_data
                ip   = data.get("src_ip", "unknown")
                sev  = data.get("severity", "LOW")
                typ  = data.get("type", "UNKNOWN")

                # Per-IP aggregation
                if ip not in ip_hits:
                    ip_hits[ip] = {
                        "ip":         ip,
                        "count":      0,
                        "HIGH":       0,
                        "MEDIUM":     0,
                        "LOW":        0,
                        "last_seen":  blk.timestamp,
                        "protocols":  set(),
                    }
                ip_hits[ip]["count"]    += 1
                ip_hits[ip][sev]        = ip_hits[ip].get(sev, 0) + 1
                ip_hits[ip]["last_seen"] = blk.timestamp
                proto = data.get("protocol", "")
                if proto:
                    ip_hits[ip]["protocols"].add(proto)

                # Global counters
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                type_counts[typ]     = type_counts.get(typ, 0) + 1

            # Serialize sets for JSON
            top_attackers = sorted(
                [
                    {**v, "protocols": list(v["protocols"])}
                    for v in ip_hits.values()
                ],
                key=lambda x: x["count"],
                reverse=True,
            )

            last_time = (
                self._chain[-1].timestamp if len(self._chain) > 1 else "N/A"
            )

            return {
                "total_blocks":     len(self._chain),
                "attacker_blocks":  len(records),
                "unique_attackers": len(ip_hits),
                "top_attackers":    top_attackers[:20],   # cap at 20 for API
                "severity_counts":  severity_counts,
                "type_counts":      type_counts,
                "last_block_time":  last_time,
                "chain_file":       CHAIN_FILE,
            }

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._chain)
