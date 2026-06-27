"""
Vulnerability Propagation Graph (VPG).

Directed graph where:
  - Nodes: Ethereum addresses (EOAs and contracts)
  - Edges: transaction interactions, weighted by risk contribution
  - Edge weight W(a→b) = risk_score × value_fraction

After each block, edge weights decay by factor (1 - γ) to reflect
that stale interactions carry less propagation potential.

The VPG enables:
1. Identifying which entities are most "connected" to risky activity
2. Computing propagation centrality to find systemic risk hubs
3. Visualising attack paths for post-incident analysis
"""

import math
from collections import defaultdict
from .models import Block, Transaction


_DEFAULT_DECAY = 0.02    # γ: per-block weight decay rate
_EDGE_PRUNE_THRESHOLD = 1e-5  # remove edges below this weight


class VulnerabilityPropagationGraph:
    """Incremental VPG that updates per block."""

    def __init__(self, decay_gamma: float = _DEFAULT_DECAY):
        self.decay_gamma = decay_gamma
        # adjacency: {from_addr: {to_addr: weight}}
        self._edges: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        # node risk accumulation
        self._node_risk: dict[str, float] = defaultdict(float)
        self._block_count = 0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def update(self, block: Block, block_risk: float) -> None:
        """Decay existing edges, then add new edges from block transactions."""
        self._decay_edges()
        self._add_block_edges(block, block_risk)
        self._block_count += 1

    def propagation_centrality(self, address: str) -> float:
        """
        Sum of outgoing edge weights — how much risk an address propagates.
        High centrality → this address is a hub of risky flows.
        """
        return sum(self._edges[address].values())

    def inbound_risk(self, address: str) -> float:
        """Sum of incoming edge weights — how much risk flows into address."""
        total = 0.0
        for targets in self._edges.values():
            total += targets.get(address, 0.0)
        return total

    def top_nodes_by_outbound(self, n: int = 10) -> list[tuple[str, float]]:
        """Return top-n addresses by propagation centrality."""
        scores = [
            (addr, self.propagation_centrality(addr))
            for addr in self._edges
            if self.propagation_centrality(addr) > 0
        ]
        return sorted(scores, key=lambda x: x[1], reverse=True)[:n]

    def edge_count(self) -> int:
        return sum(len(targets) for targets in self._edges.values())

    def node_count(self) -> int:
        nodes = set(self._edges.keys())
        for targets in self._edges.values():
            nodes.update(targets.keys())
        return len(nodes)

    def get_edges(self) -> list[tuple[str, str, float]]:
        """Return all (from, to, weight) triples."""
        result = []
        for src, targets in self._edges.items():
            for dst, w in targets.items():
                result.append((src, dst, w))
        return result

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _decay_edges(self) -> None:
        """Multiply all edge weights by (1 - γ) and prune near-zero edges."""
        decay_factor = 1.0 - self.decay_gamma
        to_delete = []
        for src in self._edges:
            for dst in list(self._edges[src]):
                self._edges[src][dst] *= decay_factor
                if self._edges[src][dst] < _EDGE_PRUNE_THRESHOLD:
                    to_delete.append((src, dst))
        for src, dst in to_delete:
            del self._edges[src][dst]

    def _add_block_edges(self, block: Block, block_risk: float) -> None:
        """Add weighted edges for each transaction in block."""
        total_value = sum(tx.value_wei for tx in block.transactions) or 1

        for tx in block.transactions:
            if tx.to_addr is None:
                continue  # contract deployment, no target
            # Weight = block risk × this tx's share of total block value
            # (minimum floor so zero-value contract calls still get a weight)
            value_fraction = tx.value_wei / total_value if tx.value_wei > 0 else 0.01
            edge_weight = block_risk * value_fraction

            self._edges[tx.from_addr][tx.to_addr] += edge_weight
            self._node_risk[tx.from_addr] += edge_weight * 0.5
            self._node_risk[tx.to_addr] += edge_weight * 0.5
