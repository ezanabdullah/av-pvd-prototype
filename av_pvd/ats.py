"""
Adaptive Trust Scorer (ATS).

ATS(a, t) models the trustworthiness of address `a` at time t.
Formula:

  ATS_new(a) = α × ATS_old(a) + (1 - α) × Behaviour(a, Bi)

Where:
  - α ∈ [0,1] is the EMA smoothing factor (higher = longer memory)
  - Behaviour(a, Bi) = 1.0 for normal tx, 0.0 for anomalous tx

Trust DECREASES when an address is involved in a high-risk block.
Trust INCREASES over time via normal, benign transactions.

Default α = 0.95 gives ~20-block half-life for trust updates.

The VScore formula uses (1 - ATS) as a multiplier, so:
  - Low trust (ATS near 0) → VScore amplified → alerts more sensitive
  - High trust (ATS near 1) → VScore suppressed (trust farming risk!)
"""

from collections import defaultdict
from .models import Block


_DEFAULT_ALPHA = 0.95          # EMA smoothing — high = slow to change
_INITIAL_TRUST = 0.5           # new addresses start at neutral trust
_ANOMALY_THRESHOLD = 0.3       # block risk above this → mark as anomalous
_TRUST_DECAY_GAMMA = 0.0001    # per-block passive decay (very slow — counters farming without eroding legitimate addresses)


class AdaptiveTrustScorer:
    """Maintains per-address trust scores with EMA update rule."""

    def __init__(
        self,
        alpha: float = _DEFAULT_ALPHA,
        initial_trust: float = _INITIAL_TRUST,
        anomaly_threshold: float = _ANOMALY_THRESHOLD,
        trust_decay: float = _TRUST_DECAY_GAMMA,
    ):
        self.alpha = alpha
        self.initial_trust = initial_trust
        self.anomaly_threshold = anomaly_threshold
        self.trust_decay = trust_decay
        self._scores: dict[str, float] = defaultdict(lambda: initial_trust)

    def update(self, block: Block, block_risk: float) -> None:
        """Update trust scores for all addresses seen in this block."""
        is_anomalous = block_risk >= self.anomaly_threshold

        # Collect addresses involved in this block
        involved: set[str] = set()
        for tx in block.transactions:
            involved.add(tx.from_addr)
            if tx.to_addr:
                involved.add(tx.to_addr)

        # Passive decay for ALL known addresses (counters trust farming)
        for addr in list(self._scores.keys()):
            self._scores[addr] -= self.trust_decay
            self._scores[addr] = max(self._scores[addr], 0.0)

        # EMA update for involved addresses
        for addr in involved:
            behaviour = 0.0 if is_anomalous else 1.0
            old = self._scores[addr]
            self._scores[addr] = self.alpha * old + (1 - self.alpha) * behaviour

        # Clip all scores to [0, 1]
        for addr in involved:
            self._scores[addr] = max(0.0, min(1.0, self._scores[addr]))

    def get_trust(self, address: str) -> float:
        """Return current trust score for address (0=untrusted, 1=fully trusted)."""
        return self._scores[address]

    def get_all_scores(self) -> dict[str, float]:
        return dict(self._scores)

    def lowest_trust_addresses(self, n: int = 10) -> list[tuple[str, float]]:
        """Return n addresses with the lowest trust scores."""
        return sorted(self._scores.items(), key=lambda x: x[1])[:n]

    def set_trust(self, address: str, score: float) -> None:
        """Manually override trust score (for testing / known-good addresses)."""
        self._scores[address] = max(0.0, min(1.0, score))
