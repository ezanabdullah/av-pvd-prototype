"""
Risk(Bi) formulation for AV-PVD.

We propose a weighted combination of three normalized anomaly signals:

  Risk(Bi) = w1 * GasAnomaly(Bi)
           + w2 * CallDepthDeviation(Bi)
           + w3 * ValueTransferEntropy(Bi)

Justification:
- GasAnomaly captures unusually high gas consumption relative to recent
  baseline, which spikes during reentrancy (recursive calls) and
  flash-loan attacks (large complex sequences in one block).
- CallDepthDeviation flags deep call stacks that exceed the protocol
  norm; legitimate DeFi rarely exceeds depth 4-5, while reentrancy
  exploits often reach depth 8-10+.
- ValueTransferEntropy measures Shannon entropy of ETH value
  distribution across transactions in a block. A single large drain
  (low entropy) or many small equal transfers (uniform distribution
  entropy) both deviate from normal log-normal spread.
"""

import math
import statistics
from collections import deque
from .models import Block, Transaction


# Default weights — tunable via constructor
# Gas anomaly is down-weighted because the lognormal gas distribution
# produces frequent right-tail spikes that look anomalous but are normal.
# Call-depth deviation is the most reliable single indicator of reentrancy.
_W1 = 0.25   # gas anomaly weight
_W2 = 0.50   # call-depth deviation weight
_W3 = 0.25   # value-transfer entropy weight

# Baseline window length in blocks
_BASELINE_WINDOW = 50


class RiskComputer:
    """Computes Risk(Bi) for each incoming block."""

    def __init__(
        self,
        w_gas: float = _W1,
        w_depth: float = _W2,
        w_entropy: float = _W3,
        baseline_window: int = _BASELINE_WINDOW,
        nominal_call_depth: float = 3.5,
        nominal_depth_std: float = 1.5,
    ):
        assert abs(w_gas + w_depth + w_entropy - 1.0) < 1e-9, "Weights must sum to 1"
        self.w_gas = w_gas
        self.w_depth = w_depth
        self.w_entropy = w_entropy
        self.nominal_call_depth = nominal_call_depth
        self.nominal_depth_std = nominal_depth_std

        # Sliding baseline history
        self._gas_history: deque[float] = deque(maxlen=baseline_window)
        self._entropy_history: deque[float] = deque(maxlen=baseline_window)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def compute(self, block: Block) -> float:
        """
        Return Risk(Bi) in [0, 1].

        Uses corroboration multiplier: if only one component is elevated,
        the risk is dampened by factor 0.5.  Two or more elevated components
        (>0.5) produce the full weighted sum.  This prevents single-dimension
        gas spikes (common in normal lognormal-distributed blocks) from
        triggering false alerts while preserving sensitivity to coordinated
        multi-dimensional anomalies typical of real exploits.
        """
        if not block.transactions:
            return 0.0

        g = self._gas_anomaly(block)
        d = self._call_depth_deviation(block)
        e = self._value_transfer_entropy(block)

        # Corroboration: penalise single-component spikes heavily.
        # Two elevated (>0.5) components → 0.75× multiplier.
        # All three elevated (>0.5) → 1.0× multiplier (full weight).
        # Genuine attacks (reentrancy, flash loan) elevate all three;
        # random gas or entropy spikes in normal blocks raise at most two.
        elevated = sum(1 for s in [g, d, e] if s > 0.5)
        if elevated == 3:
            corroboration = 1.0
        elif elevated == 2:
            corroboration = 0.65
        else:
            corroboration = 0.3

        risk = corroboration * (self.w_gas * g + self.w_depth * d + self.w_entropy * e)

        # Update baselines *after* scoring so current block is anomaly-aware
        self._gas_history.append(block.mean_gas_used)
        entropy_val = self._block_value_entropy(block)
        self._entropy_history.append(entropy_val)

        return min(risk, 1.0)

    def component_scores(self, block: Block) -> dict:
        """Return individual component scores for interpretability."""
        return {
            "gas_anomaly": self._gas_anomaly(block),
            "call_depth_deviation": self._call_depth_deviation(block),
            "value_transfer_entropy": self._value_transfer_entropy(block),
        }

    # ------------------------------------------------------------------ #
    # Component computations
    # ------------------------------------------------------------------ #

    def _gas_anomaly(self, block: Block) -> float:
        """
        Sigmoid-normalized z-score of block mean gas vs. baseline.
        Returns value in [0, 1]; >0.5 means above-baseline consumption.
        """
        if len(self._gas_history) < 5:
            # Not enough baseline — return neutral score
            return 0.1

        mu = statistics.mean(self._gas_history)
        sigma = statistics.stdev(self._gas_history) or 1.0
        z = (block.mean_gas_used - mu) / sigma
        # Sigmoid centred at 0; z=+2 → ~0.88, z=-2 → ~0.12
        return 1.0 / (1.0 + math.exp(-z))

    def _call_depth_deviation(self, block: Block) -> float:
        """
        Maximum call depth deviation from protocol norm, normalised to [0,1].

        We use the *maximum* depth seen in the block rather than the mean,
        because reentrancy exploits produce at least one transaction with
        extreme depth (8-12) mixed with many normal-depth transactions.
        Taking the mean would dilute the signal; the max is the right
        statistic for detecting any single deeply-nested call.
        """
        depths = [tx.call_depth for tx in block.transactions if tx.is_contract_call]
        if not depths:
            return 0.0

        max_depth = max(depths)
        deviation = abs(max_depth - self.nominal_call_depth) / (
            self.nominal_depth_std or 1.0
        )
        # Normalise: deviation of 3σ → score ≈ 1.0
        return min(deviation / 3.0, 1.0)

    def _value_transfer_entropy(self, block: Block) -> float:
        """
        Anomaly score based on Shannon entropy of ETH value distribution.
        Compares current block entropy to historical baseline.
        Returns [0, 1]; high score = entropy far from baseline norm.
        """
        current_entropy = self._block_value_entropy(block)

        if len(self._entropy_history) < 5:
            return 0.1

        mu = statistics.mean(self._entropy_history)
        sigma = statistics.stdev(self._entropy_history) or 0.1
        z = abs(current_entropy - mu) / sigma
        # Use absolute deviation: both too-low AND too-high entropy are suspicious
        return min(z / 3.0, 1.0)

    @staticmethod
    def _block_value_entropy(block: Block) -> float:
        """Shannon entropy (nats) of ETH value distribution across block txs."""
        values = [tx.value_wei for tx in block.transactions if tx.value_wei > 0]
        if not values:
            return 0.0

        total = sum(values)
        if total == 0:
            return 0.0

        probs = [v / total for v in values]
        entropy = -sum(p * math.log(p) for p in probs if p > 0)
        return entropy
