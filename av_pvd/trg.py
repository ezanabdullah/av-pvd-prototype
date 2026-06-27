"""
Temporal Risk Gradient (TRG) computation.

TRG(t) = Σ_{i=1}^{k} [ Risk(Bi) × e^{-λ(t - ti)} ]

Where:
  - Risk(Bi) is the risk score of block Bi
  - t is the current block timestamp
  - ti is the timestamp of block Bi
  - λ is the decay constant (controls memory horizon)
  - k is the lookback window

The exponential decay ensures recent risk events dominate while
older anomalies gradually fade, preventing alert fatigue from
distant past events while still maintaining temporal context.

λ interpretation:
  - λ = 0.001 → half-life ≈ 693 seconds ≈ ~57 Ethereum blocks
  - λ = 0.005 → half-life ≈ 139 seconds ≈ ~11 blocks  (more reactive)
  - λ = 0.0002 → half-life ≈ 3466 seconds ≈ ~289 blocks (long memory)
"""

import math
from collections import deque
from .models import Block


_DEFAULT_LAMBDA = 0.001   # decay constant
_DEFAULT_WINDOW = 100     # max blocks to retain in memory


class TRGComputer:
    """Maintains a sliding temporal window and computes TRG at each block."""

    def __init__(
        self,
        decay_lambda: float = _DEFAULT_LAMBDA,
        window_blocks: int = _DEFAULT_WINDOW,
    ):
        self.decay_lambda = decay_lambda
        self.window_blocks = window_blocks
        # Store (timestamp, risk_score) pairs
        self._history: deque[tuple[int, float]] = deque(maxlen=window_blocks)

    def update_and_compute(self, block: Block, risk_score: float) -> float:
        """
        Record risk for this block, then compute TRG at block.timestamp.
        Returns the current TRG value.
        """
        self._history.append((block.timestamp, risk_score))
        return self._compute_trg(block.timestamp)

    def _compute_trg(self, current_time: int) -> float:
        """Compute the exponentially-decayed risk sum up to current_time."""
        total = 0.0
        for ts, risk in self._history:
            delta_t = current_time - ts
            weight = math.exp(-self.decay_lambda * delta_t)
            total += risk * weight
        return total

    @property
    def history(self) -> list[tuple[int, float]]:
        return list(self._history)
