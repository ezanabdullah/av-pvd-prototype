"""
VScore computation and alert generation.

VScore(t) = Risk_norm(t) × (1 - ATS_mean(t)) × PropagationFactor(t)

Where:
  - Risk_norm(t) is the per-block risk z-score, sigmoid-mapped to [0,1],
    measured against the rolling baseline of recent Risk(Bi) values.
    This fires only when the current block is anomalous *relative to its
    own history*, avoiding TRG accumulation drift.
  - TRG(t) augments Risk_norm as a secondary weight:
    if TRG is also elevated, the multiplier rises, confirming the anomaly
    is part of a sustained pattern, not a one-off spike.
  - ATS_mean(t) is the weighted mean trust score of entities active
    in the recent window (high trust suppresses the score)
  - PropagationFactor(t) = log(1 + VPG_edge_density) normalised to [1, 2]

An alert fires when VScore(t) > threshold.
"""

import math
import statistics
from collections import deque
from .models import Block, Alert
from .trg import TRGComputer
from .vpg import VulnerabilityPropagationGraph
from .ats import AdaptiveTrustScorer
from .risk import RiskComputer


_DEFAULT_THRESHOLD = 0.6
_BASELINE_WINDOW = 50   # blocks of Risk/TRG history to normalise against


class VScoreEngine:
    """Computes VScore and emits Alert objects when threshold is crossed."""

    def __init__(
        self,
        threshold: float = _DEFAULT_THRESHOLD,
        risk_computer: RiskComputer | None = None,
        trg_computer: TRGComputer | None = None,
        vpg: VulnerabilityPropagationGraph | None = None,
        trust_scorer: AdaptiveTrustScorer | None = None,
    ):
        self.threshold = threshold
        self.risk_computer = risk_computer or RiskComputer()
        self.trg_computer = trg_computer or TRGComputer()
        self.vpg = vpg or VulnerabilityPropagationGraph()
        self.trust_scorer = trust_scorer or AdaptiveTrustScorer()

        self._vscore_history: list[tuple[int, float]] = []  # (block_num, vscore)
        self._risk_baseline: deque[float] = deque(maxlen=_BASELINE_WINDOW)
        self._trg_baseline: deque[float] = deque(maxlen=_BASELINE_WINDOW)
        self._last_risk: float = 0.0
        self._warmup_blocks: int = 20  # suppress alerts during baseline warm-up
        self._block_count: int = 0

    def process_block(self, block: Block) -> tuple[float, Alert | None]:
        """
        Full pipeline for one block:
          1. Compute Risk(Bi)
          2. Update TRG
          3. Update VPG
          4. Update ATS
          5. Compute VScore
          6. Maybe emit Alert
        Returns (vscore, alert_or_None).
        """
        # Step 1: Risk
        risk = self.risk_computer.compute(block)

        # Step 2: TRG
        trg = self.trg_computer.update_and_compute(block, risk)

        # Step 3: VPG
        self.vpg.update(block, risk)

        # Step 4: ATS
        self.trust_scorer.update(block, risk)

        # Step 5: VScore — compute before updating baselines so this block
        # is scored relative to prior history, then update baselines after.
        vscore = self._compute_vscore(block, risk, trg)
        self._risk_baseline.append(risk)
        self._trg_baseline.append(trg)
        self._last_risk = risk
        self._block_count += 1
        self._vscore_history.append((block.number, vscore))

        # Step 6: Alert (suppressed during warm-up)
        alert = None
        in_warmup = self._block_count <= self._warmup_blocks
        if vscore > self.threshold and not in_warmup:
            reasons = self._build_reasons(block, risk, trg, vscore)  # noqa: E501
            top_entities = self.trust_scorer.lowest_trust_addresses(n=5)
            alert = Alert(
                block_number=block.number,
                vscore=vscore,
                threshold=self.threshold,
                triggered_by=reasons,
                top_suspicious_entities=top_entities,
            )

        return vscore, alert

    def _compute_vscore(self, block: Block, risk: float, trg: float) -> float:
        """
        VScore = Risk_norm × TRG_boost × (1 - ATS_mean) × PropagationFactor.

        Risk_norm: z-score of current risk vs. rolling baseline, sigmoid-mapped.
          - At baseline (z=0) → 0.5; z=+2 → 0.88; z=+3 → 0.95
        TRG_boost: if TRG also elevated above its baseline, multiplier rises to 1.5.
          Confirms sustained attack pattern vs. isolated anomaly.
        """
        # --- Risk z-score ---
        if len(self._risk_baseline) >= 10:
            r_mu = statistics.mean(self._risk_baseline)
            r_sigma = statistics.stdev(self._risk_baseline) or 0.05
            risk_z = (risk - r_mu) / r_sigma
        else:
            # Cold-start: use raw risk directly
            risk_z = (risk - 0.3) / 0.1

        # Sigmoid: z=0 → 0.5, z=2 → 0.88, z=3 → 0.95
        risk_norm = 1.0 / (1.0 + math.exp(-risk_z))

        # --- TRG persistence bonus (secondary confirmation) ---
        # TRG is normalised to [0, 1] so it adds only a small bonus
        # when risk is *persistently* elevated (sustained attack pattern).
        # We cap TRG contribution to 0.2 so a single high-risk block
        # cannot drive VScore past threshold on its own via TRG alone.
        if len(self._trg_baseline) >= 10:
            t_mu = statistics.mean(self._trg_baseline)
            t_sigma = statistics.stdev(self._trg_baseline) or 0.1
            trg_z = (trg - t_mu) / t_sigma
            # Only boost if TRG is also elevated (trg_z > 1σ above baseline)
            trg_boost = 1.0 + 0.2 * math.tanh(max(trg_z - 1.0, 0.0))
        else:
            trg_boost = 1.0

        # --- Trust factor ---
        addrs = set()
        for tx in block.transactions:
            addrs.add(tx.from_addr)
            if tx.to_addr:
                addrs.add(tx.to_addr)

        if addrs:
            mean_trust = sum(
                self.trust_scorer.get_trust(a) for a in addrs
            ) / len(addrs)
        else:
            mean_trust = 0.5

        trust_factor = 1.0 - mean_trust

        # --- Propagation factor ---
        edge_density = self.vpg.edge_count() / max(self.vpg.node_count(), 1)
        prop_factor = 1.0 + (math.log(1.0 + edge_density) / math.log(10.0))
        prop_factor = min(prop_factor, 2.0)

        vscore = risk_norm * trg_boost * trust_factor * prop_factor
        return min(vscore, 1.0)

    def _build_reasons(
        self, block: Block, risk: float, trg: float, vscore: float
    ) -> list[str]:
        reasons = []
        comps = self.risk_computer.component_scores(block)

        if comps["gas_anomaly"] > 0.7:
            reasons.append(f"High gas anomaly ({comps['gas_anomaly']:.2f})")
        if comps["call_depth_deviation"] > 0.5:
            reasons.append(
                f"Abnormal call depth ({comps['call_depth_deviation']:.2f})"
            )
        if comps["value_transfer_entropy"] > 0.6:
            reasons.append(
                f"Value entropy anomaly ({comps['value_transfer_entropy']:.2f})"
            )
        if not reasons:
            reasons.append(f"Composite risk elevation (risk={risk:.2f}, trg={trg:.3f})")
        return reasons

    @property
    def vscore_history(self) -> list[tuple[int, float]]:
        return list(self._vscore_history)
