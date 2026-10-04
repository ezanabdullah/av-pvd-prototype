# AV-PVD: Adaptive Vulnerability Propagation Detection

A Python proof-of-concept implementing the AV-PVD monitoring system described in the paper. Ingests Ethereum block data (real archive node or synthetic mock), computes Temporal Risk Gradient (TRG), builds a Vulnerability Propagation Graph (VPG), maintains Adaptive Trust Scores (ATS) per address, and emits VScore alerts.

## Architecture

```
Block stream (Web3 / Mock)
        │
        ▼
  RiskComputer           Risk(Bi) = corr × [w₁·GasAnomaly + w₂·CallDepth + w₃·Entropy]
        │
        ▼
  TRGComputer            TRG(t) = Σᵢ Risk(Bᵢ) · e^{−λ(t−tᵢ)}
        │
        ├──► VPG          Directed graph: edges weighted by risk × value fraction
        │
        ├──► ATS          Per-address EMA trust: α·ATS_old + (1−α)·Behaviour
        │
        └──► VScore       Risk_norm × TRG_boost × (1−ATS_mean) × PropFactor
                │
                ▼
            Alert (if VScore > threshold)
```

## Risk(Bi) Formulation

We propose a concrete, justified Risk(Bi) as a weighted combination of three normalised anomaly signals:

```
Risk(Bi) = Corroboration × [w₁·GasAnomaly(Bi) + w₂·CallDepthDeviation(Bi) + w₃·ValueTransferEntropy(Bi)]
```

| Component | Weight | Description |
|-----------|--------|-------------|
| GasAnomaly | 0.25 | Sigmoid z-score of block mean gas vs. rolling baseline. Spikes during reentrancy and flash-loan attacks. |
| CallDepthDeviation | 0.50 | Max call depth in block vs. protocol norm (μ=3.5, σ=1.5). Reentrancy drives depth 7-12+. |
| ValueTransferEntropy | 0.25 | Shannon entropy of ETH value distribution. Concentrated drains (low entropy) and uniform withdrawals (high entropy) both deviate from normal log-normal spread. |
| **Corroboration** | — | Penalty for single-component spikes: ×1.0 if all three elevated, ×0.65 if two, ×0.3 if one. Prevents isolated gas outliers from triggering alerts. |

**Justification:** Legitimate DeFi transactions rarely exceed call depth 4-5. Reentrancy exploits require recursive calls (depth 8-12). Flash loans pack extreme gas into a single block. Single-component spikes (e.g., gas alone) are common in normal lognormal-distributed blocks; requiring corroboration dramatically reduces false positive rates.

## Setup

```bash
# Clone and install
git clone https://github.com/ezanabdullah/av-pvd-prototype
cd av-pvd-prototype
pip install -e .

# Optional: for real Ethereum data
pip install -e ".[live]"
```

**Requirements:** Python ≥ 3.11. No external dependencies for mock mode.

## Quick Start

### Mock mode (no API key needed)

```bash
python examples/run_demo.py                        # reentrancy attack at block 100
python examples/run_demo.py --attack flash_loan    # flash loan variant
python examples/run_demo.py --attack slow_drain    # slow drain (adversarial)
python examples/run_demo.py --attack none          # baseline only
```

### Real Ethereum data

```bash
export RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
python -c "
from av_pvd.monitor import AVPVDMonitor
m = AVPVDMonitor(threshold=0.65, verbose=True)
result = m.run_web3(start=17_000_000, end=17_000_200)
result.print_summary()
"
```

Free archive access: [Alchemy](https://www.alchemy.com/) or [QuickNode](https://www.quicknode.com/).

### Task 2 — Exploit evaluation

```bash
python examples/evaluate_exploits.py
```

Evaluates against 5 historical exploit profiles (DAO, Wormhole, Beanstalk, Cream, Ronin).

### Task 3 — Adversarial evasion

```bash
python examples/adversarial_evasion.py
```

## Task 2 Results

| Exploit | Detected | Latency (blocks) | Latency (sec) | Peak VScore | FP |
|---------|----------|------------------|---------------|-------------|-----|
| The DAO (2016) — Reentrancy | YES | 0 | 0 | 0.491 | 0 |
| Wormhole (2022) — Signature Bypass | YES | 1 | 12 | 0.463 | 0 |
| Beanstalk (2022) — Flash Loan Governance | YES | 0 | 0 | 0.413 | 0 |
| Cream Finance (2021) — Flash Loan Oracle | YES | 0 | 0 | 0.463 | 0 |
| Ronin Bridge (2022) — Validator Compromise | YES | 2 | 24 | 0.465 | 0 |

**Aggregate:** Precision = 1.00, Recall = 1.00, F1 = 1.00 (threshold = 0.40)

## Task 3 Results — Adversarial Evasion

### (a) Slow Drain Attack

Attacker spreads 0.5 ETH withdrawals across 180 blocks. Each block looks normal (gas 50k, depth 2). **Result without mitigation: EVADED** — per-block VScore never exceeds 0.26.

**Mitigation — Cumulative Drift Detection:** A sliding window of 50 blocks tracks cumulative outbound value. Alert fires when rolling drain exceeds 10 ETH threshold. **Result with mitigation: DETECTED at block 120** (latency: 20 blocks after drain starts), with zero FPs in pre-drain period.

### (b) Trust Farming Attack

Attacker builds ATS through N blocks of benign transactions before executing reentrancy. With ATS near 1.0, VScore is suppressed by `(1 - ATS) ≈ 0`.

| Farm blocks | Trust at attack | Detected |
|-------------|-----------------|----------|
| 50 | 0.960 | NO |
| 100 | 0.990 | NO |
| 200 | 0.998 | NO |

**Mitigation — Trust Decay Amplification:** Increase passive decay rate from 0.0001 to 0.005/block and reduce EMA alpha from 0.95 to 0.90. After 200 farm blocks, trust stabilises around 0.955 (vs 0.998 without mitigation). **Result: still EVADED** — even with mitigation, 200 blocks of legitimate activity sufficiently suppress VScore. Proposed further mitigation: add a minimum raw-risk floor in VScore that bypasses the trust factor when all three components are simultaneously at maximum (risk≥0.9), ensuring catastrophic attacks are always flagged regardless of trust history.

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## File Structure

```
av_pvd/
  models.py     — Block, Transaction, Alert data classes
  risk.py       — Risk(Bi) computation with corroboration logic
  trg.py        — Temporal Risk Gradient (exponential decay accumulator)
  vpg.py        — Vulnerability Propagation Graph (incremental, decaying edges)
  ats.py        — Adaptive Trust Scorer (EMA per address)
  vscore.py     — VScore pipeline + alert emission
  ingestor.py   — Web3 (real) and Mock block ingestors
  monitor.py    — AVPVDMonitor top-level orchestrator

examples/
  run_demo.py              — Task 1: interactive demo
  evaluate_exploits.py     — Task 2: 5-exploit evaluation table
  adversarial_evasion.py   — Task 3: slow drain + trust farming

tests/
  test_core.py  — 14 unit tests (all passing)
```

## Reproducing the paper's results

All numbers in the accompanying manuscript ("Toward Early-Stage, Intra-Execution Security in Blockchain: The AV-PVD Framework") come from the scripts below. Use Python 3.11+; the baseline comparison also needs `scikit-learn` and `numpy`. The alert threshold used in the paper is **0.40**; note that the library default (0.6) is higher and detects none of the five profiles.

```bash
python3.11 examples/evaluate_exploits.py          # reference run (seed 42, threshold 0.40)
python3.11 experiments/seed_threshold_sweep.py    # 30 seeds x 5 profiles -> experiments/results/
python3.11 experiments/analyze_sweep.py           # detection / latency / false alerts per threshold
python3.11 experiments/ablation.py                # component ablation -> experiments/results/ablation.json
python3.11 experiments/analyze_ablation.py        # ablation table
python3.11 experiments/baselines.py               # single-signal rules + Isolation Forest (needs scikit-learn)
python3.11 experiments/adversarial_at_tau.py      # slow-drain and trust-farming at threshold 0.40 and 0.50
python3.11 experiments/component_breakdown.py     # per-block Risk components for each profile
python3.11 benchmark.py                           # per-stage timing and memory
```

The `experiments/results/` directory contains the raw per-block VScores used for the tables (`seed_threshold_sweep.json`, `ablation.json`, `baselines.json`). The exploit profiles are synthetic reconstructions from public post-mortems and DeFiHackLabs, not replays of archive-node traces.

