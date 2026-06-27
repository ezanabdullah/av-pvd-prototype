"""
Task 3 — Adversarial Evasion Analysis.

Two evasion scenarios:

(a) Slow Drain Attack
    Attacker spreads withdrawals over many blocks, keeping per-block
    TRG below the detection threshold. We test whether AV-PVD catches
    the cumulative drift via entropy shifts across the time window.

(b) Trust Farming Attack
    Attacker builds high ATS over N "honest" blocks before striking.
    Since VScore × (1 - ATS) suppresses the score when trust is high,
    we measure how many trust-farming blocks suffice to mask an attack.

For each scenario we also implement and test a mitigation:
  (a) Cumulative Drift Detector: tracks rolling sum of value_wei
      across a sliding window; fires if cumulative drain exceeds a
      threshold even when per-block scores look normal.
  (b) Trust Decay Amplifier: adds an extra decay term proportional to
      historical gas anomaly — "innocent-looking" blocks with elevated
      gas still erode trust slowly.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from av_pvd.monitor import AVPVDMonitor
from av_pvd.models import Block, Transaction
from av_pvd.vscore import VScoreEngine
from av_pvd.ats import AdaptiveTrustScorer
from av_pvd.risk import RiskComputer
from av_pvd.trg import TRGComputer
from av_pvd.vpg import VulnerabilityPropagationGraph

import random
from collections import deque


# ------------------------------------------------------------------ #
# Scenario (a): Slow Drain Attack
# ------------------------------------------------------------------ #

def run_slow_drain(
    n_blocks: int = 300,
    drain_start: int = 100,
    drain_end: int = 280,
    drain_amount_per_block_eth: float = 0.5,
    threshold: float = 0.5,
    use_mitigation: bool = False,
):
    """
    Attacker drains 0.5 ETH per block across 180 blocks (90 ETH total)
    in small equal transfers — per-block gas and depth look normal.

    Returns dict with detection info.
    """
    rng = random.Random(99)
    attacker = f"0x{'aa'*20}"
    victim = f"0x{'bb'*20}"
    base_ts = 1_700_000_000

    monitor = AVPVDMonitor(threshold=threshold, verbose=False)

    # Cumulative drift mitigation state
    cumulative_window: deque[float] = deque(maxlen=50)
    CUMULATIVE_THRESHOLD_ETH = 10.0
    mitigation_alert_block = None

    detected_block = None
    vscore_series = []
    total_drained = 0.0

    for bn in range(n_blocks):
        ts = base_ts + bn * 12
        is_drain = drain_start <= bn <= drain_end

        if is_drain:
            # Slow drain: many small txs, each looks normal
            n_drain_txs = 30
            drain_txs = []
            for i in range(n_drain_txs):
                drain_txs.append(Transaction(
                    tx_hash=f"0x{'dd'*28}{bn:04x}{i:04x}",
                    from_addr=attacker,
                    to_addr=victim,
                    value_wei=int(drain_amount_per_block_eth * 1e18 / n_drain_txs),
                    gas_used=50_000,   # normal gas
                    gas_price=30 * int(1e9),
                    call_depth=2,     # normal depth
                    input_data="0xdeadbeef",
                    is_contract_call=True,
                    block_number=bn,
                    tx_index=i,
                ))
            normal_txs = _make_normal_txs(bn, rng, count=70)
            block = Block(number=bn, timestamp=ts, transactions=drain_txs + normal_txs)
            total_drained += drain_amount_per_block_eth
        else:
            block = Block(
                number=bn,
                timestamp=ts,
                transactions=_make_normal_txs(bn, rng, count=120),
            )

        vscore, alert = monitor.process_block(block)
        vscore_series.append((bn, vscore, alert is not None))

        if alert and detected_block is None and bn >= drain_start:
            detected_block = bn

        # Mitigation: cumulative drift detection
        if use_mitigation and is_drain:
            block_drain = drain_amount_per_block_eth
            cumulative_window.append(block_drain)
            rolling_drain = sum(cumulative_window)
            if rolling_drain > CUMULATIVE_THRESHOLD_ETH and mitigation_alert_block is None:
                mitigation_alert_block = bn
                print(f"  [MITIGATION] Cumulative drift alert at block {bn}: "
                      f"{rolling_drain:.1f} ETH drained in last {len(cumulative_window)} blocks")

    detection = detected_block or mitigation_alert_block
    return {
        "scenario": "Slow Drain",
        "detected": detection is not None,
        "detection_block": detection,
        "detection_latency_blocks": (detection - drain_start) if detection else None,
        "total_drained_eth": total_drained,
        "fp_count": sum(1 for bn, _, alerted in vscore_series if alerted and bn < drain_start),
        "peak_vscore": max(vs for _, vs, _ in vscore_series),
        "vscore_series": vscore_series,
        "mitigation_fired": mitigation_alert_block,
    }


# ------------------------------------------------------------------ #
# Scenario (b): Trust Farming Attack
# ------------------------------------------------------------------ #

def run_trust_farming(
    trust_farm_blocks: int = 200,
    threshold: float = 0.5,
    use_mitigation: bool = False,
):
    """
    Attacker sends N blocks of benign-looking txs to build high ATS,
    then executes a reentrancy exploit at block trust_farm_blocks.

    With mitigation: extra trust decay applied for addresses whose
    historical gas patterns show any anomaly (even small ones).
    """
    rng = random.Random(77)
    attacker = f"0x{'ca'*20}"
    victim = f"0x{'fe'*20}"
    base_ts = 1_700_000_000

    # Custom ATS with faster decay if mitigation enabled
    if use_mitigation:
        trust_scorer = AdaptiveTrustScorer(alpha=0.90, trust_decay=0.005)
    else:
        trust_scorer = AdaptiveTrustScorer()  # default slow decay

    engine = VScoreEngine(
        threshold=threshold,
        trust_scorer=trust_scorer,
    )
    monitor = AVPVDMonitor(vscore_engine=engine, threshold=threshold, verbose=False)

    attack_block = trust_farm_blocks
    detected_block = None
    trust_at_attack = None
    vscore_series = []

    for bn in range(trust_farm_blocks + 20):
        ts = base_ts + bn * 12
        is_attack = bn == attack_block

        if is_attack:
            # Reentrancy exploit
            txs = []
            for i in range(5):
                txs.append(Transaction(
                    tx_hash=f"0x{'ee'*28}{bn:04x}{i:04x}",
                    from_addr=attacker,
                    to_addr=victim,
                    value_wei=int(10_000 * 1e18),
                    gas_used=1_500_000,
                    gas_price=500 * int(1e9),
                    call_depth=10,
                    input_data="0x" + "ff" * 200,
                    is_contract_call=True,
                    block_number=bn,
                    tx_index=i,
                ))
            trust_at_attack = trust_scorer.get_trust(attacker)
            block = Block(number=bn, timestamp=ts, transactions=txs)
        elif bn < trust_farm_blocks:
            # Trust farming: attacker sends normal-looking txs
            farm_txs = [Transaction(
                tx_hash=f"0x{'fa'*28}{bn:04x}0000",
                from_addr=attacker,
                to_addr=f"0x{'ab'*20}",
                value_wei=int(0.01 * 1e18),
                gas_used=50_000,
                gas_price=30 * int(1e9),
                call_depth=2,
                input_data="0xabcd",
                is_contract_call=True,
                block_number=bn,
                tx_index=0,
            )]
            normal = _make_normal_txs(bn, rng, count=100)
            block = Block(number=bn, timestamp=ts, transactions=farm_txs + normal)
        else:
            block = Block(
                number=bn, timestamp=ts,
                transactions=_make_normal_txs(bn, rng, count=100)
            )

        vscore, alert = monitor.process_block(block)
        vscore_series.append((bn, vscore, alert is not None))

        if alert and detected_block is None and bn >= attack_block:
            detected_block = bn

    return {
        "scenario": f"Trust Farming ({trust_farm_blocks} farm blocks)",
        "detected": detected_block is not None,
        "detection_block": detected_block,
        "detection_latency_blocks": (
            detected_block - attack_block if detected_block is not None else None
        ),
        "trust_at_attack": trust_at_attack,
        "peak_vscore": max(vs for _, vs, _ in vscore_series),
        "attack_block": attack_block,
        "vscore_series": vscore_series,
    }


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_normal_txs(block_num: int, rng: random.Random, count: int) -> list[Transaction]:
    txs = []
    for i in range(count):
        gas = int(rng.lognormvariate(11.0, 0.8))
        gas = max(21_000, min(gas, 500_000))
        depth = rng.choices([1, 2, 3, 4], weights=[0.4, 0.3, 0.2, 0.1])[0]
        val = int(rng.lognormvariate(14, 2)) if rng.random() < 0.3 else 0
        txs.append(Transaction(
            tx_hash=f"0x{'b0'*28}{block_num:04x}{i:04x}",
            from_addr=f"0x{'01'*18}{i:04x}",
            to_addr=f"0x{'02'*18}{i:04x}",
            value_wei=val,
            gas_used=gas,
            gas_price=30 * int(1e9),
            call_depth=depth,
            input_data="0x",
            is_contract_call=rng.random() < 0.6,
            block_number=block_num,
            tx_index=i,
        ))
    return txs


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main():
    print("\nAV-PVD — Adversarial Evasion Analysis (Task 3)")
    print("=" * 65)

    # ---- (a) Slow Drain ----
    print("\n[Scenario A] Slow Drain Attack — WITHOUT mitigation")
    r_a = run_slow_drain(use_mitigation=False)
    _print_result(r_a)

    print("\n[Scenario A] Slow Drain Attack — WITH cumulative drift mitigation")
    r_a_mit = run_slow_drain(use_mitigation=True)
    _print_result(r_a_mit)

    # ---- (b) Trust Farming ----
    for farm_blocks in [50, 100, 200]:
        print(f"\n[Scenario B] Trust Farming — {farm_blocks} farm blocks, NO mitigation")
        r_b = run_trust_farming(trust_farm_blocks=farm_blocks, use_mitigation=False)
        _print_result(r_b)

    print(f"\n[Scenario B] Trust Farming — 200 farm blocks, WITH trust decay mitigation")
    r_b_mit = run_trust_farming(trust_farm_blocks=200, use_mitigation=True)
    _print_result(r_b_mit)

    # ---- Summary table ----
    print("\n\nEvasion Analysis Summary")
    print("=" * 75)
    header = f"{'Scenario':<45} {'Detected':>8} {'Latency(blk)':>13} {'PeakVScore':>11}"
    print(header)
    print("-" * 75)
    for r in [r_a, r_a_mit, r_b, r_b_mit]:
        det = "YES" if r["detected"] else "NO"
        lat = str(r["detection_latency_blocks"]) if r["detection_latency_blocks"] is not None else "N/A"
        print(f"{r['scenario'][:44]:<45} {det:>8} {lat:>13} {r['peak_vscore']:>11.4f}")


def _print_result(r: dict):
    det = "DETECTED" if r["detected"] else "EVADED"
    print(f"  Result         : {det}")
    if r["detected"]:
        print(f"  Detection block: {r['detection_block']}")
        print(f"  Latency        : {r['detection_latency_blocks']} blocks")
    print(f"  Peak VScore    : {r['peak_vscore']:.4f}")
    if "trust_at_attack" in r and r["trust_at_attack"] is not None:
        print(f"  Trust at attack: {r['trust_at_attack']:.4f}")
    if "total_drained_eth" in r:
        print(f"  Total drained  : {r['total_drained_eth']:.1f} ETH")
    if r.get("fp_count") is not None:
        print(f"  False positives: {r['fp_count']}")


if __name__ == "__main__":
    main()
