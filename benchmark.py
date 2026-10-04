"""
AV-PVD per-block timing and memory benchmark.
Runs 200 blocks (100 baseline + 100 attack) and reports
per-stage timing and peak RSS.
"""

import os
import sys
import time
import statistics
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from av_pvd.models import Block
from av_pvd.risk import RiskComputer
from av_pvd.trg import TRGComputer
from av_pvd.vpg import VulnerabilityPropagationGraph
from av_pvd.ats import AdaptiveTrustScorer
from av_pvd.vscore import VScoreEngine
from av_pvd.ingestor import MockIngestor

N_BLOCKS = 200
ATTACK_PROFILE = {
    "start_block": 100,
    "end_block": 110,
    "type": "reentrancy",
}

# Pre-generate all blocks so generation time doesn't pollute measurements
ingestor = MockIngestor(seed=42)
blocks = list(ingestor.iter_blocks(0, N_BLOCKS - 1, attack_profile=ATTACK_PROFILE))

# Per-stage timers (nanoseconds, converted to ms at the end)
stage_times = {
    "feature_extraction": [],
    "trg_update": [],
    "vpg_update": [],
    "ats_update": [],
    "vscore_compute": [],
    "total": [],
}

# Instrument VScoreEngine internals with a manual loop
risk_computer = RiskComputer()
trg_computer = TRGComputer()
vpg = VulnerabilityPropagationGraph()
trust_scorer = AdaptiveTrustScorer()
engine = VScoreEngine(
    threshold=0.6,
    risk_computer=risk_computer,
    trg_computer=trg_computer,
    vpg=vpg,
    trust_scorer=trust_scorer,
)

tracemalloc.start()

for block in blocks:
    t0 = time.perf_counter_ns()

    # Stage 1: feature extraction (Risk computation)
    t1 = time.perf_counter_ns()
    risk = risk_computer.compute(block)
    t2 = time.perf_counter_ns()

    # Stage 2: TRG update
    trg = trg_computer.update_and_compute(block, risk)
    t3 = time.perf_counter_ns()

    # Stage 3: VPG update
    vpg.update(block, risk)
    t4 = time.perf_counter_ns()

    # Stage 4: ATS update
    trust_scorer.update(block, risk)
    t5 = time.perf_counter_ns()

    # Stage 5: VScore compute (via engine internal, reusing already-updated components)
    vscore = engine._compute_vscore(block, risk, trg)
    t6 = time.perf_counter_ns()

    stage_times["feature_extraction"].append(t2 - t1)
    stage_times["trg_update"].append(t3 - t2)
    stage_times["vpg_update"].append(t4 - t3)
    stage_times["ats_update"].append(t5 - t4)
    stage_times["vscore_compute"].append(t6 - t5)
    stage_times["total"].append(t6 - t0)

_, peak_bytes = tracemalloc.get_traced_memory()
tracemalloc.stop()

peak_mb = peak_bytes / (1024 * 1024)

print("=" * 60)
print("AV-PVD Block Processing Benchmark")
print(f"Blocks: {N_BLOCKS}  (100 baseline + 10 reentrancy attack + 90 post)")
print("=" * 60)

labels = {
    "feature_extraction": "Feature extraction (Risk)",
    "trg_update": "TRG update",
    "vpg_update": "VPG graph update",
    "ats_update": "ATS update",
    "vscore_compute": "VScore computation",
    "total": "TOTAL per block",
}

for key, label in labels.items():
    ns_list = stage_times[key]
    mean_ms = statistics.mean(ns_list) / 1e6
    median_ms = statistics.median(ns_list) / 1e6
    p95_ms = sorted(ns_list)[int(0.95 * len(ns_list))] / 1e6
    sep = "-" * 40 if key == "total" else ""
    if sep:
        print(sep)
    print(f"{label:<35} mean={mean_ms:.3f}ms  median={median_ms:.3f}ms  p95={p95_ms:.3f}ms")

print("=" * 60)
print(f"Peak tracemalloc memory: {peak_mb:.2f} MB")
print("=" * 60)

import platform
print(f"Python: {sys.version.split()[0]}  |  Platform: {platform.platform()}")
print(f"CPU: {platform.processor() or platform.machine()}")
