"""Held-out threshold calibration (answers 'thresholds chosen on evaluation data').
Seeds 0-14: calibrate each detector's threshold = largest background score (blocks 50-99).
Seeds 15-29: test. Detection = attack-window maximum above the calibrated threshold;
false alerts = test background blocks (50-99) above it."""
import json, os, sys
PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, os.path.join(PROTO, "experiments"))
from baselines import run, SEEDS, WIN0, EXPLOITS  # noqa: E402

CAL = [s for s in SEEDS if s < 15]; TEST = [s for s in SEEDS if s >= 15]

ab = json.load(open(os.path.join(RES, "ablation.json")))
full = {(r["exploit"], r["seed"]): r["vscores"] for r in ab if r["variant"] == "full"}

series = {}  # detector -> {(ei, seed): list}
for ei in range(5):
    for seed in SEEDS:
        for name, s in run(ei, seed).items():
            series.setdefault(name, {})[(ei, seed)] = s
        series.setdefault("AV-PVD (full)", {})[(ei, seed)] = full[(ei, seed)]

out = {}
for name, d in series.items():
    tau = max(max(d[(0, s)][WIN0:100]) for s in CAL)      # background identical across profiles per seed
    det = [0] * 5
    for ei in range(5):
        a = EXPLOITS[ei]["start_block"]; L = EXPLOITS[ei]["duration_blocks"]
        det[ei] = sum(1 for s in TEST if max(d[(ei, s)][a:a + L]) > tau)
    fp = sum(1 for s in TEST for x in d[(0, s)][WIN0:100] if x > tau)
    out[name] = {"calibrated_threshold": tau, "detected_per_profile": det, "detected_total": sum(det),
                 "test_attack_runs": 5 * len(TEST), "false_alerts": fp, "test_background_blocks": len(TEST) * (100 - WIN0)}
    print(f"{name:28s} tau={tau:8.3f} detected={sum(det)}/{5*len(TEST)} per={det} false_alerts={fp}/{len(TEST)*(100-WIN0)}")
json.dump(out, open(os.path.join(RES, "heldout_threshold.json"), "w"), indent=1)
