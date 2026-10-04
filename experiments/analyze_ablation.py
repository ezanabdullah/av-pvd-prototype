"""Summarize ablation.json (Table: component ablation in the paper)."""
import json, os, statistics as st
RES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results")
ab = json.load(open(os.path.join(RES, "ablation.json")))
sw = json.load(open(os.path.join(RES, "seed_threshold_sweep.json")))
ex = sw["exploits"]; WARM = 20
ref = {(r["exploit"], r["seed"]): r["vscores"] for r in sw["runs"]}
full = {(r["exploit"], r["seed"]): r["vscores"] for r in ab if r["variant"] == "full"}
print("full variant reproduces main sweep exactly:", all(max(abs(a - b) for a, b in zip(full[k], ref[k])) < 1e-12 for k in ref))
for v in ["full", "no_kappa", "no_trg", "no_vpg", "no_ats"]:
    runs = [r for r in ab if r["variant"] == v]
    bgmax = max(max(r["vscores"][WARM:100]) for r in runs if r["exploit"] == 0)
    pk = {}
    for r in runs:
        e = ex[r["exploit"]]; a = e["start_block"]; L = e["duration_blocks"]
        pk.setdefault(r["exploit"], []).append(max(r["vscores"][a:a + L]))
    det40 = sum(1 for e in pk for x in pk[e] if x > 0.40)
    fp40 = sum(1 for r in runs if r["exploit"] == 0 for x in r["vscores"][WARM:100] if x > 0.40)
    per = [sum(1 for x in pk[e] if x > bgmax) for e in range(5)]
    print(f"{v:9s} max_background={bgmax:.3f} zero-FP detected={sum(per)}/150 per={per} | tau=0.40: detected={det40}/150 false_alerts={fp40}")
