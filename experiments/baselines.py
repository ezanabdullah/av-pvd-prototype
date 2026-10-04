"""Baseline detectors on the SAME synthetic traces as the AV-PVD sweep (read-only on the prototype).
All detectors are compared at their zero-false-alert threshold on the background window (blocks 50-99),
so no detector gets a hand-tuned advantage. Isolation Forest is fit on blocks 0-49 (background only)."""
import json, math, os, statistics as st, sys
import numpy as np
from sklearn.ensemble import IsolationForest

PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, PROTO); sys.path.insert(0, os.path.join(PROTO, "examples"))
from evaluate_exploits import EXPLOITS, ExploitIngestor   # noqa: E402
from av_pvd.risk import RiskComputer                        # noqa: E402

SEEDS = list(range(30)); POST = 20; FIT = 50; WIN0 = 50


def feats(b):
    depths = [t.call_depth for t in b.transactions if t.is_contract_call]
    return [b.mean_gas_used, max(depths) if depths else 0, RiskComputer._block_value_entropy(b),
            len(b.transactions), math.log1p(sum(t.value_wei for t in b.transactions))]


def rolling_z(series, absval=False, w=50, minn=5):
    out = []
    for i, x in enumerate(series):
        h = series[max(0, i - w):i]
        if len(h) < minn:
            out.append(0.0); continue
        mu = st.mean(h); sd = st.stdev(h) or 1e-9
        z = (x - mu) / sd
        out.append(abs(z) if absval else z)
    return out


def run(ei, seed):
    prof = EXPLOITS[ei]; end = prof["start_block"] + prof["duration_blocks"] + POST
    F = np.array([feats(b) for b in ExploitIngestor(prof, seed=seed).iter_blocks(0, end)])
    sc = {}
    sc["Gas z-score rule"] = rolling_z(list(F[:, 0]))
    sc["Call-depth rule"] = list(F[:, 1])
    sc["Value-entropy z-score rule"] = rolling_z(list(F[:, 2]), absval=True)
    mu, sd = F[:FIT].mean(0), F[:FIT].std(0) + 1e-9
    iso = IsolationForest(n_estimators=100, random_state=0).fit((F[:FIT] - mu) / sd)
    sc["Isolation Forest"] = list(-iso.score_samples((F - mu) / sd))
    return sc


if __name__ == "__main__":
    ab = json.load(open(os.path.join(RES, "ablation.json")))
    full = {(r["exploit"], r["seed"]): r["vscores"] for r in ab if r["variant"] == "full"}
    data = {}  # det -> list of (ei, seed, series)
    for ei in range(5):
        for seed in SEEDS:
            for name, s in run(ei, seed).items():
                data.setdefault(name, []).append((ei, seed, s))
            data.setdefault("AV-PVD (full)", []).append((ei, seed, full[(ei, seed)]))
    out = {}
    for name, runs in data.items():
        bg = max(max(s[WIN0:100]) for ei, seed, s in runs if ei == 0)
        per = [0] * 5
        for ei, seed, s in runs:
            e = EXPLOITS[ei]; a = e["start_block"]; L = e["duration_blocks"]
            if max(s[a:a + L]) > bg: per[ei] += 1
        out[name] = {"bg_max": bg, "per": per, "total": sum(per)}
        print(f"{name:28s} bg_max={bg:8.3f} detected={sum(per)}/150 per={per}")
    json.dump(out, open(os.path.join(RES, "baselines.json"), "w"), indent=1)
