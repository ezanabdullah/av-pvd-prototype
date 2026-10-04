"""Read-only multi-seed sweep over the AV-PVD prototype exploit profiles.
Stores raw VScore series; thresholds are applied offline (alerts are a pure
function of VScore > tau after the 20-block warm-up, no state feedback)."""
import json, os, sys, time
from multiprocessing import Pool

PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, PROTO)
sys.path.insert(0, os.path.join(PROTO, "examples"))

from av_pvd.monitor import AVPVDMonitor          # noqa: E402
from evaluate_exploits import EXPLOITS, ExploitIngestor  # noqa: E402

SEEDS = list(range(30))
POST = 20


def run(args):
    ei, seed = args
    prof = EXPLOITS[ei]
    mon = AVPVDMonitor(threshold=0.4, verbose=False)
    ing = ExploitIngestor(prof, seed=seed)
    end = prof["start_block"] + prof["duration_blocks"] + POST
    series = []
    for b in ing.iter_blocks(0, end):
        v, _ = mon.process_block(b)
        series.append(v)
    return ei, seed, series


if __name__ == "__main__":
    t0 = time.time()
    jobs = [(e, s) for e in range(len(EXPLOITS)) for s in SEEDS]
    with Pool(8) as p:
        res = p.map(run, jobs)
    out = {"exploits": [{k: e[k] for k in ("name", "start_block", "duration_blocks")} for e in EXPLOITS],
           "runs": [{"exploit": e, "seed": s, "vscores": v} for e, s, v in res]}
    json.dump(out, open(os.path.join(RES, "seed_threshold_sweep.json"), "w"))
    print("done", len(res), "runs in", round(time.time() - t0, 1), "s")
