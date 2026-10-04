import sys, os
PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, PROTO); sys.path.insert(0, os.path.join(PROTO, "examples"))
from evaluate_exploits import EXPLOITS, ExploitIngestor
from av_pvd.vscore import VScoreEngine
for seed in (42,):
  for p in EXPLOITS:
    eng = VScoreEngine(threshold=0.4); ing = ExploitIngestor(p, seed=seed)
    a=p["start_block"]; L=p["duration_blocks"]
    print("==", p["name"])
    for b in ing.iter_blocks(0, a+L+3):
        if a-1 <= b.number <= a+L+2:
            comps = eng.risk_computer.component_scores(b)   # before update (as engine does)
            v,_ = eng.process_block(b)
            print(f" blk {b.number} gas={comps['gas_anomaly']:.2f} depth={comps['call_depth_deviation']:.2f} ent={comps['value_transfer_entropy']:.2f} vscore={v:.3f}")
        else:
            eng.process_block(b)
