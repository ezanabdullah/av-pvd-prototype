"""Read-only ablation of AV-PVD prototype components (no changes to the prototype repo).
Variants are built by subclassing; the 'full' variant must reproduce the original sweep exactly."""
import json, math, os, statistics, sys, time
from multiprocessing import Pool

PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, PROTO); sys.path.insert(0, os.path.join(PROTO, "examples"))

from av_pvd.risk import RiskComputer                      # noqa: E402
from av_pvd.vscore import VScoreEngine                     # noqa: E402
from av_pvd.monitor import AVPVDMonitor                    # noqa: E402
from evaluate_exploits import EXPLOITS, ExploitIngestor    # noqa: E402

SEEDS = list(range(30)); POST = 20


class NoKappaRisk(RiskComputer):
    """Same as RiskComputer.compute but corroboration multiplier fixed to 1."""
    def compute(self, block):
        if not block.transactions:
            return 0.0
        g = self._gas_anomaly(block); d = self._call_depth_deviation(block); e = self._value_transfer_entropy(block)
        risk = self.w_gas * g + self.w_depth * d + self.w_entropy * e
        self._gas_history.append(block.mean_gas_used)
        self._entropy_history.append(self._block_value_entropy(block))
        return min(risk, 1.0)


class FlagEngine(VScoreEngine):
    def __init__(self, use_trg=True, use_ats=True, use_vpg=True, **kw):
        super().__init__(**kw)
        self.use_trg, self.use_ats, self.use_vpg = use_trg, use_ats, use_vpg

    def _compute_vscore(self, block, risk, trg):  # faithful copy of VScoreEngine._compute_vscore with switches
        import statistics as st
        if len(self._risk_baseline) >= 10:
            r_mu = st.mean(self._risk_baseline); r_sigma = st.stdev(self._risk_baseline) or 0.05
            risk_z = (risk - r_mu) / r_sigma
        else:
            risk_z = (risk - 0.3) / 0.1
        risk_norm = 1.0 / (1.0 + math.exp(-risk_z))
        if self.use_trg and len(self._trg_baseline) >= 10:
            t_mu = st.mean(self._trg_baseline); t_sigma = st.stdev(self._trg_baseline) or 0.1
            trg_boost = 1.0 + 0.2 * math.tanh(max((trg - t_mu) / t_sigma - 1.0, 0.0))
        else:
            trg_boost = 1.0
        if self.use_ats:
            addrs = set()
            for tx in block.transactions:
                addrs.add(tx.from_addr)
                if tx.to_addr: addrs.add(tx.to_addr)
            mean_trust = sum(self.trust_scorer.get_trust(a) for a in addrs) / len(addrs) if addrs else 0.5
            trust_factor = 1.0 - mean_trust
        else:
            trust_factor = 0.5
        if self.use_vpg:
            dens = self.vpg.edge_count() / max(self.vpg.node_count(), 1)
            prop = min(1.0 + math.log(1.0 + dens) / math.log(10.0), 2.0)
        else:
            prop = 1.0
        return min(risk_norm * trg_boost * trust_factor * prop, 1.0)


VARIANTS = {
    "full":    dict(),
    "no_kappa": dict(kappa=False),
    "no_trg":  dict(use_trg=False),
    "no_vpg":  dict(use_vpg=False),
    "no_ats":  dict(use_ats=False),
}


def run(args):
    vname, ei, seed = args
    cfg = dict(VARIANTS[vname]); prof = EXPLOITS[ei]
    rc = NoKappaRisk() if cfg.pop("kappa", True) is False else RiskComputer()
    eng = FlagEngine(threshold=0.4, risk_computer=rc, **cfg)
    mon = AVPVDMonitor(vscore_engine=eng, threshold=0.4, verbose=False)
    end = prof["start_block"] + prof["duration_blocks"] + POST
    vs = [mon.process_block(b)[0] for b in ExploitIngestor(prof, seed=seed).iter_blocks(0, end)]
    return vname, ei, seed, vs


if __name__ == "__main__":
    t0 = time.time()
    jobs = [(v, e, s) for v in VARIANTS for e in range(len(EXPLOITS)) for s in SEEDS]
    with Pool(10) as p:
        res = p.map(run, jobs)
    json.dump([{"variant": v, "exploit": e, "seed": s, "vscores": x} for v, e, s, x in res], open(os.path.join(RES, "ablation.json"), "w"))
    print("done", len(res), round(time.time() - t0, 1), "s")
