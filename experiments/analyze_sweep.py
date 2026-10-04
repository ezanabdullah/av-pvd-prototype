import json, os, statistics as st
RES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results")
d=json.load(open(os.path.join(RES, "seed_threshold_sweep.json")))
ex=d['exploits']; runs=d['runs']
WARM=20
def alerts(v,tau): return [i for i,x in enumerate(v) if x>tau and i>=WARM]
print("per-exploit peak vscore in attack window (mean, min, max over 30 seeds)")
for ei,e in enumerate(ex):
    a=e['start_block']; L=e['duration_blocks']
    pk=[max(r['vscores'][a:a+L]) for r in runs if r['exploit']==ei]
    print(f"{e['name'][:28]:30s} mean={st.mean(pk):.3f} min={min(pk):.3f} max={max(pk):.3f}")
for tau in [0.30,0.35,0.40,0.45,0.50,0.60]:
    print(f"\n=== tau={tau}")
    tot_fp=0; tot_blocks=0
    for ei,e in enumerate(ex):
        a=e['start_block']; L=e['duration_blocks']
        det=0; lat=[]; fp=0; n=0
        for r in runs:
            if r['exploit']!=ei: continue
            n+=1
            al=alerts(r['vscores'],tau)
            inwin=[i for i in al if a<=i<a+L]
            if inwin: det+=1; lat.append(inwin[0]-a)
            fp+=sum(1 for i in al if i<a)
            tot_blocks+=a-WARM
        tot_fp+=fp
        print(f"{e['name'][:28]:30s} det={det}/{n} lat={sorted(set(lat))} medlat={st.median(lat) if lat else None} FP={fp}")
    print(f"total FP alerts pre-attack={tot_fp} (profile-block evaluations: {tot_blocks}; the 5 profiles share each seed's background, so {tot_blocks//5} distinct blocks) -> {1000*tot_fp/tot_blocks:.2f}/1000 blocks")
