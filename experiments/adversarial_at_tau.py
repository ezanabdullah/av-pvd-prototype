import sys, os
PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PROTO, "experiments", "results")
sys.path.insert(0, PROTO); sys.path.insert(0, os.path.join(PROTO, "examples"))
import io, contextlib
import adversarial_evasion as A
for tau in (0.40, 0.50):
    print("== tau", tau)
    r = A.run_slow_drain(threshold=tau, use_mitigation=False); print("slow drain no-mit:", {k:v for k,v in r.items() if k!='vscore_series'})
    r = A.run_slow_drain(threshold=tau, use_mitigation=True);  print("slow drain mit   :", {k:v for k,v in r.items() if k!='vscore_series'})
    for n in (50,100,200):
        r = A.run_trust_farming(trust_farm_blocks=n, threshold=tau); print("farm",n, {k:v for k,v in r.items() if k!='vscore_series'})
    r = A.run_trust_farming(trust_farm_blocks=200, threshold=tau, use_mitigation=True); print("farm 200 mit", {k:v for k,v in r.items() if k!='vscore_series'})
