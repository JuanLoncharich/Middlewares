# s4_loso.py <model>... — leave-one-source-out: drop a source from the full
# corpus (+hp+mc), recalibrate, and measure detection of that source's TEST
# texts (pure and, where it exists, embedded). Unseen-family generalisation.
import os, sys
import pandas as pd
sys.path.insert(0, os.path.dirname(__file__))
from s3_eval import load, evaluate, pct, METHODS

PICK = ["whole", "hybrid 0+1", "sent0-2 p>=.3", "hybrid 0+1 p>=q2", "hybrid 0+1+2 p>=q2"]
target = float(os.environ.get("TARGET", "0.02")); calib_on = os.environ.get("CALIB", "tool")
out = []
for key in sys.argv[1:]:
    meta, dist, q = load(key)
    allsrc = sorted({g[0] for g in meta["groups"] if g[1] in (0, 1)} - {"mcptox-A"})
    for held in ("llmail-inject-p2", "hackaprompt", "mosscap", "gandalf-ignore", "trustair-jailbreak", "yanis-multilingual"):
        cs = [s for s in allsrc if s != held]
        for mname, method, ks, g, pb in METHODS:
            if mname not in PICK:
                continue
            r_out = evaluate(key, meta, dist, q, cs, method, ks, g, target, calib_on, purity=pb)
            r_in = evaluate(key, meta, dist, q, allsrc, method, ks, g, target, calib_on, purity=pb)
            out.append({"model": key, "held-out source": held, "method": mname,
                        "in corpus": pct(r_in, [held]), "LEFT OUT": pct(r_out, [held]),
                        "emb in": pct(r_in, ["embedded:" + held]), "emb LEFT OUT": pct(r_out, ["embedded:" + held])})
df = pd.DataFrame(out)
pd.set_option("display.width", 250)
print(df.round(0).to_string(index=False))
df.to_csv(os.path.expanduser(f"~/.cache/mcp-eval/corpus3/out/loso_{'-'.join(sys.argv[1:])}.csv"), index=False)
