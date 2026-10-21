#!/usr/bin/env python3
# Stand-in `kubectl` for hack/gitops/render.sh: records instead of applying.
#
# apply -f ...        manifests are appended to $RENDER_OUT/manifests.yaml
# set env deploy/X    recorded in $RENDER_OUT/setenv.jsonl
# kustomize, create --dry-run=client
#                     run by the real kubectl ($REAL_KUBECTL); both are offline
# get endpointslices  answered from RENDER_API_PEERS / RENDER_API_PORT
# get secret -o ...   a placeholder (the Secret it feeds is dropped anyway)
# get (anything else) "not found", so scripts take their first-install path
# rollout, wait, delete, annotate, patch, scale, label
#                     no-ops: Flux owns the live cluster
import json
import os
import sys

OUT = os.environ["RENDER_OUT"]
os.makedirs(OUT, exist_ok=True)
args = sys.argv[1:]

# Flags that take a value; everything else starting with '-' stands alone.
VALUED = {"-n", "--namespace", "--context", "-o", "--output", "-f", "--filename", "-l", "--selector",
          "-p", "--patch", "--type", "--timeout", "--for", "--from-file", "--from-literal",
          "--from-env-file", "--dry-run", "-c", "--field-selector", "--replicas"}


def split(argv):
    words, flags = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("-"):
            if "=" in a or a not in VALUED:
                flags.append((a.split("=", 1)[0], a.split("=", 1)[1] if "=" in a else None))
            else:
                flags.append((a, argv[i + 1] if i + 1 < len(argv) else None))
                i += 1
        else:
            words.append(a)
        i += 1
    return words, flags


words, flags = split(args)
verb = words[0] if words else ""
flag = {k: v for k, v in flags}
ns = flag.get("-n") or flag.get("--namespace")


def real():
    os.execv(os.environ["REAL_KUBECTL"], [os.environ["REAL_KUBECTL"]] + args)


if verb == "kustomize":
    real()
if verb == "create":
    if not any(k == "--dry-run" for k, _ in flags):
        sys.exit(f"render: refusing a real create: kubectl {' '.join(args)}")
    real()

if verb == "apply":
    files = [v for k, v in flags if k in ("-f", "--filename")]
    chunks = []
    for f in files:
        if f == "-":
            chunks.append(sys.stdin.read())
        elif f.startswith("http"):
            sys.exit(f"render: remote manifest not supported: {f}")
        elif os.path.isdir(f):
            for name in sorted(os.listdir(f)):
                if name.endswith((".yaml", ".yml")):
                    chunks.append(open(os.path.join(f, name)).read())
        else:
            chunks.append(open(f).read())
    with open(os.path.join(OUT, "manifests.jsonl"), "a") as out:
        for c in chunks:
            out.write(json.dumps({"namespace": ns, "yaml": c}) + "\n")
    print("rendered")
    sys.exit(0)

if verb == "set" and len(words) >= 3 and words[1] == "env":
    target = words[2]
    env = [w for w in words[3:] if "=" in w]
    with open(os.path.join(OUT, "setenv.jsonl"), "a") as out:
        out.write(json.dumps({"namespace": ns, "target": target, "env": env}) + "\n")
    sys.exit(0)

if verb == "get":
    what = " ".join(words[1:])
    output = flag.get("-o") or flag.get("--output") or ""
    if "endpointslices" in what:
        if "ports[0].port" in output:
            print(os.environ["RENDER_API_PORT"], end="")
        else:
            print(" ".join(os.environ["RENDER_API_PEERS"].split()), end="")
        sys.exit(0)
    if what.startswith("secret") and output.startswith("jsonpath"):
        print("cmVuZGVyLXBsYWNlaG9sZGVy", end="")   # base64("render-placeholder")
        sys.exit(0)
    print(f'Error from server (NotFound): {what} (render)', file=sys.stderr)
    sys.exit(1)

if verb in ("rollout", "wait", "delete", "annotate", "patch", "scale", "label"):
    sys.exit(0)

sys.exit(f"render: unsupported kubectl call: kubectl {' '.join(args)}")
