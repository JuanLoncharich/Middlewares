# GitOps: how the k0s cluster is deployed

Flux runs in the cluster, watches this repository's `main` branch and applies
`deploy/k0s`. Nobody runs `kubectl apply` or `deploy.sh` against k0s.

```
push to main ──► images.yml: build + push the images to Docker Hub (sha-<7>)
                 └─► re-render deploy/k0s/generated with that tag, commit it
Flux (every 2 min) ──► sees the new commit ──► applies deploy/k0s
```

| path | what it is |
|---|---|
| `k0s/render.env` | the `deploy.sh` settings for this cluster (provider, replicas, registry). No secrets |
| `k0s/generated/` | **generated** by `hack/gitops/render.sh` from `deploy.sh`: everything it would apply, minus Secrets. Never edit by hand |
| `k0s/patches/` | what only this cluster needs (Vigil pinned to the GPU PC) |
| `flux/` | Flux itself (source + kustomize controllers only) and its sync objects |
| `k0s-nodes/` | node-level settings Flux cannot manage: kubelet memory reserves and eviction thresholds (`apply.sh`, run by hand from the laptop) |

`deploy.sh` stays the one description of the platform: kind and one-off
clusters still use it directly, and `render.sh` runs it with a stand-in
`kubectl` that records instead of applying (`hack/gitops/fake-kubectl.py`).

## Changing something

- **A manifest or deploy.sh**: change it, then `hack/gitops/render.sh deploy/k0s`
  and commit both. CI re-renders on every push to main anyway, so a forgotten
  render is fixed by the next image build.
- **A cluster setting** (model, LLM URL, replicas): edit `k0s/render.env`, render, commit.
- **Images**: nothing to do. CI builds them and bumps the tag.
- The corpus image is the exception: its data file is git-ignored
  (hack/vigil-corpus), so it is built and pushed by hand, once per corpus.

## Node memory protection (outside Flux)

The kubelet settings live on the VMs, not in the API, so Flux cannot apply
them. `k0s-nodes/worker-profiles.yaml` is their source of truth;
`k0s-nodes/apply.sh plan` shows the current state (read-only) and
`apply.sh apply` rolls them out one node at a time (`rollback` undoes it).
Run it from the laptop, which holds the SSH key for the nodes, or from
anywhere with `JUMP=<laptop>`. Re-run `apply` after reinstalling a node.

## Secrets

Secrets never go to git. `hack/gitops/secrets.sh deploy/k0s` creates them once
per cluster (LLM key for Occludra, a placeholder for the evaluation
namespace, Chroma tokens, MinIO's fixed profile) and rewrites the LLM key when
run again. Flux does not manage them, so they survive every sync.

## Installing Flux on a cluster (once)

```
kubectl --context k0s apply -k deploy/flux
CONTEXT=k0s LOCAL_LLM_API_KEY="$(cat ~/.config/mcp-eval/local-llm.key)" hack/gitops/secrets.sh deploy/k0s
kubectl --context k0s -n flux-system get gitrepository,kustomization
```

To upgrade Flux: `flux install --export --components=source-controller,kustomize-controller
--network-policy=true > deploy/flux/gotk-components.yaml`, commit, apply again.

Flux never prunes Namespaces or PVCs (annotation set by the renderer), so a
bad commit cannot delete the vector data or the hand-made Secrets.

## What runs outside the cluster

- **The LLM**: llama.cpp on the GPU PC, `PUBLISH=<its ZeroTier IP>
  LOCAL_LLM_API_KEY=... hack/local-llm/llm up`. Occludra may reach exactly that
  IP and port (`occludra-egress-local-llm`).
- **Vigil's node**: the GPU PC joins k0s as a worker with `hack/gpu-node/gpu-node up`.
  While it is detached Vigil is Pending and evaluations fail closed.
