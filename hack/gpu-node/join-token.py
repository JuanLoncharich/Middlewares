#!/usr/bin/env python3
# Make a k0s worker join token without SSH to the controller (gpu-node token).
#
# A k0s worker token is a gzipped, base64 kubeconfig that authenticates with a
# Kubernetes bootstrap token (Secret bootstrap-token-<id> in kube-system);
# k0s's own RBAC lets the group system:bootstrappers join and fetch the worker
# config.
#
#   stdin   the cluster CA (PEM)
#   env     API (server URL), EXPIRY (e.g. 24h or 30m)
#   fd 3    the bootstrap-token Secret, for `kubectl apply -f -`
#   stdout  the join token, for the token file
#   stderr  the token id (not secret on its own)
import base64
import datetime
import gzip
import os
import re
import secrets
import string
import sys

ca = sys.stdin.read()
if "BEGIN CERTIFICATE" not in ca:
    sys.exit("join-token: no CA on stdin")
m = re.fullmatch(r"(\d+)([hm])", os.environ["EXPIRY"])
if not m:
    sys.exit("join-token: EXPIRY must look like 24h or 30m")
delta = datetime.timedelta(hours=int(m[1])) if m[2] == "h" else datetime.timedelta(minutes=int(m[1]))
expires = (datetime.datetime.now(datetime.timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")

alpha = string.ascii_lowercase + string.digits
tid = "".join(secrets.choice(alpha) for _ in range(6))
tsec = "".join(secrets.choice(alpha) for _ in range(16))

secret = f"""apiVersion: v1
kind: Secret
type: bootstrap.kubernetes.io/token
metadata:
  name: bootstrap-token-{tid}
  namespace: kube-system
stringData:
  token-id: {tid}
  token-secret: {tsec}
  expiration: {expires}
  usage-bootstrap-authentication: "true"
  usage-bootstrap-signing: "true"
  description: gpu-node join token
"""
kubeconfig = f"""apiVersion: v1
kind: Config
clusters:
- name: k0s
  cluster:
    server: {os.environ["API"]}
    certificate-authority-data: {base64.b64encode(ca.encode()).decode()}
contexts:
- name: k0s
  context:
    cluster: k0s
    user: kubelet-bootstrap
current-context: k0s
users:
- name: kubelet-bootstrap
  user:
    token: {tid}.{tsec}
"""
with os.fdopen(3, "w") as out:
    out.write(secret)
sys.stdout.write(base64.b64encode(gzip.compress(kubeconfig.encode())).decode())
print(tid, file=sys.stderr)
