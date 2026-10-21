/*
Copyright 2026 The MCP Eval Operator Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"os"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

func testRun() *securityv1alpha1.MCPEvaluationRun {
	return &securityv1alpha1.MCPEvaluationRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-1", Namespace: "mcp-evals"},
		Spec: securityv1alpha1.MCPEvaluationRunSpec{
			ServerRef:      "filesystem-mcp",
			Agents:         []string{"sast", "synth"},
			TimeoutSeconds: 900,
		},
	}
}

func meshImages() ImageConfig {
	return ImageConfig{
		MeshEnforce:          true,
		NetBirdImage:         "netbirdio/netbird:test",
		NetBirdManagementURL: "https://netbird.test:443",
		NetBirdSecretName:    "netbird-auth",
		NetBirdSecretKey:     "setup-key",
		NetBirdEgressCIDRs:   []string{"10.0.0.0/8", "192.168.0.0/16"},
		MeshProxyURL:         "socks5://127.0.0.1:1080",
		MeshBridgePort:       18080,
		VigilURL:             "http://vigil-service.security-gateways.svc.cluster.local:5000/analyze/prompt",
		OccludraBaseURL:      "http://occludra-service.security-gateways.svc.cluster.local:8080/v1",
	}
}

func envValue(t *testing.T, container corev1.Container, name string) string {
	t.Helper()
	for _, env := range container.Env {
		if env.Name == name {
			// An empty Value is meaningful (e.g. MESH_PROXY="" disables the
			// mesh); presence of the var is what this helper asserts.
			return env.Value
		}
	}
	t.Fatalf("env %s not found on container %s", name, container.Name)
	return ""
}

func TestBuildJobInjectsMeshSidecarAndEnv(t *testing.T) {
	r := &MCPEvaluationRunReconciler{Images: meshImages()}
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}

	job := r.buildJob(run, server)
	podSpec := job.Spec.Template.Spec

	// Sidecar: native (init, restartPolicy Always), userspace, no capabilities.
	var sidecar *corev1.Container
	for i := range podSpec.InitContainers {
		if podSpec.InitContainers[i].Name == containerNetBird {
			sidecar = &podSpec.InitContainers[i]
		}
	}
	if sidecar == nil {
		t.Fatal("netbird sidecar not injected into InitContainers")
	}
	if !isNativeSidecar(sidecar) {
		t.Error("netbird sidecar must be a native sidecar (restartPolicy Always)")
	}
	if envValue(t, *sidecar, "NETBIRD_USERSPACE_HOSTWIRESOCK") != "yes" {
		t.Error("sidecar must run in userspace mode (PSA restricted-safe)")
	}
	if sidecar.SecurityContext == nil || sidecar.SecurityContext.Capabilities == nil {
		t.Fatal("sidecar missing capabilities context")
	}
	if len(sidecar.SecurityContext.Capabilities.Add) != 0 {
		t.Errorf("userspace sidecar must not add capabilities, got %v", sidecar.SecurityContext.Capabilities.Add)
	}
	if !ptr.Deref(sidecar.SecurityContext.RunAsNonRoot, false) {
		t.Error("userspace sidecar must run as non-root")
	}

	// Evaluator: mesh + security layer env.
	var evaluator *corev1.Container
	for i := range podSpec.Containers {
		if podSpec.Containers[i].Name == containerEvaluator {
			evaluator = &podSpec.Containers[i]
		}
	}
	if evaluator == nil {
		t.Fatal("evaluator container missing")
	}
	if got := envValue(t, *evaluator, "MESH_PROXY"); got != "socks5://127.0.0.1:1080" {
		t.Errorf("MESH_PROXY = %q", got)
	}
	if got := envValue(t, *evaluator, "VIGIL_URL"); got != r.Images.VigilURL {
		t.Errorf("VIGIL_URL = %q", got)
	}
	if got := envValue(t, *evaluator, "OCCLUDRA_BASE_URL"); got != r.Images.OccludraBaseURL {
		t.Errorf("OCCLUDRA_BASE_URL = %q", got)
	}
}

func TestBuildJobMeshDisabledOmitsSidecarAndProxy(t *testing.T) {
	images := meshImages()
	images.MeshEnforce = false
	r := &MCPEvaluationRunReconciler{Images: images}
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}

	job := r.buildJob(run, server)
	podSpec := job.Spec.Template.Spec
	for i := range podSpec.InitContainers {
		if podSpec.InitContainers[i].Name == containerNetBird {
			t.Fatal("sidecar must be absent when the mesh is disabled")
		}
	}
	for i := range podSpec.Containers {
		if podSpec.Containers[i].Name == containerEvaluator {
			if got := envValue(t, podSpec.Containers[i], "MESH_PROXY"); got != "" {
				t.Errorf("MESH_PROXY must be explicitly empty when mesh disabled, got %q", got)
			}
		}
	}
	if s := r.buildNetBirdSidecar(run); len(s) != 0 {
		t.Fatal("buildNetBirdSidecar must return nil when the mesh is disabled")
	}
}

func TestBuildEvaluateNetworkPolicy(t *testing.T) {
	images := meshImages()
	run := testRun()
	policy := buildEvaluateNetworkPolicy(run, images, []string{"10.66.50.194/32"})

	if policy.Name != "run-1-evaluate-egress" || policy.Namespace != "mcp-evals" {
		t.Fatalf("unexpected policy name/namespace: %s/%s", policy.Namespace, policy.Name)
	}
	sel := policy.Spec.PodSelector.MatchLabels
	if sel[securityv1alpha1.LabelRun] != "run-1" || sel[securityv1alpha1.LabelNetPhase] != securityv1alpha1.NetPhaseEvaluate {
		t.Fatalf("policy must select the run's evaluate-phase pods, got %v", sel)
	}
	if len(policy.Spec.PolicyTypes) != 1 || policy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("policy must be egress-only")
	}
	if len(policy.Spec.Egress) != 3 {
		t.Fatalf("expected DNS + apiserver + netbird rules, got %d", len(policy.Spec.Egress))
	}

	// Apiserver rule carries the resolved endpoint /32.
	var apiRule *networkingv1.NetworkPolicyEgressRule
	for i := range policy.Spec.Egress {
		for _, peer := range policy.Spec.Egress[i].To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "10.66.50.194/32" {
				r := policy.Spec.Egress[i]
				apiRule = &r
			}
		}
	}
	if apiRule == nil {
		t.Fatal("apiserver endpoint /32 missing from egress rules")
	}

	// NetBird rule carries the WireGuard + control-plane ports.
	var foundWG, foundTURN, foundRange bool
	for i := range policy.Spec.Egress {
		for _, port := range policy.Spec.Egress[i].Ports {
			if port.Port == nil {
				continue
			}
			switch port.Port.IntValue() {
			case 51820:
				foundWG = true
			case 3478:
				foundTURN = true
			case 49152:
				if port.EndPort != nil && *port.EndPort == 65535 {
					foundRange = true
				}
			}
		}
	}
	if !foundWG || !foundTURN || !foundRange {
		t.Fatalf("netbird data-plane ports incomplete: wg=%v turn=%v relayRange=%v", foundWG, foundTURN, foundRange)
	}
}

func TestImageConfigEndpointDerivation(t *testing.T) {
	// Mesh mode: endpoints become the NetBird peer DNS names.
	t.Setenv("MESH_ENFORCE", "true")
	t.Setenv("NETBIRD_DNS_DOMAIN", "mesh.example.internal")
	os.Setenv("VIGIL_URL", "")
	os.Setenv("OCCLUDRA_BASE_URL", "")
	images := ImageConfigFromEnv()
	if images.VigilURL != "http://vigil.mesh.example.internal:5000/analyze/prompt" {
		t.Errorf("mesh-mode VIGIL_URL = %q", images.VigilURL)
	}
	if images.OccludraBaseURL != "http://occludra.mesh.example.internal:8080/v1" {
		t.Errorf("mesh-mode OCCLUDRA_BASE_URL = %q", images.OccludraBaseURL)
	}

	// Legacy mode: cluster-local services.
	t.Setenv("MESH_ENFORCE", "false")
	images = ImageConfigFromEnv()
	if images.VigilURL != vigilServiceLocal {
		t.Errorf("legacy-mode VIGIL_URL = %q", images.VigilURL)
	}
	if images.OccludraBaseURL != occludraServiceLocal {
		t.Errorf("legacy-mode OCCLUDRA_BASE_URL = %q", images.OccludraBaseURL)
	}

	// Explicit settings always win.
	os.Setenv("VIGIL_URL", "http://custom-vigil:9999/analyze")
	images = ImageConfigFromEnv()
	if images.VigilURL != "http://custom-vigil:9999/analyze" {
		t.Errorf("explicit VIGIL_URL overridden: %q", images.VigilURL)
	}
}

func TestBuildEvaluateNetworkPolicyLegacyMode(t *testing.T) {
	images := meshImages()
	images.MeshEnforce = false
	run := testRun()
	policy := buildEvaluateNetworkPolicy(run, images, []string{"172.21.0.2/32"})

	// Legacy: DNS + apiserver + gateways + public 443 — no netbird rule.
	if len(policy.Spec.Egress) != 4 {
		t.Fatalf("legacy policy must have 4 egress rules, got %d", len(policy.Spec.Egress))
	}
	var foundGateways, foundPublic443, foundNetbird bool
	for i := range policy.Spec.Egress {
		rule := &policy.Spec.Egress[i]
		for _, port := range rule.Ports {
			if port.Port != nil && port.Port.IntValue() == 5000 && len(rule.To) == 1 && rule.To[0].NamespaceSelector != nil {
				foundGateways = true
			}
			if port.Port != nil && port.Port.IntValue() == 443 && len(rule.To) == 1 && rule.To[0].IPBlock != nil && rule.To[0].IPBlock.CIDR == "0.0.0.0/0" {
				foundPublic443 = true
			}
			if port.Port != nil && port.Port.IntValue() == 51820 {
				foundNetbird = true
			}
		}
	}
	if !foundGateways || !foundPublic443 {
		t.Fatalf("legacy policy missing gateways/public-443 rules: gw=%v pub=%v", foundGateways, foundPublic443)
	}
	if foundNetbird {
		t.Fatal("legacy policy must not contain netbird rules")
	}
}

func TestInitContainersDoneWithNativeSidecar(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{Name: "cloner"},
				{Name: containerNetBird, RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways)},
			},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}},
				{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			},
		},
	}
	if !initContainersDone(pod) {
		t.Fatal("running native sidecar must count as init-done")
	}
	// A still-running regular init container blocks.
	pod.Status.InitContainerStatuses[0] = corev1.ContainerStatus{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	if initContainersDone(pod) {
		t.Fatal("running regular init container must block")
	}
}

// ---- security-gateway tuning knobs + RuntimeClass wiring ----

// evaluatorContainer returns the evaluator container of a built Job.
func evaluatorContainer(t *testing.T, job *batchv1.Job) *corev1.Container {
	t.Helper()
	for i := range job.Spec.Template.Spec.Containers {
		if job.Spec.Template.Spec.Containers[i].Name == containerEvaluator {
			return &job.Spec.Template.Spec.Containers[i]
		}
	}
	t.Fatal("evaluator container missing")
	return nil
}

// findEnv returns the named env var's value and whether it is present at all
// (unlike envValue it tolerates absence, for "must be omitted" assertions).
func findEnv(container corev1.Container, name string) (string, bool) {
	for _, env := range container.Env {
		if env.Name == name {
			return env.Value, true
		}
	}
	return "", false
}

func TestBuildJobInjectsSecurityGatewayKnobs(t *testing.T) {
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}

	cases := []struct {
		name    string
		apply   func(*ImageConfig)
		envName string
		want    string
	}{
		{"vigil enabled flag", func(c *ImageConfig) { c.VigilEnabled = "0" }, "VIGIL_ENABLED", "0"},
		{"vigil enforce mode", func(c *ImageConfig) { c.VigilEnforce = "monitor" }, "VIGIL_ENFORCE", "monitor"},
		{"vigil timeout", func(c *ImageConfig) { c.VigilTimeoutMs = "2500" }, "VIGIL_TIMEOUT_MS", "2500"},
		{"vigil max payload", func(c *ImageConfig) { c.VigilMaxPayloadBytes = "4096" }, "VIGIL_MAX_PAYLOAD_BYTES", "4096"},
		{"occludra enabled flag", func(c *ImageConfig) { c.OccludraEnabled = "false" }, "OCCLUDRA_ENABLED", "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			images := meshImages()
			tc.apply(&images)
			r := &MCPEvaluationRunReconciler{Images: images}
			evaluator := evaluatorContainer(t, r.buildJob(run, server))
			got, ok := findEnv(*evaluator, tc.envName)
			if !ok {
				t.Fatalf("%s must be injected into the evaluator env when the operator env var is set", tc.envName)
			}
			if got != tc.want {
				t.Fatalf("%s = %q, want %q (pass-through verbatim)", tc.envName, got, tc.want)
			}
		})
	}
}

func TestBuildJobOmitsUnsetSecurityGatewayKnobs(t *testing.T) {
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}

	r := &MCPEvaluationRunReconciler{Images: meshImages()}
	evaluator := evaluatorContainer(t, r.buildJob(run, server))
	// Unset knobs must be absent entirely so the evaluator's built-in
	// defaults (enabled / strict / 10000ms / 65536B / enabled) apply.
	for _, envName := range []string{
		"VIGIL_ENABLED", "VIGIL_ENFORCE", "VIGIL_TIMEOUT_MS", "VIGIL_MAX_PAYLOAD_BYTES", "OCCLUDRA_ENABLED",
	} {
		if v, ok := findEnv(*evaluator, envName); ok {
			t.Errorf("%s must be absent when the operator env var is unset, got %q", envName, v)
		}
	}
}

func TestImageConfigSecurityGatewayKnobsFromEnv(t *testing.T) {
	// Unset: pass-throughs stay empty (runner defaults apply) and no
	// RuntimeClass is configured.
	for _, key := range []string{
		"VIGIL_ENABLED", "VIGIL_ENFORCE", "VIGIL_TIMEOUT_MS", "VIGIL_MAX_PAYLOAD_BYTES",
		"OCCLUDRA_ENABLED", "RUNTIME_CLASS_NAME",
	} {
		os.Setenv(key, "")
	}
	images := ImageConfigFromEnv()
	if images.VigilEnabled != "" || images.VigilEnforce != "" || images.VigilTimeoutMs != "" ||
		images.VigilMaxPayloadBytes != "" || images.OccludraEnabled != "" {
		t.Errorf("unset gateway knobs must stay empty, got %+v", images)
	}
	if images.RuntimeClassName != "" {
		t.Errorf("unset RUNTIME_CLASS_NAME must stay empty, got %q", images.RuntimeClassName)
	}

	// Set: captured verbatim — the runner does its own validation.
	t.Setenv("VIGIL_ENABLED", "1")
	t.Setenv("VIGIL_ENFORCE", "monitor")
	t.Setenv("VIGIL_TIMEOUT_MS", "2500")
	t.Setenv("VIGIL_MAX_PAYLOAD_BYTES", "4096")
	t.Setenv("OCCLUDRA_ENABLED", "false")
	t.Setenv("RUNTIME_CLASS_NAME", "gvisor")
	images = ImageConfigFromEnv()
	if images.VigilEnabled != "1" {
		t.Errorf("VIGIL_ENABLED = %q, want \"1\"", images.VigilEnabled)
	}
	if images.VigilEnforce != "monitor" {
		t.Errorf("VIGIL_ENFORCE = %q, want \"monitor\"", images.VigilEnforce)
	}
	if images.VigilTimeoutMs != "2500" {
		t.Errorf("VIGIL_TIMEOUT_MS = %q, want \"2500\"", images.VigilTimeoutMs)
	}
	if images.VigilMaxPayloadBytes != "4096" {
		t.Errorf("VIGIL_MAX_PAYLOAD_BYTES = %q, want \"4096\"", images.VigilMaxPayloadBytes)
	}
	if images.OccludraEnabled != "false" {
		t.Errorf("OCCLUDRA_ENABLED = %q, want \"false\"", images.OccludraEnabled)
	}
	if images.RuntimeClassName != "gvisor" {
		t.Errorf("RUNTIME_CLASS_NAME = %q, want \"gvisor\"", images.RuntimeClassName)
	}
}

func TestBuildJobRuntimeClassName(t *testing.T) {
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}

	// Set: the pod template pins the RuntimeClass (e.g. gVisor — the README's
	// loopback-reachability mitigation).
	images := meshImages()
	images.RuntimeClassName = "gvisor"
	r := &MCPEvaluationRunReconciler{Images: images}
	job := r.buildJob(run, server)
	if got := job.Spec.Template.Spec.RuntimeClassName; got == nil || *got != "gvisor" {
		t.Fatalf("pod template RuntimeClassName = %v, want gvisor", got)
	}

	// Unset: no runtimeClassName on the pod template.
	job = (&MCPEvaluationRunReconciler{Images: meshImages()}).buildJob(run, server)
	if job.Spec.Template.Spec.RuntimeClassName != nil {
		t.Fatalf("pod template RuntimeClassName must stay nil when unset, got %q", *job.Spec.Template.Spec.RuntimeClassName)
	}
}

func TestBuildJobVigilGPUURLOnlyWhenConfigured(t *testing.T) {
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "filesystem-mcp", Namespace: "mcp-evals"},
		Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
	}
	build := func(images ImageConfig) *corev1.Container {
		return evaluatorContainer(t, (&MCPEvaluationRunReconciler{Images: images}).buildJob(testRun(), server))
	}

	if _, ok := findEnv(*build(meshImages()), "VIGIL_GPU_URL"); ok {
		t.Error("VIGIL_GPU_URL must be absent unless configured (GPU scanner is opt-in)")
	}
	images := meshImages()
	images.VigilGPUURL = "http://vigil-gpu-service.security-gateways.svc.cluster.local:5000/analyze/prompt"
	evaluator := build(images)
	if got, ok := findEnv(*evaluator, "VIGIL_GPU_URL"); !ok || got != images.VigilGPUURL {
		t.Errorf("VIGIL_GPU_URL = %q (present=%v), want %q", got, ok, images.VigilGPUURL)
	}
	// The CPU endpoint stays the fallback, unchanged.
	if got, _ := findEnv(*evaluator, "VIGIL_URL"); got != images.VigilURL {
		t.Errorf("VIGIL_URL changed to %q", got)
	}
}

// The custom git CA (key ca.crt of credentialsSecretRef) is PEM text. git's
// GIT_SSL_CAINFO must be a file path, so the operator hands the PEM over as
// GIT_CA_PEM and the cloner writes it to a file itself.
func TestBuildJobPassesGitCAAsPEMNotAsCAInfoPath(t *testing.T) {
	run := testRun()
	server := &securityv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "fixture", Namespace: "mcp-evals"},
		Spec: securityv1alpha1.MCPServerSpec{
			RepositoryUrl:        "https://git.internal/x/y",
			Transport:            "stdio",
			CredentialsSecretRef: "git-creds",
		},
	}
	job := (&MCPEvaluationRunReconciler{Images: meshImages()}).buildJob(run, server)
	var cloner *corev1.Container
	for i := range job.Spec.Template.Spec.InitContainers {
		if job.Spec.Template.Spec.InitContainers[i].Name == containerCloner {
			cloner = &job.Spec.Template.Spec.InitContainers[i]
		}
	}
	if cloner == nil {
		t.Fatal("no cloner init container")
	}
	var pem *corev1.EnvVar
	for i := range cloner.Env {
		switch cloner.Env[i].Name {
		case "GIT_SSL_CAINFO":
			t.Fatalf("GIT_SSL_CAINFO must not carry the secret's PEM content (git treats it as a path)")
		case "GIT_CA_PEM":
			pem = &cloner.Env[i]
		}
	}
	if pem == nil || pem.ValueFrom == nil || pem.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("GIT_CA_PEM missing or not sourced from a secret: %+v", pem)
	}
	ref := pem.ValueFrom.SecretKeyRef
	if ref.Name != "git-creds" || ref.Key != "ca.crt" || ref.Optional == nil || !*ref.Optional {
		t.Fatalf("GIT_CA_PEM ref = %+v, want optional git-creds/ca.crt", ref)
	}
}

// Untrusted code (the cloner runs repository build steps, the target is the
// server under test) must never mount the evaluator's HOME.
func TestBuildJobUntrustedContainersDoNotShareTheEvaluatorHome(t *testing.T) {
	for _, images := range []ImageConfig{meshImages(), {}} {
		job := (&MCPEvaluationRunReconciler{Images: images}).buildJob(testRun(), &securityv1alpha1.MCPServer{
			ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "mcp-evals"},
			Spec:       securityv1alpha1.MCPServerSpec{RepositoryUrl: "https://github.com/x/y", Transport: "stdio"},
		})
		spec := job.Spec.Template.Spec
		mounts := map[string]map[string]string{} // container -> mountPath -> volume
		for _, c := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
			mounts[c.Name] = map[string]string{}
			for _, m := range c.VolumeMounts {
				mounts[c.Name][m.MountPath] = m.Name
			}
		}
		home := mounts[containerEvaluator][mountTmp]
		if home == "" {
			t.Fatal("evaluator has no /tmp")
		}
		for _, untrusted := range []string{containerCloner, containerTarget} {
			if mounts[untrusted] == nil {
				t.Fatalf("no %s container", untrusted)
			}
			if mounts[untrusted][mountTmp] == "" {
				t.Errorf("%s has no /tmp of its own", untrusted)
			}
			for path, vol := range mounts[untrusted] {
				if vol == home {
					t.Errorf("%s mounts the evaluator's HOME volume %q at %s", untrusted, vol, path)
				}
			}
		}
		if mounts[containerCloner][mountTmp] == mounts[containerTarget][mountTmp] {
			t.Error("cloner and target share a /tmp")
		}
		declared := map[string]bool{}
		for _, v := range spec.Volumes {
			declared[v.Name] = true
		}
		for c, ms := range mounts {
			for path, vol := range ms {
				if !declared[vol] {
					t.Errorf("%s mounts undeclared volume %q at %s", c, vol, path)
				}
			}
		}
	}
}
