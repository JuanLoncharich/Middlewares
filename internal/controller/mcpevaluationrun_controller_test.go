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
		VigilURL:             "http://vigil-service.security-gateways.svc.cluster.local:5000/analyze",
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
	if images.VigilURL != "http://vigil.mesh.example.internal:5000/analyze" {
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
