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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

const (
	// ConditionJobCreated tracks whether the evaluation Job exists.
	ConditionJobCreated = "JobCreated"
	// ConditionSucceeded reflects the terminal outcome of the run.
	ConditionSucceeded = "Succeeded"
	// ConditionRetried records that a transient Job failure was recovered.
	ConditionRetried = "Retried"

	containerCloner    = "cloner"
	containerTarget    = "target"
	containerEvaluator = "evaluator"
	containerNetBird   = "netbird"

	volumeWorkspace   = "workspace"
	volumeIPC         = "ipc"
	volumeTmp         = "tmp"
	volumeOutput      = "output"
	volumeSAToken     = "sa-token"
	volumeNetBirdStat = "netbird-state"

	mountWorkspace   = "/workspace"
	mountIPC         = "/ipc"
	mountTmp         = "/tmp"
	mountOutput      = "/output"
	mountSAToken     = "/var/run/secrets/kubernetes.io/serviceaccount"
	mountNetBirdStat = "/var/lib/netbird"

	evaluatorUID int64 = 10001
	targetUID    int64 = 10002

	jobTTLSeconds int32 = 600
	openCodePort        = "4096"

	// meshBridgePortDefault is the local HTTP-proxy bridge port the evaluator
	// exposes for the OpenCode child process (see runner/src/meshhttp.ts).
	meshBridgePortDefault int32 = 18080

	runRequeueInterval = 15 * time.Second

	// maxJobRetries bounds how many times a run's Job is recreated after a
	// transient infrastructure failure (eviction, node loss, image pull
	// flake). Evaluation-verdict failures are never retried.
	maxJobRetries int32 = 2

	// stuckPendingAfter is how long a pod may sit Pending without any
	// container starting before the controller treats it as an infrastructure
	// fault and retries the Job instead of burning the whole deadline.
	stuckPendingAfter = 5 * time.Minute

	// runReconcileWorkers bounds how many run reconciles execute in parallel
	// (one run's reconcile does several API-server round-trips; the default
	// single worker would serialize the whole platform under load).
	runReconcileWorkers = 8
)

// ImageConfig carries the images, secrets and security-layer wiring injected
// into evaluation Jobs.
type ImageConfig struct {
	ClonerImage          string
	TargetImage          string
	EvaluatorImage       string
	RunnerServiceAccount string
	LLMSecretName        string
	LLMSecretKey         string

	// MeshEnforce enables the NetBird zero-trust wiring: a userspace netbird
	// sidecar per evaluation pod, mesh env vars on the evaluator, and a
	// per-run NetworkPolicy whose only egress is DNS, the API server and the
	// NetBird control/data planes. MESH_ENFORCE=false restores the legacy
	// direct-to-provider mode (no sidecar, no per-run policy).
	MeshEnforce          bool
	NetBirdImage         string
	NetBirdManagementURL string
	NetBirdSecretName    string
	NetBirdSecretKey     string
	// NetBirdEgressCIDRs are the destinations the per-run policy allows for
	// NetBird control plane (management/signal/relay) and WireGuard data
	// plane traffic.
	NetBirdEgressCIDRs []string
	// MeshProxyURL is passed to the evaluator as MESH_PROXY (the netbird
	// userspace SOCKS5 endpoint inside the pod).
	MeshProxyURL   string
	MeshBridgePort int32
	// VigilURL / OccludraBaseURL are the security-layer endpoints the
	// evaluator scans against and points its LLM providers at. When not set
	// explicitly they are DERIVED from the mode: mesh peer DNS names under
	// NetBirdDNSDomain in mesh mode, cluster-local service names otherwise.
	VigilURL        string
	OccludraBaseURL string
	// NetBirdDNSDomain is the DNS domain the NetBird management server hands
	// out for peer names (vigil / occludra — pinned via NETBIRD_HOSTNAME).
	NetBirdDNSDomain string
}

// Security-layer endpoint defaults. The cluster-local service names are the
// only reachable path with MESH_ENFORCE=false (and for operator smoke tests);
// in mesh mode the per-run NetworkPolicy BLOCKS that path and the NetBird
// SOCKS proxy cannot dial ClusterIPs, so the defaults become the mesh peer
// DNS names — which is why they are derived, not hardcoded.
const (
	vigilServiceLocal    = "http://vigil-service.security-gateways.svc.cluster.local:5000/analyze"
	occludraServiceLocal = "http://occludra-service.security-gateways.svc.cluster.local:8080/v1"
	defaultNetBirdDomain = "netbird.selfhosted"
)

// FromEnv reads ImageConfig from environment variables with production defaults.
func ImageConfigFromEnv() ImageConfig {
	meshEnforce := envFlag("MESH_ENFORCE", true)
	dnsDomain := envOr("NETBIRD_DNS_DOMAIN", defaultNetBirdDomain)

	// Explicit settings always win; otherwise derive from the mode.
	vigilURL := os.Getenv("VIGIL_URL")
	if strings.TrimSpace(vigilURL) == "" {
		if meshEnforce {
			vigilURL = "http://vigil." + dnsDomain + ":5000/analyze"
		} else {
			vigilURL = vigilServiceLocal
		}
	}
	occludraURL := os.Getenv("OCCLUDRA_BASE_URL")
	if strings.TrimSpace(occludraURL) == "" {
		if meshEnforce {
			occludraURL = "http://occludra." + dnsDomain + ":8080/v1"
		} else {
			occludraURL = occludraServiceLocal
		}
	}

	return ImageConfig{
		ClonerImage:          envOr("CLONER_IMAGE", "ghcr.io/security-eval/mcp-cloner:latest"),
		TargetImage:          envOr("TARGET_IMAGE", "ghcr.io/security-eval/mcp-target-sandbox:latest"),
		EvaluatorImage:       envOr("EVALUATOR_IMAGE", "ghcr.io/security-eval/mcp-evaluator:latest"),
		RunnerServiceAccount: envOr("RUNNER_SERVICE_ACCOUNT", "mcp-eval-runner"),
		LLMSecretName:        envOr("LLM_SECRET_NAME", "llm-provider-credentials"),
		LLMSecretKey:         envOr("LLM_SECRET_KEY", "ANTHROPIC_API_KEY"),

		MeshEnforce:          meshEnforce,
		NetBirdImage:         envOr("NETBIRD_IMAGE", "netbirdio/netbird:latest"),
		NetBirdManagementURL: envOr("NETBIRD_MANAGEMENT_URL", "https://netbird.example.com:443"),
		NetBirdSecretName:    envOr("NETBIRD_SECRET_NAME", "netbird-auth"),
		NetBirdSecretKey:     envOr("NETBIRD_SECRET_KEY", "setup-key"),
		NetBirdEgressCIDRs:   envCIDRs("NETBIRD_EGRESS_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),
		MeshProxyURL:         envOr("MESH_PROXY_URL", "socks5://127.0.0.1:1080"),
		MeshBridgePort:       envInt32("MESH_BRIDGE_PORT", meshBridgePortDefault),
		VigilURL:             vigilURL,
		OccludraBaseURL:      occludraURL,
		NetBirdDNSDomain:     dnsDomain,
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envFlag parses a boolean env var; unparsable values keep the default.
func envFlag(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt32(key string, def int32) int32 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	var v int32
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil || v <= 0 || v > 65535 {
		return def
	}
	return v
}

// envCIDRs parses a comma-separated CIDR list; invalid entries are dropped
// (the manager startup log prints the effective list).
func envCIDRs(key, def string) []string {
	raw := envOr(key, def)
	var out []string
	for _, part := range strings.Split(raw, ",") {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		out = append(out, cidr)
	}
	return out
}

// terminationMessage is the JSON contract the evaluator writes to /dev/termination-log.
type terminationMessage struct {
	Phase        string `json:"phase"`
	FinalScore   int32  `json:"finalScore"`
	RiskCategory string `json:"riskCategory"`
	Message      string `json:"message"`
}

// MCPEvaluationRunReconciler reconciles a MCPEvaluationRun object.
type MCPEvaluationRunReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Images   ImageConfig
}

// +kubebuilder:rbac:groups=security.eval.io,resources=mcpevaluationruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpevaluationruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpevaluationruns/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.eval.io,resources=opencodeagents,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives an MCPEvaluationRun through Pending → Cloning → Running → Evaluating → Completed|Failed.
func (r *MCPEvaluationRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	run := &securityv1alpha1.MCPEvaluationRun{}
	if err := r.Get(ctx, req.NamespacedName, run); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MCPEvaluationRun: %w", err)
	}

	// Deletion: remove the Job then drop the finalizer.
	if !run.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(run, securityv1alpha1.RunFinalizer) {
			if err := r.deleteJob(ctx, run); err != nil {
				return ctrl.Result{}, err
			}
			patched := run.DeepCopy()
			controllerutil.RemoveFinalizer(patched, securityv1alpha1.RunFinalizer)
			if err := r.Patch(ctx, patched, client.MergeFrom(run)); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(run, securityv1alpha1.RunFinalizer) {
		patched := run.DeepCopy()
		controllerutil.AddFinalizer(patched, securityv1alpha1.RunFinalizer)
		if err := r.Patch(ctx, patched, client.MergeFrom(run)); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		run = patched
	}

	// Terminal runs need no further work; TTL on the Job handles cleanup.
	if run.Status.Phase.IsTerminal() {
		return ctrl.Result{}, nil
	}

	original := run.DeepCopy()

	if run.Status.Phase == "" {
		run.Status.Phase = securityv1alpha1.PhasePending
		run.Status.StartTime = &metav1.Time{Time: time.Now()}
		run.Status.Message = "run accepted"
	}

	// Resolve the target server.
	server := &securityv1alpha1.MCPServer{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.ServerRef}, server); err != nil {
		if apierrors.IsNotFound(err) {
			return r.fail(ctx, run, original, "ServerNotFound",
				fmt.Sprintf("MCPServer %q not found in namespace %s", run.Spec.ServerRef, run.Namespace))
		}
		return ctrl.Result{}, fmt.Errorf("fetching MCPServer %s: %w", run.Spec.ServerRef, err)
	}

	// Resolve every agent.
	var missing []string
	for _, name := range run.Spec.Agents {
		agent := &securityv1alpha1.OpenCodeAgent{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: name}, agent); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, name)
				continue
			}
			return ctrl.Result{}, fmt.Errorf("fetching OpenCodeAgent %s: %w", name, err)
		}
	}
	if len(missing) > 0 {
		return r.fail(ctx, run, original, "AgentNotFound",
			fmt.Sprintf("OpenCodeAgents not found: %s", strings.Join(missing, ", ")))
	}

	// Ensure the Job exists.
	job := &batchv1.Job{}
	jobName := jobNameFor(run)
	err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: jobName}, job)
	switch {
	case apierrors.IsNotFound(err):
		// Mesh mode: the per-run egress policy exists BEFORE the pod so the
		// net-phase flip never leaves an evaluate-phase pod without coverage.
		if err := r.ensureEvaluateNetworkPolicy(ctx, run); err != nil {
			return ctrl.Result{}, err
		}
		job = r.buildJob(run, server)
		if err := controllerutil.SetControllerReference(run, job, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("setting owner reference on Job: %w", err)
		}
		if err := r.Create(ctx, job); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			if isTransientKubeError(err) {
				// A transient API-server/etcd hiccup must not fail the run;
				// controller-runtime retries with exponential backoff.
				return ctrl.Result{}, fmt.Errorf("creating Job %s (transient, will retry): %w", job.Name, err)
			}
			return r.fail(ctx, run, original, "JobCreateFailed", fmt.Sprintf("creating Job: %v", err))
		}
		run.Status.JobName = job.Name
		meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
			Type:               ConditionJobCreated,
			Status:             metav1.ConditionTrue,
			Reason:             "JobCreated",
			Message:            fmt.Sprintf("Job %s created", job.Name),
			ObservedGeneration: run.Generation,
		})
		r.Recorder.Eventf(run, corev1.EventTypeNormal, "JobCreated", "created Job %s", job.Name)
		log.Info("created evaluation job", "job", job.Name)
		if err := r.patchStatus(ctx, run, original); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: runRequeueInterval}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("fetching Job %s: %w", jobName, err)
	}
	if job.DeletionTimestamp != nil {
		// A transient-failure retry deleted the old Job; wait for it to go
		// away so the NotFound branch recreates a clean one.
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	run.Status.JobName = job.Name

	// Self-heal: recreate the mesh egress policy if someone deleted it.
	if err := r.ensureEvaluateNetworkPolicy(ctx, run); err != nil {
		return ctrl.Result{}, err
	}

	// Locate the pod backing the job.
	pod, err := r.findPod(ctx, run)
	if err != nil {
		return ctrl.Result{}, err
	}

	// A pod that sits Pending without any container starting is an
	// infrastructure fault (image pull, scheduling), not an evaluation
	// outcome — retry it instead of burning the whole deadline.
	if pod != nil && pod.Status.Phase == corev1.PodPending && stuckPending(pod, time.Now()) {
		detail := fmt.Sprintf("pod %s stuck Pending without starting", pod.Name)
		if reasons := podWaitingReasons(pod); len(reasons) > 0 {
			detail = fmt.Sprintf("pod %s stuck Pending: %s", pod.Name, strings.Join(reasons, ","))
		}
		return r.retryJob(ctx, run, original, detail)
	}

	// Terminal Job conditions.
	if cond := jobCondition(job, batchv1.JobFailed); cond != nil {
		msg := fmt.Sprintf("Job failed: %s", cond.Reason)
		if cond.Message != "" {
			msg = fmt.Sprintf("%s: %s", msg, cond.Message)
		}
		if detail := containerFailureDetail(pod); detail != "" {
			msg = fmt.Sprintf("%s (%s)", msg, detail)
		}
		// The runner may already have recorded a richer message via its own status patch.
		if tm := parseTerminationMessage(pod); tm != nil && tm.Message != "" {
			msg = fmt.Sprintf("%s; evaluator: %s", msg, tm.Message)
		}
		if reason, transient := infraTransientFailure(job, pod); transient {
			return r.retryJob(ctx, run, original, reason)
		}
		return r.fail(ctx, run, original, cond.Reason, msg)
	}
	if cond := jobCondition(job, batchv1.JobComplete); cond != nil {
		return r.complete(ctx, run, original, pod)
	}

	// Derive an in-flight phase from the pod, never downgrading what the runner set.
	derived := securityv1alpha1.PhasePending
	if pod != nil {
		derived = derivePhaseFromPod(pod)
		if derived.Rank() >= securityv1alpha1.PhaseRunning.Rank() {
			if err := r.ensureEvaluateNetPhase(ctx, pod); err != nil {
				return ctrl.Result{}, err
			}
		}
		// The evaluator container may terminate before the Job controller flips a condition.
		if cs := containerStatus(pod, containerEvaluator); cs != nil && cs.State.Terminated != nil {
			if cs.State.Terminated.ExitCode == 0 {
				return r.complete(ctx, run, original, pod)
			}
			msg := fmt.Sprintf("evaluator container exited with code %d (%s)",
				cs.State.Terminated.ExitCode, cs.State.Terminated.Reason)
			if tm := parseTerminationMessage(pod); tm != nil && tm.Message != "" {
				msg = fmt.Sprintf("%s: %s", msg, tm.Message)
			}
			// An OOM kill is a resource fault, not an evaluation verdict —
			// give the run its bounded recovery attempts.
			if cs.State.Terminated.Reason == "OOMKilled" {
				return r.retryJob(ctx, run, original, "evaluator container OOMKilled")
			}
			return r.fail(ctx, run, original, "EvaluatorFailed", msg)
		}
	}
	if run.Status.CurrentAgent != "" && derived.Rank() < securityv1alpha1.PhaseEvaluating.Rank() {
		derived = securityv1alpha1.PhaseEvaluating
	}
	if derived.Rank() > run.Status.Phase.Rank() {
		log.Info("phase transition", "from", run.Status.Phase, "to", derived)
		r.Recorder.Eventf(run, corev1.EventTypeNormal, "PhaseChanged", "%s -> %s", run.Status.Phase, derived)
		run.Status.Phase = derived
		run.Status.Message = phaseMessage(derived, pod)
	}

	if err := r.patchStatus(ctx, run, original); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: runRequeueInterval}, nil
}

// complete transitions the run to Completed (or Failed if the evaluator reported failure).
func (r *MCPEvaluationRunReconciler) complete(ctx context.Context, run, original *securityv1alpha1.MCPEvaluationRun, pod *corev1.Pod) (ctrl.Result, error) {
	tm := parseTerminationMessage(pod)
	if tm != nil && strings.EqualFold(tm.Phase, string(securityv1alpha1.PhaseFailed)) {
		msg := tm.Message
		if msg == "" {
			msg = "evaluator reported failure"
		}
		return r.fail(ctx, run, original, "EvaluatorReportedFailure", msg)
	}

	// A terminal completion with no termination message, no score and no
	// recorded agent results is not a success — mark it failed loudly instead
	// of silently completing with score 0.
	if tm == nil && run.Status.FinalScore == 0 && run.Status.Scoring == nil && len(run.Status.AgentResults) == 0 {
		return r.fail(ctx, run, original, "EvaluatorResultsMissing",
			"evaluator terminated without a termination message and without recording any results")
	}

	run.Status.Phase = securityv1alpha1.PhaseCompleted
	run.Status.CurrentAgent = ""
	run.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	if tm != nil {
		if tm.FinalScore != 0 || run.Status.FinalScore == 0 {
			run.Status.FinalScore = tm.FinalScore
		}
		if tm.RiskCategory != "" {
			if run.Status.Scoring == nil {
				run.Status.Scoring = &securityv1alpha1.ScoringBlock{}
			}
			if run.Status.Scoring.RiskCategory == "" {
				run.Status.Scoring.RiskCategory = securityv1alpha1.RiskCategory(tm.RiskCategory)
			}
			if run.Status.Scoring.SafetyScore == 0 {
				run.Status.Scoring.SafetyScore = tm.FinalScore
			}
		}
		if tm.Message != "" {
			run.Status.Message = tm.Message
		} else {
			run.Status.Message = "evaluation completed"
		}
	} else {
		// Results were patched by the evaluator before it lost its
		// termination message; complete from what is recorded.
		run.Status.Message = "evaluation completed from recorded agent results (evaluator termination message missing)"
	}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type:               ConditionSucceeded,
		Status:             metav1.ConditionTrue,
		Reason:             "Completed",
		Message:            run.Status.Message,
		ObservedGeneration: run.Generation,
	})
	r.Recorder.Eventf(run, corev1.EventTypeNormal, "Completed", "evaluation completed with score %d", run.Status.FinalScore)
	r.deleteEvaluateNetworkPolicy(ctx, run)
	if err := r.patchStatus(ctx, run, original); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// fail transitions the run to Failed with the given reason and message.
func (r *MCPEvaluationRunReconciler) fail(ctx context.Context, run, original *securityv1alpha1.MCPEvaluationRun, reason, msg string) (ctrl.Result, error) {
	run.Status.Phase = securityv1alpha1.PhaseFailed
	run.Status.CurrentAgent = ""
	run.Status.Message = msg
	run.Status.CompletionTime = &metav1.Time{Time: time.Now()}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type:               ConditionSucceeded,
		Status:             metav1.ConditionFalse,
		Reason:             sanitizeReason(reason),
		Message:            msg,
		ObservedGeneration: run.Generation,
	})
	r.Recorder.Event(run, corev1.EventTypeWarning, sanitizeReason(reason), msg)
	r.deleteEvaluateNetworkPolicy(ctx, run)
	if err := r.patchStatus(ctx, run, original); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// sanitizeReason makes an arbitrary string safe for a Condition reason (CamelCase, no spaces).
func sanitizeReason(reason string) string {
	var b strings.Builder
	for _, ch := range reason {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		}
	}
	if b.Len() == 0 {
		return "Failed"
	}
	return b.String()
}

// patchStatus writes the status subresource.
func (r *MCPEvaluationRunReconciler) patchStatus(ctx context.Context, run, original *securityv1alpha1.MCPEvaluationRun) error {
	if err := r.Status().Patch(ctx, run, client.MergeFrom(original)); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("patching MCPEvaluationRun status: %w", err)
	}
	return nil
}

// deleteJob removes the Job owned by the run with background propagation.
func (r *MCPEvaluationRunReconciler) deleteJob(ctx context.Context, run *securityv1alpha1.MCPEvaluationRun) error {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: jobNameFor(run), Namespace: run.Namespace},
	}
	if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting Job %s: %w", job.Name, err)
	}
	return nil
}

// retryJob recreates the run's Job after a transient infrastructure failure
// (eviction, node loss, image pull flake, OOM kill). Bounded by maxJobRetries;
// beyond that the run fails permanently. Evaluation-verdict failures never
// reach this path.
func (r *MCPEvaluationRunReconciler) retryJob(ctx context.Context, run, original *securityv1alpha1.MCPEvaluationRun, detail string) (ctrl.Result, error) {
	if run.Status.Retries >= maxJobRetries {
		return r.fail(ctx, run, original, "JobRetriesExhausted",
			fmt.Sprintf("transient failure repeated after %d retries, giving up: %s", run.Status.Retries, detail))
	}
	run.Status.Retries++
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type:               ConditionRetried,
		Status:             metav1.ConditionTrue,
		Reason:             "TransientJobFailure",
		Message:            truncate(fmt.Sprintf("%s; recreating Job (retry %d/%d)", detail, run.Status.Retries, maxJobRetries), 512),
		ObservedGeneration: run.Generation,
	})
	r.Recorder.Eventf(run, corev1.EventTypeWarning, "JobRetried",
		"%s; recreating Job (retry %d/%d)", detail, run.Status.Retries, maxJobRetries)
	log := logf.FromContext(ctx)
	log.Info("retrying run after transient infrastructure failure", "run", run.Name, "detail", detail, "retry", run.Status.Retries)
	if err := r.deleteJob(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.patchStatus(ctx, run, original); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
}

// isTransientKubeError reports whether an API-server error is worth a
// controller-runtime backoff-and-retry instead of a terminal run failure.
func isTransientKubeError(err error) bool {
	if apierrors.IsInternalError(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsTimeout(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// infraTransientFailure inspects a failed Job and its pod and reports whether
// the failure looks infrastructure-transient — evictions, node loss, pods that
// never started (image pull, scheduling), OOM kills — rather than a real
// evaluation outcome. Only such failures are eligible for a Job retry.
// A nil pod is treated as a real outcome (a deadline expiry whose pod is
// already gone), never as transient: the stuck-Pending detection covers the
// "pod never started" case while the pod still exists.
func infraTransientFailure(job *batchv1.Job, pod *corev1.Pod) (string, bool) {
	if pod == nil {
		return "", false
	}
	switch pod.Status.Reason {
	case "Evicted", "NodeLost":
		return fmt.Sprintf("pod %s: %s", pod.Name, pod.Status.Reason), true
	}
	if pod.Status.Phase == corev1.PodPending {
		// The pod never started any container: pull or scheduling trouble.
		if reasons := podWaitingReasons(pod); len(reasons) > 0 {
			return fmt.Sprintf("pod %s never started: %s", pod.Name, strings.Join(reasons, ",")), true
		}
		return fmt.Sprintf("pod %s never started", pod.Name), true
	}
	for _, cs := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		if t := cs.State.Terminated; t != nil && t.Reason == "OOMKilled" {
			return fmt.Sprintf("container %s OOMKilled", cs.Name), true
		}
	}
	return "", false
}

// podWaitingReasons collects the non-trivial container waiting reasons of a pod.
func podWaitingReasons(pod *corev1.Pod) []string {
	var reasons []string
	seen := map[string]bool{}
	all := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, cs := range all {
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "PodInitializing" && !seen[w.Reason] {
			seen[w.Reason] = true
			reasons = append(reasons, w.Reason)
		}
	}
	return reasons
}

// stuckPending reports whether a pod has been Pending without any container
// starting (running or terminated) for longer than stuckPendingAfter.
func stuckPending(pod *corev1.Pod, now time.Time) bool {
	if pod.CreationTimestamp.IsZero() || now.Sub(pod.CreationTimestamp.Time) < stuckPendingAfter {
		return false
	}
	all := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, cs := range all {
		if cs.State.Running != nil || cs.State.Terminated != nil {
			return false
		}
	}
	return true
}

// deleteEvaluateNetworkPolicy removes the per-run egress policy once the run
// reached a terminal phase. The Job lingers only for its TTL window with no
// pod running; the policy has no reason to outlive it. Owner-reference GC
// remains the backstop when the run object itself is deleted.
func (r *MCPEvaluationRunReconciler) deleteEvaluateNetworkPolicy(ctx context.Context, run *securityv1alpha1.MCPEvaluationRun) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: evaluateNetworkPolicyName(run), Namespace: run.Namespace},
	}
	if err := r.Delete(ctx, policy); err != nil && !apierrors.IsNotFound(err) {
		// Best-effort: GC will collect it with the run; keep terminating.
		logf.FromContext(ctx).Error(err, "deleting per-run egress NetworkPolicy", "policy", policy.Name)
	}
}

// findPod returns the newest pod labelled for the run, or nil.
func (r *MCPEvaluationRunReconciler) findPod(ctx context.Context, run *securityv1alpha1.MCPEvaluationRun) (*corev1.Pod, error) {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods,
		client.InNamespace(run.Namespace),
		client.MatchingLabels{securityv1alpha1.LabelRun: run.Name},
	); err != nil {
		return nil, fmt.Errorf("listing pods for run: %w", err)
	}
	var newest *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if newest == nil || p.CreationTimestamp.After(newest.CreationTimestamp.Time) {
			newest = p
		}
	}
	return newest, nil
}

// ensureEvaluateNetPhase flips the pod's net-phase label from clone to evaluate exactly once.
func (r *MCPEvaluationRunReconciler) ensureEvaluateNetPhase(ctx context.Context, pod *corev1.Pod) error {
	if pod.Labels[securityv1alpha1.LabelNetPhase] == securityv1alpha1.NetPhaseEvaluate {
		return nil
	}
	patched := pod.DeepCopy()
	if patched.Labels == nil {
		patched.Labels = map[string]string{}
	}
	patched.Labels[securityv1alpha1.LabelNetPhase] = securityv1alpha1.NetPhaseEvaluate
	if err := r.Patch(ctx, patched, client.MergeFrom(pod)); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("patching pod net-phase label: %w", err)
	}
	pod.Labels = patched.Labels
	logf.FromContext(ctx).Info("narrowed pod egress", "pod", pod.Name, "netPhase", securityv1alpha1.NetPhaseEvaluate)
	return nil
}

// derivePhaseFromPod maps pod/container state to a run phase.
func derivePhaseFromPod(pod *corev1.Pod) securityv1alpha1.RunPhase {
	if pod == nil {
		return securityv1alpha1.PhasePending
	}
	switch pod.Status.Phase {
	case corev1.PodPending:
		if len(pod.Status.InitContainerStatuses) > 0 && initContainersDone(pod) {
			return securityv1alpha1.PhaseRunning
		}
		if len(pod.Status.InitContainerStatuses) > 0 {
			return securityv1alpha1.PhaseCloning
		}
		return securityv1alpha1.PhasePending
	case corev1.PodRunning:
		if !initContainersDone(pod) {
			return securityv1alpha1.PhaseCloning
		}
		return securityv1alpha1.PhaseRunning
	case corev1.PodSucceeded, corev1.PodFailed:
		return securityv1alpha1.PhaseRunning
	default:
		return securityv1alpha1.PhasePending
	}
}

// initContainersDone reports whether every init container has terminated.
// Native sidecars (init containers with restartPolicy Always, e.g. the
// userspace netbird client) never terminate; they count as done once Running.
func initContainersDone(pod *corev1.Pod) bool {
	if len(pod.Spec.InitContainers) == 0 {
		return true
	}
	if len(pod.Status.InitContainerStatuses) < len(pod.Spec.InitContainers) {
		return false
	}
	for i := range pod.Status.InitContainerStatuses {
		cs := &pod.Status.InitContainerStatuses[i]
		if cs.State.Terminated != nil {
			continue
		}
		if cs.State.Running != nil && i < len(pod.Spec.InitContainers) && isNativeSidecar(&pod.Spec.InitContainers[i]) {
			continue
		}
		return false
	}
	return true
}

// isNativeSidecar reports whether the container is a native sidecar
// (init container with restartPolicy: Always).
func isNativeSidecar(c *corev1.Container) bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}

// containerStatus returns the status entry for the named container.
func containerStatus(pod *corev1.Pod, name string) *corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == name {
			return &pod.Status.ContainerStatuses[i]
		}
	}
	for i := range pod.Status.InitContainerStatuses {
		if pod.Status.InitContainerStatuses[i].Name == name {
			return &pod.Status.InitContainerStatuses[i]
		}
	}
	return nil
}

// parseTerminationMessage decodes the evaluator's termination log JSON, if present.
func parseTerminationMessage(pod *corev1.Pod) *terminationMessage {
	cs := containerStatus(pod, containerEvaluator)
	if cs == nil || cs.State.Terminated == nil {
		return nil
	}
	raw := strings.TrimSpace(cs.State.Terminated.Message)
	if raw == "" {
		return nil
	}
	tm := &terminationMessage{}
	if err := json.Unmarshal([]byte(raw), tm); err != nil {
		// Non-JSON termination messages are still useful as free text.
		return &terminationMessage{Message: truncate(raw, 1024)}
	}
	tm.Message = truncate(tm.Message, 1024)
	return tm
}

// containerFailureDetail summarizes any terminated-with-error container states.
func containerFailureDetail(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	var parts []string
	all := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	all = append(all, pod.Status.ContainerStatuses...)
	for _, cs := range all {
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			parts = append(parts, fmt.Sprintf("%s exit=%d reason=%s", cs.Name, t.ExitCode, t.Reason))
		}
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "PodInitializing" {
			parts = append(parts, fmt.Sprintf("%s waiting=%s", cs.Name, w.Reason))
		}
	}
	return truncate(strings.Join(parts, "; "), 512)
}

// phaseMessage renders a short status message for an in-flight phase.
func phaseMessage(phase securityv1alpha1.RunPhase, pod *corev1.Pod) string {
	podName := "<none>"
	if pod != nil {
		podName = pod.Name
	}
	switch phase {
	case securityv1alpha1.PhaseCloning:
		return fmt.Sprintf("cloning repository in pod %s", podName)
	case securityv1alpha1.PhaseRunning:
		return fmt.Sprintf("target and evaluator containers running in pod %s", podName)
	case securityv1alpha1.PhaseEvaluating:
		return fmt.Sprintf("evaluator driving agents in pod %s", podName)
	default:
		return fmt.Sprintf("waiting for pod %s", podName)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// jobCondition returns the True condition of the given type, if present.
func jobCondition(job *batchv1.Job, t batchv1.JobConditionType) *batchv1.JobCondition {
	for i := range job.Status.Conditions {
		c := &job.Status.Conditions[i]
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return c
		}
	}
	return nil
}

func jobNameFor(run *securityv1alpha1.MCPEvaluationRun) string {
	return run.Name + "-job"
}

// lockedSecurityContext returns the hard-invariant container security context.
// Every container shares the pod's fsGroup (evaluatorUID) as its primary group so
// the emptyDir volumes are usable, while the target runs under a distinct UID.
func lockedSecurityContext(uid int64) *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To(uid),
		RunAsGroup:               ptr.To(evaluatorUID),
		ReadOnlyRootFilesystem:   ptr.To(true),
		AllowPrivilegeEscalation: ptr.To(false),
		Privileged:               ptr.To(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// buildJob renders the locked-down multi-container evaluation Job.
func (r *MCPEvaluationRunReconciler) buildJob(run *securityv1alpha1.MCPEvaluationRun, server *securityv1alpha1.MCPServer) *batchv1.Job {
	labels := map[string]string{
		securityv1alpha1.LabelRun:      run.Name,
		securityv1alpha1.LabelServer:   server.Name,
		securityv1alpha1.LabelRole:     securityv1alpha1.RoleEvaluationPod,
		securityv1alpha1.LabelNetPhase: securityv1alpha1.NetPhaseClone,
	}

	timeout := run.Spec.TimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	transport := string(server.Spec.Transport)
	if transport == "" {
		transport = string(securityv1alpha1.TransportStdio)
	}
	targetPort := server.Spec.TargetPort
	if targetPort <= 0 {
		targetPort = 8080
	}
	ref := server.Spec.Ref
	if ref == "" {
		ref = "main"
	}

	volumes := []corev1.Volume{
		{
			Name: volumeWorkspace,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("2Gi")),
				},
			},
		},
		{
			// Disk-backed on purpose: Memory-medium emptyDirs mount as tmpfs
			// with the sticky bit (1777), and hosts with
			// fs.protected_regular=2 then EACCES every non-owner O_CREAT —
			// the target (UID 10002) can no longer open the FIFOs or log
			// files the cloner (UID 10001) created. FIFO payloads are kernel
			// pipe buffers regardless of the backing medium, so nothing is
			// lost; the 64Mi sizeLimit still bounds the supervisor logs.
			Name: volumeIPC,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("64Mi")),
				},
			},
		},
		{
			Name: volumeTmp,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("1Gi")),
				},
			},
		},
		{
			Name: volumeOutput,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("256Mi")),
				},
			},
		},
		{
			// Writable state for the userspace netbird sidecar (ro rootfs).
			Name: volumeNetBirdStat,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("128Mi")),
				},
			},
		},
		{
			Name: volumeSAToken,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: ptr.To[int32](0o440),
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Audience:          "",
								ExpirationSeconds: ptr.To[int64](3600),
								Path:              "token",
							},
						},
						{
							ConfigMap: &corev1.ConfigMapProjection{
								LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
								Items: []corev1.KeyToPath{
									{Key: "ca.crt", Path: "ca.crt"},
								},
							},
						},
						{
							DownwardAPI: &corev1.DownwardAPIProjection{
								Items: []corev1.DownwardAPIVolumeFile{
									{
										Path: "namespace",
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.namespace",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// ---- Init container: cloner & toolchain detector ----
	clonerEnv := []corev1.EnvVar{
		{Name: "REPO_URL", Value: server.Spec.RepositoryUrl},
		{Name: "REPO_REF", Value: ref},
		{Name: "REPO_PATH", Value: server.Spec.Path},
		{Name: "TRANSPORT", Value: transport},
		{Name: "TARGET_PORT", Value: fmt.Sprintf("%d", targetPort)},
		{Name: "WORKSPACE_DIR", Value: mountWorkspace},
		{Name: "IPC_DIR", Value: mountIPC},
		{Name: "HOME", Value: mountTmp},
	}
	clonerMounts := []corev1.VolumeMount{
		{Name: volumeWorkspace, MountPath: mountWorkspace},
		{Name: volumeIPC, MountPath: mountIPC},
		{Name: volumeTmp, MountPath: mountTmp},
	}
	if server.Spec.CredentialsSecretRef != "" {
		clonerEnv = append(clonerEnv,
			corev1.EnvVar{
				Name: "GIT_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: server.Spec.CredentialsSecretRef},
						Key:                  "username",
						Optional:             ptr.To(true),
					},
				},
			},
			corev1.EnvVar{
				Name: "GIT_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: server.Spec.CredentialsSecretRef},
						Key:                  "token",
						Optional:             ptr.To(true),
					},
				},
			},
			// Optional custom CA for self-hosted git servers (in-cluster
			// test fixtures, corporate Gitea): key ca.crt in the same
			// secret is handed to git as GIT_SSL_CAINFO, which git reads
			// natively.
			corev1.EnvVar{
				Name: "GIT_SSL_CAINFO",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: server.Spec.CredentialsSecretRef},
						Key:                  "ca.crt",
						Optional:             ptr.To(true),
					},
				},
			},
		)
	}

	cloner := corev1.Container{
		Name:            containerCloner,
		Image:           r.Images.ClonerImage,
		ImagePullPolicy: corev1.PullAlways,
		Env:             clonerEnv,
		VolumeMounts:    clonerMounts,
		SecurityContext: lockedSecurityContext(evaluatorUID),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		},
	}

	// ---- Target container: untrusted MCP server (jailed) ----
	target := corev1.Container{
		Name:            containerTarget,
		Image:           r.Images.TargetImage,
		ImagePullPolicy: corev1.PullAlways,
		Env: []corev1.EnvVar{
			{Name: "MCP_TRANSPORT", Value: transport},
			{Name: "MCP_PORT", Value: fmt.Sprintf("%d", targetPort)},
			{Name: "HOME", Value: mountTmp},
			{Name: "LAUNCH_FILE", Value: mountWorkspace + "/.mcp-launch.json"},
			{Name: "IPC_DIR", Value: mountIPC},
			{Name: "NO_PROXY", Value: "*"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: volumeWorkspace, MountPath: mountWorkspace, ReadOnly: true},
			{Name: volumeIPC, MountPath: mountIPC},
			{Name: volumeTmp, MountPath: mountTmp},
		},
		SecurityContext: lockedSecurityContext(targetUID),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		},
	}
	if transport == string(securityv1alpha1.TransportSSE) {
		target.Ports = []corev1.ContainerPort{
			{Name: "mcp", ContainerPort: targetPort, Protocol: corev1.ProtocolTCP},
		}
	}

	// ---- Evaluator container: OpenCode runner ----
	evaluator := corev1.Container{
		Name:            containerEvaluator,
		Image:           r.Images.EvaluatorImage,
		ImagePullPolicy: corev1.PullAlways,
		Env: []corev1.EnvVar{
			{Name: "RUN_NAME", Value: run.Name},
			{
				Name: "RUN_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"},
				},
			},
			{Name: "SERVER_NAME", Value: server.Name},
			{Name: "AGENT_NAMES", Value: strings.Join(run.Spec.Agents, ",")},
			{Name: "TRANSPORT", Value: transport},
			{Name: "TARGET_PORT", Value: fmt.Sprintf("%d", targetPort)},
			{Name: "WORKSPACE_DIR", Value: mountWorkspace},
			{Name: "IPC_DIR", Value: mountIPC},
			{Name: "OUTPUT_DIR", Value: mountOutput},
			{Name: "OPENCODE_PORT", Value: openCodePort},
			{Name: "HOME", Value: mountTmp},
			{Name: "RUN_TIMEOUT_SECONDS", Value: fmt.Sprintf("%d", timeout)},
			{
				Name: "ANTHROPIC_API_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: r.Images.LLMSecretName},
						Key:                  r.Images.LLMSecretKey,
						Optional:             ptr.To(true),
					},
				},
			},
			{
				// OpenCode Zen API key for provider `opencode` (e.g. opencode/claude-sonnet-4-6).
				Name: "OPENCODE_API_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: r.Images.LLMSecretName},
						Key:                  "OPENCODE_API_KEY",
						Optional:             ptr.To(true),
					},
				},
			},
			// ---- security layer wiring (Vigil / Occludra / NetBird) ----
			{
				Name:  "MESH_PROXY",
				Value: meshProxyEnv(r.Images),
			},
			{Name: "MESH_BRIDGE_PORT", Value: fmt.Sprintf("%d", r.Images.MeshBridgePort)},
			{Name: "VIGIL_URL", Value: r.Images.VigilURL},
			{Name: "OCCLUDRA_BASE_URL", Value: r.Images.OccludraBaseURL},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: volumeWorkspace, MountPath: mountWorkspace, ReadOnly: true},
			{Name: volumeIPC, MountPath: mountIPC},
			{Name: volumeTmp, MountPath: mountTmp},
			{Name: volumeOutput, MountPath: mountOutput},
			{Name: volumeSAToken, MountPath: mountSAToken, ReadOnly: true},
		},
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext:          lockedSecurityContext(evaluatorUID),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("2Gi"),
			},
		},
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobNameFor(run),
			Namespace: run.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr.To[int32](0),
			Completions:             ptr.To[int32](1),
			Parallelism:             ptr.To[int32](1),
			TTLSecondsAfterFinished: ptr.To(jobTTLSeconds),
			ActiveDeadlineSeconds:   ptr.To(int64(timeout)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"security.eval.io/repository": server.Spec.RepositoryUrl,
						"security.eval.io/ref":        ref,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                 corev1.RestartPolicyNever,
					ServiceAccountName:            r.Images.RunnerServiceAccount,
					AutomountServiceAccountToken:  ptr.To(false),
					EnableServiceLinks:            ptr.To(false),
					TerminationGracePeriodSeconds: ptr.To[int64](30),
					ShareProcessNamespace:         ptr.To(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(evaluatorUID),
						RunAsGroup:   ptr.To(evaluatorUID),
						FSGroup:      ptr.To(evaluatorUID),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					// The netbird sidecar is a NATIVE sidecar (init container
					// with restartPolicy Always): it starts right after the
					// cloner finishes and is Running before the target and
					// evaluator containers boot, so the WireGuard overlay is
					// up by the time the first Vigil/Occludra call is made.
					InitContainers: append([]corev1.Container{cloner}, r.buildNetBirdSidecar(run)...),
					Containers:     []corev1.Container{target, evaluator},
					Volumes:        volumes,
				},
			},
		},
	}
}

// meshProxyEnv renders the evaluator's MESH_PROXY value. An empty value is
// significant: it tells the runner the mesh is disabled (non-mesh fallback).
func meshProxyEnv(images ImageConfig) string {
	if !images.MeshEnforce {
		return ""
	}
	return images.MeshProxyURL
}

// buildNetBirdSidecar renders the userspace NetBird client injected into every
// evaluation pod. Userspace mode (NETBIRD_USERSPACE_HOSTWIRESOCK) terminates
// WireGuard in a netstack inside the container and exposes a local SOCKS5
// proxy on 127.0.0.1:1080 — no TUN device, no capabilities, PodSecurity
// restricted-safe. The proxy is shared through the pod network namespace; the
// evaluator reaches Vigil/Occludra through it (MESH_PROXY). Returns an empty
// slice when the mesh is disabled.
func (r *MCPEvaluationRunReconciler) buildNetBirdSidecar(run *securityv1alpha1.MCPEvaluationRun) []corev1.Container {
	if !r.Images.MeshEnforce {
		return nil
	}
	sidecar := corev1.Container{
		// restartPolicy Always promotes this init container to a native
		// sidecar: started before the main containers, never "completes".
		RestartPolicy:   ptr.To(corev1.ContainerRestartPolicyAlways),
		Name:            containerNetBird,
		Image:           r.Images.NetBirdImage,
		ImagePullPolicy: corev1.PullAlways,
		Env: []corev1.EnvVar{
			{Name: "NETBIRD_MANAGEMENT_URL", Value: r.Images.NetBirdManagementURL},
			{
				Name: "NETBIRD_SETUP_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: r.Images.NetBirdSecretName},
						Key:                  r.Images.NetBirdSecretKey,
					},
				},
			},
			{
				// Unique ephemeral mesh identity per evaluation pod.
				Name: "NETBIRD_HOSTNAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.name"},
				},
			},
			// Userspace netstack + local SOCKS5 proxy (127.0.0.1:1080).
			{Name: "NETBIRD_USERSPACE_HOSTWIRESOCK", Value: "yes"},
			{Name: "HOME", Value: mountTmp},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: volumeNetBirdStat, MountPath: mountNetBirdStat},
			{Name: volumeTmp, MountPath: mountTmp},
		},
		SecurityContext: lockedSecurityContext(evaluatorUID),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
	}
	return []corev1.Container{sidecar}
}

// evaluateNetworkPolicyName is the per-run NetworkPolicy locking an
// evaluation pod's evaluate-phase egress. In mesh mode that is DNS + API
// server + NetBird only; in legacy mode DNS + API server + the security
// gateways + public 443.
func evaluateNetworkPolicyName(run *securityv1alpha1.MCPEvaluationRun) string {
	return run.Name + "-evaluate-egress"
}

// ensureEvaluateNetworkPolicy creates (once) the per-run NetworkPolicy that
// implements "all eth0 egress denied except the NetBird overlay": the only
// allowed egress for pods in the evaluate phase is DNS, the Kubernetes API
// server and the NetBird control/data planes. NetworkPolicy cannot match on
// interfaces, so the WireGuard overlay is enforced by allowlisting exactly the
// destinations the netbird sidecar needs — the evaluator's Vigil/Occludra
// traffic has no permitted non-mesh path and must traverse wt0/SOCKS5.
//
// The policy carries an owner reference to the run (GC on deletion) and is
// created BEFORE the Job so the net-phase label flip never has a window
// without policy coverage. It is self-healing: recreated if deleted.
func (r *MCPEvaluationRunReconciler) ensureEvaluateNetworkPolicy(ctx context.Context, run *securityv1alpha1.MCPEvaluationRun) error {
	log := logf.FromContext(ctx)
	key := types.NamespacedName{Namespace: run.Namespace, Name: evaluateNetworkPolicyName(run)}
	existing := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, key, existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("fetching NetworkPolicy %s: %w", key.String(), err)
	}

	apiserverAddresses, err := r.resolveAPIServerAddresses(ctx)
	if err != nil {
		// Fail closed is wrong here (the run would never progress); fail open
		// to the ClusterIP rule and log loudly — DNS + ClusterIP still work
		// on CNIs that match pre-DNAT.
		log.Error(err, "cannot resolve apiserver endpoints; allowing ClusterIP only")
		apiserverAddresses = nil
	}

	policy := buildEvaluateNetworkPolicy(run, r.Images, apiserverAddresses)
	if err := controllerutil.SetControllerReference(run, policy, r.Scheme); err != nil {
		return fmt.Errorf("setting owner reference on NetworkPolicy: %w", err)
	}
	if err := r.Create(ctx, policy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("creating NetworkPolicy %s: %w", key.String(), err)
	}
	log.Info("created mesh-only egress NetworkPolicy", "policy", key.String(), "apiserverEndpoints", apiserverAddresses)
	r.Recorder.Eventf(run, corev1.EventTypeNormal, "MeshPolicyCreated",
		"evaluate-phase egress restricted to DNS, API server and NetBird (%s)", policy.Name)
	return nil
}

// buildEvaluateNetworkPolicy renders the per-run mesh-only egress policy.
func buildEvaluateNetworkPolicy(run *securityv1alpha1.MCPEvaluationRun, images ImageConfig, apiserverAddresses []string) *networkingv1.NetworkPolicy {
	labels := map[string]string{
		securityv1alpha1.LabelRun:      run.Name,
		securityv1alpha1.LabelRole:     securityv1alpha1.RoleEvaluationPod,
		"app.kubernetes.io/managed-by": "mcp-eval-operator",
	}

	// DNS: kube-dns in kube-system.
	dnsPort := intstr.FromInt32(53)
	dnsRule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
				},
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s-app": "kube-dns"},
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: ptr.To(corev1.ProtocolUDP), Port: &dnsPort},
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: &dnsPort},
		},
	}

	// Kubernetes API server: ClusterIP + real endpoint IPs (Calico and other
	// CNIs evaluate egress policy on the post-DNAT destination, so a
	// ClusterIP-only rule never matches — mirror deploy.sh's concern).
	apiPorts := []networkingv1.NetworkPolicyPort{
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(443))},
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(6443))},
	}
	var apiPeers []networkingv1.NetworkPolicyPeer
	if clusterIP := envOr("APISERVER_CLUSTERIP", ""); clusterIP != "" {
		apiPeers = append(apiPeers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: clusterIP}})
	}
	for _, addr := range apiserverAddresses {
		apiPeers = append(apiPeers, networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: addr},
		})
	}
	apiServerRule := networkingv1.NetworkPolicyEgressRule{To: apiPeers, Ports: apiPorts}

	// LEGACY mode (MESH_ENFORCE=false): the LLM path terminates in-cluster at
	// the security gateways, and direct provider calls (public 443) remain
	// possible for operators who bypass Occludra explicitly.
	gatewayPort5000 := intstr.FromInt32(5000)
	gatewayPort8080 := intstr.FromInt32(8080)
	gatewaysRule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "security-gateways"},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: &gatewayPort5000},
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: &gatewayPort8080},
		},
	}
	public443Rule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			IPBlock: &networkingv1.IPBlock{
				CIDR: "0.0.0.0/0",
				Except: []string{
					"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
					"169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
				},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(443))},
		},
	}

	// MESH mode: NetBird control plane (management 443/33073, signal 10000,
	// relay 33080) and data plane (WireGuard 51820/UDP, STUN/TURN 3478/UDP,
	// relay UDP range). No gateway-service or public-443 rule is emitted —
	// the ONLY LLM path is the WireGuard overlay.
	netbirdPorts := []networkingv1.NetworkPolicyPort{
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(443))},
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(33073))},
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(10000))},
		{Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To(intstr.FromInt32(33080))},
		{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(51820))},
		{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(3478))},
		// TURN relay ephemeral range.
		{Protocol: ptr.To(corev1.ProtocolUDP), Port: ptr.To(intstr.FromInt32(49152)), EndPort: ptr.To(int32(65535))},
	}
	var netbirdRule networkingv1.NetworkPolicyEgressRule
	if len(images.NetBirdEgressCIDRs) > 0 {
		peers := make([]networkingv1.NetworkPolicyPeer, 0, len(images.NetBirdEgressCIDRs))
		for _, cidr := range images.NetBirdEgressCIDRs {
			peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
		}
		netbirdRule = networkingv1.NetworkPolicyEgressRule{To: peers, Ports: netbirdPorts}
	}

	egress := []networkingv1.NetworkPolicyEgressRule{dnsRule, apiServerRule}
	if images.MeshEnforce {
		if netbirdRule.To != nil {
			egress = append(egress, netbirdRule)
		}
	} else {
		egress = append(egress, gatewaysRule, public443Rule)
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evaluateNetworkPolicyName(run),
			Namespace: run.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"security.eval.io/invariant": "evaluate-phase egress: DNS + API server + NetBird overlay (mesh) or gateways + public 443 (legacy)",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					securityv1alpha1.LabelRun:      run.Name,
					securityv1alpha1.LabelNetPhase: securityv1alpha1.NetPhaseEvaluate,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}
}

// resolveAPIServerAddresses returns the /32 CIDRs of the default/kubernetes
// service endpoints (EndpointSlice API first, legacy Endpoints fallback) plus
// the service ClusterIP, for use as NetworkPolicy ipBlocks.
func (r *MCPEvaluationRunReconciler) resolveAPIServerAddresses(ctx context.Context) ([]string, error) {
	seen := map[string]struct{}{}
	add := func(ip string) {
		if net.ParseIP(ip) != nil {
			seen[ip+"/32"] = struct{}{}
		}
	}

	slices := &discoveryv1.EndpointSliceList{}
	if err := r.List(ctx, slices,
		client.InNamespace("default"),
		client.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"},
	); err != nil {
		return nil, fmt.Errorf("listing endpointslices for default/kubernetes: %w", err)
	}
	for i := range slices.Items {
		for _, ep := range slices.Items[i].Endpoints {
			for _, addr := range ep.Addresses {
				add(addr)
			}
		}
	}
	if len(seen) == 0 {
		eps := &corev1.EndpointsList{}
		if err := r.List(ctx, eps, client.InNamespace("default")); err == nil {
			for i := range eps.Items {
				if eps.Items[i].Name != "kubernetes" {
					continue
				}
				for _, subset := range eps.Items[i].Subsets {
					for _, addr := range subset.Addresses {
						add(addr.IP)
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for cidr := range seen {
		out = append(out, cidr)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no endpoint addresses found for default/kubernetes")
	}
	return out, nil
}

// podToRun maps a pod event to the owning MCPEvaluationRun via the run label.
func podToRun(_ context.Context, obj client.Object) []reconcile.Request {
	runName, ok := obj.GetLabels()[securityv1alpha1.LabelRun]
	if !ok || runName == "" {
		return nil
	}
	return []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: runName}},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *MCPEvaluationRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("mcpevaluationrun-controller")
	}
	if r.Images.EvaluatorImage == "" {
		r.Images = ImageConfigFromEnv()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.MCPEvaluationRun{}).
		Owns(&batchv1.Job{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(podToRun)).
		Named("mcpevaluationrun").
		// The default of 1 serializes every run reconcile: with many
		// MCPServers firing at once, run/Job creation, net-phase flips and
		// pod observation would queue behind each other. 8 concurrent
		// workers keep throughput near the API server's rate limit; the
		// default exponential rate limiter still bounds retry storms.
		WithOptions(controller.Options{MaxConcurrentReconciles: runReconcileWorkers}).
		Complete(r)
}
