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
	"fmt"
	"os"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	containerCloner    = "cloner"
	containerTarget    = "target"
	containerEvaluator = "evaluator"

	volumeWorkspace = "workspace"
	volumeIPC       = "ipc"
	volumeTmp       = "tmp"
	volumeOutput    = "output"
	volumeSAToken   = "sa-token"

	mountWorkspace = "/workspace"
	mountIPC       = "/ipc"
	mountTmp       = "/tmp"
	mountOutput    = "/output"
	mountSAToken   = "/var/run/secrets/kubernetes.io/serviceaccount"

	evaluatorUID int64 = 10001
	targetUID    int64 = 10002

	jobTTLSeconds int32 = 600
	openCodePort        = "4096"

	runRequeueInterval = 15 * time.Second
)

// ImageConfig carries the images and secrets injected into evaluation Jobs.
type ImageConfig struct {
	ClonerImage          string
	TargetImage          string
	EvaluatorImage       string
	RunnerServiceAccount string
	LLMSecretName        string
	LLMSecretKey         string
}

// FromEnv reads ImageConfig from environment variables with production defaults.
func ImageConfigFromEnv() ImageConfig {
	return ImageConfig{
		ClonerImage:          envOr("CLONER_IMAGE", "ghcr.io/security-eval/mcp-cloner:latest"),
		TargetImage:          envOr("TARGET_IMAGE", "ghcr.io/security-eval/mcp-target-sandbox:latest"),
		EvaluatorImage:       envOr("EVALUATOR_IMAGE", "ghcr.io/security-eval/mcp-evaluator:latest"),
		RunnerServiceAccount: envOr("RUNNER_SERVICE_ACCOUNT", "mcp-eval-runner"),
		LLMSecretName:        envOr("LLM_SECRET_NAME", "llm-provider-credentials"),
		LLMSecretKey:         envOr("LLM_SECRET_KEY", "ANTHROPIC_API_KEY"),
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
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
		job = r.buildJob(run, server)
		if err := controllerutil.SetControllerReference(run, job, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("setting owner reference on Job: %w", err)
		}
		if err := r.Create(ctx, job); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil
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
	run.Status.JobName = job.Name

	// Locate the pod backing the job.
	pod, err := r.findPod(ctx, run)
	if err != nil {
		return ctrl.Result{}, err
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
		run.Status.Message = "evaluation completed"
	}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type:               ConditionSucceeded,
		Status:             metav1.ConditionTrue,
		Reason:             "Completed",
		Message:            run.Status.Message,
		ObservedGeneration: run.Generation,
	})
	r.Recorder.Eventf(run, corev1.EventTypeNormal, "Completed", "evaluation completed with score %d", run.Status.FinalScore)
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
func initContainersDone(pod *corev1.Pod) bool {
	if len(pod.Spec.InitContainers) == 0 {
		return true
	}
	if len(pod.Status.InitContainerStatuses) < len(pod.Spec.InitContainers) {
		return false
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Terminated == nil {
			return false
		}
	}
	return true
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
			Name: volumeIPC,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium:    corev1.StorageMediumMemory,
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
					InitContainers: []corev1.Container{cloner},
					Containers:     []corev1.Container{target, evaluator},
					Volumes:        volumes,
				},
			},
		},
	}
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
	if r.Images == (ImageConfig{}) {
		r.Images = ImageConfigFromEnv()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.MCPEvaluationRun{}).
		Owns(&batchv1.Job{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(podToRun)).
		Named("mcpevaluationrun").
		Complete(r)
}
