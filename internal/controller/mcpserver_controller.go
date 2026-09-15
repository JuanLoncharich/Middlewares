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
	"fmt"
	"sort"
	"time"

	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

const (
	// ConditionReady is the MCPServer readiness condition type.
	ConditionReady = "Ready"

	reasonMissingAgent    = "MissingAgent"
	reasonInvalidSchedule = "InvalidSchedule"
	reasonScheduled       = "Scheduled"
	reasonInactive        = "Inactive"

	// serverRequeueFallback bounds how long we wait when no cron fire time can be computed.
	serverRequeueFallback = 5 * time.Minute
)

// MCPServerReconciler reconciles a MCPServer object.
type MCPServerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=security.eval.io,resources=mcpservers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpservers/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.eval.io,resources=mcpevaluationruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.eval.io,resources=opencodeagents,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile evaluates the MCPServer's cron schedule and spawns MCPEvaluationRuns when due.
func (r *MCPServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	server := &securityv1alpha1.MCPServer{}
	if err := r.Get(ctx, req.NamespacedName, server); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MCPServer: %w", err)
	}
	if !server.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	original := server.DeepCopy()

	// Validate agent references before considering any scheduling.
	if missing := r.missingAgents(ctx, server); len(missing) > 0 {
		msg := fmt.Sprintf("agentSuite references missing OpenCodeAgents: %v", missing)
		meta.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonMissingAgent,
			Message:            msg,
			ObservedGeneration: server.Generation,
		})
		r.Recorder.Event(server, corev1.EventTypeWarning, reasonMissingAgent, msg)
		if err := r.patchStatus(ctx, server, original); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: serverRequeueFallback}, nil
	}

	// Mirror results of the latest run into server status.
	runs, err := r.listRuns(ctx, server)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.syncLatestRunResult(server, runs)

	if !server.Spec.IsActive() {
		meta.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonInactive,
			Message:            "scheduled evaluations are paused (spec.active=false)",
			ObservedGeneration: server.Generation,
		})
		server.Status.NextScheduledTime = nil
		if err := r.patchStatus(ctx, server, original); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	schedule, err := cron.ParseStandard(server.Spec.Schedule)
	if err != nil {
		msg := fmt.Sprintf("invalid cron schedule %q: %v", server.Spec.Schedule, err)
		meta.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonInvalidSchedule,
			Message:            msg,
			ObservedGeneration: server.Generation,
		})
		r.Recorder.Event(server, corev1.EventTypeWarning, reasonInvalidSchedule, msg)
		if err := r.patchStatus(ctx, server, original); err != nil {
			return ctrl.Result{}, err
		}
		// A spec change will re-trigger reconciliation; nothing to requeue for.
		return ctrl.Result{}, nil
	}

	now := time.Now()
	triggerNow := server.Annotations[securityv1alpha1.AnnotationTriggerNow] == "true"
	due, mostRecentFire := r.isDue(server, schedule, now)
	next := schedule.Next(now)

	activeRun := findActiveRun(runs)
	created := false

	if (due || triggerNow) && activeRun == nil {
		run, err := r.createRun(ctx, server)
		if err != nil {
			return ctrl.Result{}, err
		}
		created = true
		fireTime := now
		if due && !triggerNow && !mostRecentFire.IsZero() {
			fireTime = mostRecentFire
		}
		server.Status.LastEvaluationDate = &metav1.Time{Time: fireTime}
		server.Status.LastRunRef = run.Name
		r.Recorder.Eventf(server, corev1.EventTypeNormal, "RunCreated", "created MCPEvaluationRun %s", run.Name)
		log.Info("created evaluation run", "run", run.Name, "triggerNow", triggerNow)
	} else if (due || triggerNow) && activeRun != nil {
		log.Info("evaluation due but a run is still active; skipping", "activeRun", activeRun.Name)
		r.Recorder.Eventf(server, corev1.EventTypeNormal, "RunSkipped", "run %s still active, skipping scheduled fire", activeRun.Name)
		if due {
			// Consume the fire so we do not keep re-triggering on every requeue.
			server.Status.LastEvaluationDate = &metav1.Time{Time: mostRecentFire}
		}
	}

	if triggerNow && created {
		if err := r.clearTriggerAnnotation(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
	}

	server.Status.NextScheduledTime = &metav1.Time{Time: next}
	meta.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             reasonScheduled,
		Message:            fmt.Sprintf("next evaluation scheduled at %s", next.UTC().Format(time.RFC3339)),
		ObservedGeneration: server.Generation,
	})

	if err := r.patchStatus(ctx, server, original); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.pruneRuns(ctx, server, runs); err != nil {
		return ctrl.Result{}, err
	}

	requeue := time.Until(next)
	if requeue < time.Second {
		requeue = time.Second
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// isDue reports whether a cron fire time elapsed since the last evaluation (or creation).
// It returns the most recent elapsed fire time so it can be recorded as lastEvaluationDate.
func (r *MCPServerReconciler) isDue(server *securityv1alpha1.MCPServer, schedule cron.Schedule, now time.Time) (bool, time.Time) {
	var since time.Time
	if server.Status.LastEvaluationDate != nil {
		since = server.Status.LastEvaluationDate.Time
	} else {
		since = server.CreationTimestamp.Time
	}
	if since.IsZero() {
		since = now
	}

	// Walk forward from the reference point; bound the loop to avoid runaway iteration
	// when a server has been inactive for a very long time.
	var lastFire time.Time
	cursor := since
	for i := 0; i < 1000; i++ {
		fire := schedule.Next(cursor)
		if fire.After(now) {
			break
		}
		lastFire = fire
		cursor = fire
	}
	return !lastFire.IsZero(), lastFire
}

// missingAgents returns the names in agentSuite that do not resolve to an OpenCodeAgent.
func (r *MCPServerReconciler) missingAgents(ctx context.Context, server *securityv1alpha1.MCPServer) []string {
	var missing []string
	for _, ref := range server.Spec.AgentSuite {
		agent := &securityv1alpha1.OpenCodeAgent{}
		key := types.NamespacedName{Namespace: server.Namespace, Name: ref.Name}
		if err := r.Get(ctx, key, agent); err != nil {
			missing = append(missing, ref.Name)
		}
	}
	return missing
}

// listRuns returns all MCPEvaluationRuns labelled for this server.
func (r *MCPServerReconciler) listRuns(ctx context.Context, server *securityv1alpha1.MCPServer) ([]securityv1alpha1.MCPEvaluationRun, error) {
	list := &securityv1alpha1.MCPEvaluationRunList{}
	if err := r.List(ctx, list,
		client.InNamespace(server.Namespace),
		client.MatchingLabels{securityv1alpha1.LabelServer: server.Name},
	); err != nil {
		return nil, fmt.Errorf("listing MCPEvaluationRuns: %w", err)
	}
	return list.Items, nil
}

// findActiveRun returns the first non-terminal run, if any.
func findActiveRun(runs []securityv1alpha1.MCPEvaluationRun) *securityv1alpha1.MCPEvaluationRun {
	for i := range runs {
		if !runs[i].DeletionTimestamp.IsZero() {
			continue
		}
		if !runs[i].Status.Phase.IsTerminal() {
			return &runs[i]
		}
	}
	return nil
}

// syncLatestRunResult copies the newest terminal run's score/risk into the server status.
func (r *MCPServerReconciler) syncLatestRunResult(server *securityv1alpha1.MCPServer, runs []securityv1alpha1.MCPEvaluationRun) {
	var latest *securityv1alpha1.MCPEvaluationRun
	for i := range runs {
		run := &runs[i]
		if run.Status.Phase != securityv1alpha1.PhaseCompleted {
			continue
		}
		if latest == nil || run.CreationTimestamp.After(latest.CreationTimestamp.Time) {
			latest = run
		}
	}
	if latest == nil {
		return
	}
	server.Status.LastFinalScore = latest.Status.FinalScore
	if latest.Status.Scoring != nil && latest.Status.Scoring.RiskCategory != "" {
		server.Status.OverallRiskStatus = string(latest.Status.Scoring.RiskCategory)
	} else {
		server.Status.OverallRiskStatus = string(securityv1alpha1.RiskUnknown)
	}
}

// createRun builds and creates an MCPEvaluationRun owned by the server.
func (r *MCPServerReconciler) createRun(ctx context.Context, server *securityv1alpha1.MCPServer) (*securityv1alpha1.MCPEvaluationRun, error) {
	agents := make([]string, 0, len(server.Spec.AgentSuite))
	for _, ref := range server.Spec.AgentSuite {
		agents = append(agents, ref.Name)
	}
	timeout := server.Spec.TimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}

	run := &securityv1alpha1.MCPEvaluationRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-run-%s", server.Name, utilrand.String(5)),
			Namespace: server.Namespace,
			Labels: map[string]string{
				securityv1alpha1.LabelServer: server.Name,
			},
		},
		Spec: securityv1alpha1.MCPEvaluationRunSpec{
			ServerRef:      server.Name,
			Agents:         agents,
			TimeoutSeconds: timeout,
		},
	}
	if err := controllerutil.SetControllerReference(server, run, r.Scheme); err != nil {
		return nil, fmt.Errorf("setting owner reference on run: %w", err)
	}
	if err := r.Create(ctx, run); err != nil {
		return nil, fmt.Errorf("creating MCPEvaluationRun: %w", err)
	}
	return run, nil
}

// clearTriggerAnnotation removes the trigger-now annotation after a run has been created.
func (r *MCPServerReconciler) clearTriggerAnnotation(ctx context.Context, server *securityv1alpha1.MCPServer) error {
	patched := server.DeepCopy()
	delete(patched.Annotations, securityv1alpha1.AnnotationTriggerNow)
	if err := r.Patch(ctx, patched, client.MergeFrom(server)); err != nil {
		return fmt.Errorf("clearing trigger annotation: %w", err)
	}
	server.Annotations = patched.Annotations
	server.ResourceVersion = patched.ResourceVersion
	return nil
}

// pruneRuns deletes the oldest terminal runs beyond spec.runHistoryLimit.
func (r *MCPServerReconciler) pruneRuns(ctx context.Context, server *securityv1alpha1.MCPServer, runs []securityv1alpha1.MCPEvaluationRun) error {
	limit := int(server.Spec.RunHistoryLimit)
	if limit < 0 {
		limit = 0
	}
	var terminal []securityv1alpha1.MCPEvaluationRun
	for _, run := range runs {
		if run.Status.Phase.IsTerminal() && run.DeletionTimestamp.IsZero() {
			terminal = append(terminal, run)
		}
	}
	if len(terminal) <= limit {
		return nil
	}
	sort.Slice(terminal, func(i, j int) bool {
		return terminal[i].CreationTimestamp.Before(&terminal[j].CreationTimestamp)
	})
	excess := terminal[:len(terminal)-limit]
	for i := range excess {
		run := &excess[i]
		if err := r.Delete(ctx, run); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("pruning run %s: %w", run.Name, err)
		}
		r.Recorder.Eventf(server, corev1.EventTypeNormal, "RunPruned", "deleted old MCPEvaluationRun %s", run.Name)
	}
	return nil
}

// patchStatus writes the status subresource if it changed.
func (r *MCPServerReconciler) patchStatus(ctx context.Context, server, original *securityv1alpha1.MCPServer) error {
	if err := r.Status().Patch(ctx, server, client.MergeFrom(original)); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("patching MCPServer status: %w", err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MCPServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("mcpserver-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.MCPServer{}).
		Owns(&securityv1alpha1.MCPEvaluationRun{}).
		Named("mcpserver").
		Complete(r)
}
