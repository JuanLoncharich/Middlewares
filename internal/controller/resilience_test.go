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
	"errors"
	"net"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestIsTransientKubeError(t *testing.T) {
	gvk := schema.GroupResource{Group: "batch", Resource: "jobs"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"server timeout", apierrors.NewServerTimeout(gvk, "create", 1), true},
		{"too many requests", apierrors.NewTooManyRequestsError("throttled"), true},
		{"service unavailable", apierrors.NewServiceUnavailable("apiserver restarting"), true},
		{"internal error", apierrors.NewInternalError(errors.New("etcd lost quorum")), true},
		{"network refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"invalid (permanent)", apierrors.NewInvalid(schema.GroupKind{Group: "batch", Kind: "Job"}, "x", nil), false},
		{"forbidden (permanent)", apierrors.NewForbidden(gvk, "x", errors.New("nope")), false},
		{"plain error (permanent)", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientKubeError(tc.err); got != tc.want {
				t.Fatalf("isTransientKubeError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestInfraTransientFailure(t *testing.T) {
	evictedPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	evictedPod.Status.Reason = "Evicted"

	pullPod := func(waiting string, age time.Duration) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", CreationTimestamp: metav1.NewTime(time.Now().Add(-age))}}
		p.Status.Phase = corev1.PodPending
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  containerEvaluator,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: waiting}},
		}}
		return p
	}

	ranPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	ranPod.Status.Phase = corev1.PodRunning
	ranPod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  containerEvaluator,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
	}}

	oomClonerPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	oomClonerPod.Status.Phase = corev1.PodFailed
	oomClonerPod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:  containerCloner,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}},
	}}

	deadlineJob := &batchv1.Job{}
	deadlineJob.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}}

	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"evicted is transient", evictedPod, true},
		{"image pull backoff is transient", pullPod("ImagePullBackOff", time.Minute), true},
		{"unschedulable is transient", pullPod("Unschedulable", time.Minute), true},
		{"oomkilled init container is transient", oomClonerPod, true},
		{"nil pod (deadline, pod gone) is terminal", nil, false},
		{"evaluator ran and failed is terminal", ranPod, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := infraTransientFailure(deadlineJob, tc.pod)
			if got != tc.want {
				t.Fatalf("infraTransientFailure() transient = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStuckPending(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-2 * stuckPendingAfter))
	fresh := metav1.NewTime(time.Now())

	started := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", CreationTimestamp: old}}
	started.Status.Phase = corev1.PodPending
	started.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:  containerCloner,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}

	idle := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", CreationTimestamp: old}}
	idle.Status.Phase = corev1.PodPending

	newPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", CreationTimestamp: fresh}}
	newPod.Status.Phase = corev1.PodPending

	now := time.Now()
	if stuckPending(started, now) {
		t.Error("pod with a running init container must not be considered stuck")
	}
	if !stuckPending(idle, now) {
		t.Error("old Pending pod with no container progress must be considered stuck")
	}
	if stuckPending(newPod, now) {
		t.Error("young Pending pod must not be considered stuck yet")
	}
}

func TestRetryJobBounded(t *testing.T) {
	// retryJob's bound is enforced inline; verify the constant stays coherent
	// with the CRD validation (retries maximum: 2).
	if maxJobRetries != 2 {
		t.Fatalf("maxJobRetries = %d, want 2 (CRD status.retries maximum)", maxJobRetries)
	}
	if stuckPendingAfter != 5*time.Minute {
		t.Fatalf("stuckPendingAfter = %s, want 5m", stuckPendingAfter)
	}
}
