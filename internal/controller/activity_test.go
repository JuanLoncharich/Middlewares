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
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

func runInPhase(name, ns string, phase securityv1alpha1.RunPhase) *securityv1alpha1.MCPEvaluationRun {
	return &securityv1alpha1.MCPEvaluationRun{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status:     securityv1alpha1.MCPEvaluationRunStatus{Phase: phase},
	}
}

func activityReader(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(objs...).Build()
}

func TestCountActiveRunsCountsOnlyNonTerminalPhases(t *testing.T) {
	reader := activityReader(t,
		runInPhase("new", "mcp-evals", ""), // just created: needs a scanner soon
		runInPhase("pending", "mcp-evals", securityv1alpha1.PhasePending),
		runInPhase("cloning", "mcp-evals", securityv1alpha1.PhaseCloning),
		runInPhase("running", "other-ns", securityv1alpha1.PhaseRunning),
		runInPhase("evaluating", "mcp-evals", securityv1alpha1.PhaseEvaluating),
		runInPhase("done", "mcp-evals", securityv1alpha1.PhaseCompleted),
		runInPhase("failed", "mcp-evals", securityv1alpha1.PhaseFailed),
	)
	got, err := CountActiveRuns(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if got != 5 {
		t.Errorf("active runs = %d, want 5 (all non-terminal phases, every namespace)", got)
	}
}

func TestActiveRunsEndpointShape(t *testing.T) {
	cases := []struct {
		name string
		objs []client.Object
		want int
	}{
		{"idle platform scales the GPU scanner to zero", nil, 0},
		{"one evaluation in flight", []client.Object{runInPhase("r1", "mcp-evals", securityv1alpha1.PhaseEvaluating)}, 1},
		{"only finished runs", []client.Object{
			runInPhase("r1", "mcp-evals", securityv1alpha1.PhaseCompleted),
			runInPhase("r2", "mcp-evals", securityv1alpha1.PhaseFailed),
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ActivityServer{Reader: activityReader(t, tc.objs...)}
			rec := httptest.NewRecorder()
			s.handleActiveRuns(rec, httptest.NewRequest(http.MethodGet, "/active-runs", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var body map[string]int
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("not JSON: %v (%s)", err, rec.Body.String())
			}
			// KEDA's metrics-api scaler reads valueLocation "activeRuns".
			if body["activeRuns"] != tc.want {
				t.Errorf("activeRuns = %d, want %d", body["activeRuns"], tc.want)
			}
		})
	}
}

func TestActiveRunsEndpointRejectsWrites(t *testing.T) {
	s := &ActivityServer{Reader: activityReader(t)}
	rec := httptest.NewRecorder()
	s.handleActiveRuns(rec, httptest.NewRequest(http.MethodPost, "/active-runs", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}
