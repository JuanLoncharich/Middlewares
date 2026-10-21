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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

func runAt(minute int, phase securityv1alpha1.RunPhase, risk securityv1alpha1.RiskCategory, score int32) securityv1alpha1.MCPEvaluationRun {
	run := securityv1alpha1.MCPEvaluationRun{}
	run.CreationTimestamp = metav1.NewTime(time.Date(2026, 10, 21, 10, minute, 0, 0, time.UTC))
	run.Status.Phase = phase
	run.Status.FinalScore = score
	if risk != "" {
		run.Status.Scoring = &securityv1alpha1.ScoringBlock{RiskCategory: risk}
	}
	return run
}

func TestServerStatusFollowsTheLatestVerdict(t *testing.T) {
	cases := []struct {
		name      string
		runs      []securityv1alpha1.MCPEvaluationRun
		wantRisk  string
		wantScore int32
	}{
		{"completed safe", []securityv1alpha1.MCPEvaluationRun{
			runAt(1, securityv1alpha1.PhaseCompleted, securityv1alpha1.RiskSafe, 92)}, "Safe", 92},
		{"vigil abort after an older safe run", []securityv1alpha1.MCPEvaluationRun{
			runAt(1, securityv1alpha1.PhaseCompleted, securityv1alpha1.RiskSafe, 92),
			runAt(2, securityv1alpha1.PhaseFailed, securityv1alpha1.RiskMalicious, 0)}, "Malicious", 0},
		{"infrastructure failure keeps the last verdict", []securityv1alpha1.MCPEvaluationRun{
			runAt(1, securityv1alpha1.PhaseCompleted, securityv1alpha1.RiskSafe, 92),
			runAt(2, securityv1alpha1.PhaseFailed, "", 0)}, "Safe", 92},
		{"newer completed run replaces a malicious one", []securityv1alpha1.MCPEvaluationRun{
			runAt(2, securityv1alpha1.PhaseFailed, securityv1alpha1.RiskMalicious, 0),
			runAt(3, securityv1alpha1.PhaseCompleted, securityv1alpha1.RiskSafe, 88)}, "Safe", 88},
	}
	for _, c := range cases {
		server := &securityv1alpha1.MCPServer{}
		(&MCPServerReconciler{}).syncLatestRunResult(server, c.runs)
		if server.Status.OverallRiskStatus != c.wantRisk || server.Status.LastFinalScore != c.wantScore {
			t.Errorf("%s: got %q/%d, want %q/%d", c.name, server.Status.OverallRiskStatus,
				server.Status.LastFinalScore, c.wantRisk, c.wantScore)
		}
	}
}
