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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RunPhase is the lifecycle phase of an MCPEvaluationRun.
// +kubebuilder:validation:Enum=Pending;Cloning;Running;Evaluating;Completed;Failed
type RunPhase string

const (
	// PhasePending means the run has been accepted but no Job exists yet.
	PhasePending RunPhase = "Pending"
	// PhaseCloning means the cloner init container is fetching the repository.
	PhaseCloning RunPhase = "Cloning"
	// PhaseRunning means target and evaluator containers are up.
	PhaseRunning RunPhase = "Running"
	// PhaseEvaluating means the evaluator has started driving agents.
	PhaseEvaluating RunPhase = "Evaluating"
	// PhaseCompleted means the evaluation finished and results are recorded.
	PhaseCompleted RunPhase = "Completed"
	// PhaseFailed means the evaluation could not complete.
	PhaseFailed RunPhase = "Failed"
)

// IsTerminal reports whether the phase is Completed or Failed.
func (p RunPhase) IsTerminal() bool {
	return p == PhaseCompleted || p == PhaseFailed
}

// Rank orders phases so the controller never downgrades a phase set by the runner.
func (p RunPhase) Rank() int {
	switch p {
	case PhasePending:
		return 1
	case PhaseCloning:
		return 2
	case PhaseRunning:
		return 3
	case PhaseEvaluating:
		return 4
	case PhaseCompleted, PhaseFailed:
		return 5
	default:
		return 0
	}
}

// RiskCategory is the synthesized risk classification of a target.
// +kubebuilder:validation:Enum=Safe;Caution;Untrusted;Malicious;Unknown
type RiskCategory string

const (
	RiskSafe      RiskCategory = "Safe"
	RiskCaution   RiskCategory = "Caution"
	RiskUntrusted RiskCategory = "Untrusted"
	RiskMalicious RiskCategory = "Malicious"
	RiskUnknown   RiskCategory = "Unknown"
)

// Severity classifies a finding.
// +kubebuilder:validation:Enum=Critical;High;Medium;Low;Info
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

// ScoringBlock is the synthesized final scoring produced by the synthesis agent.
type ScoringBlock struct {
	// SafetyScore is 0-100 (higher is safer).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	SafetyScore int32 `json:"safetyScore"`

	// ReliabilityScore is 0-100 (higher is more robust).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	ReliabilityScore int32 `json:"reliabilityScore"`

	// RiskCategory is the overall classification.
	RiskCategory RiskCategory `json:"riskCategory"`

	// Summary is a short human-readable verdict.
	// +optional
	Summary string `json:"summary,omitempty"`
}

// Finding is a single normalized security finding.
type Finding struct {
	// Agent that produced the finding.
	Agent string `json:"agent"`

	// Severity of the finding.
	Severity Severity `json:"severity"`

	// Title is a one-line description.
	Title string `json:"title"`

	// Description gives detail on the finding.
	// +optional
	Description string `json:"description,omitempty"`

	// Remediation is the recommended fix.
	// +optional
	Remediation string `json:"remediation,omitempty"`
}

// MCPEvaluationRunSpec defines the desired state of MCPEvaluationRun.
type MCPEvaluationRunSpec struct {
	// ServerRef names the MCPServer in the same namespace to evaluate.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ServerRef string `json:"serverRef"`

	// Agents lists the OpenCodeAgent names to run, in order.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Agents []string `json:"agents"`

	// TimeoutSeconds bounds the whole run (Job activeDeadlineSeconds).
	// +kubebuilder:default=900
	// +kubebuilder:validation:Minimum=60
	// +optional
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// MCPEvaluationRunStatus defines the observed state of MCPEvaluationRun.
type MCPEvaluationRunStatus struct {
	// Phase is the lifecycle phase.
	// +kubebuilder:default=Pending
	// +optional
	Phase RunPhase `json:"phase,omitempty"`

	// CurrentAgent is the agent currently executing (set by the runner).
	// +optional
	CurrentAgent string `json:"currentAgent,omitempty"`

	// AgentResults maps agent name to its raw structured output.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	AgentResults map[string]runtime.RawExtension `json:"agentResults,omitempty"`

	// FinalScore is the synthesized 0-100 safety score.
	// +optional
	FinalScore int32 `json:"finalScore,omitempty"`

	// Scoring holds the full synthesized scoring block.
	// +optional
	Scoring *ScoringBlock `json:"scoring,omitempty"`

	// Findings is the normalized list of findings across all agents.
	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// Message carries a human-readable status or error description.
	// +optional
	Message string `json:"message,omitempty"`

	// JobName is the batch/v1 Job created for this run.
	// +optional
	JobName string `json:"jobName,omitempty"`

	// StartTime is when the run entered Pending.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the run reached a terminal phase.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Conditions represent the latest available observations of the run's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcprun
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef`
// +kubebuilder:printcolumn:name="Score",type=integer,JSONPath=`.status.finalScore`
// +kubebuilder:printcolumn:name="Risk",type=string,JSONPath=`.status.scoring.riskCategory`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MCPEvaluationRun is the Schema for the mcpevaluationruns API.
type MCPEvaluationRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPEvaluationRunSpec   `json:"spec,omitempty"`
	Status MCPEvaluationRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPEvaluationRunList contains a list of MCPEvaluationRun.
type MCPEvaluationRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPEvaluationRun `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPEvaluationRun{}, &MCPEvaluationRunList{})
}
