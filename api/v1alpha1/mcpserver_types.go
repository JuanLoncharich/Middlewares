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
)

// Transport is the MCP wire transport exposed by the target server.
// +kubebuilder:validation:Enum=stdio;sse
type Transport string

const (
	// TransportStdio drives the server over stdin/stdout JSON-RPC frames.
	TransportStdio Transport = "stdio"
	// TransportSSE drives the server over HTTP + Server-Sent Events.
	TransportSSE Transport = "sse"
)

// AgentReference names an OpenCodeAgent in the same namespace.
type AgentReference struct {
	// Name of the OpenCodeAgent resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// MCPServerSpec defines the desired state of MCPServer.
type MCPServerSpec struct {
	// RepositoryUrl is the HTTPS git URL of the MCP server source.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https://`
	RepositoryUrl string `json:"repositoryUrl"`

	// Ref is the branch, tag or commit to check out.
	// +kubebuilder:default="main"
	// +optional
	Ref string `json:"ref,omitempty"`

	// Path is an optional sub-directory inside the repository containing the server.
	// +optional
	Path string `json:"path,omitempty"`

	// Transport selects how the evaluator talks to the target (stdio or sse).
	// +kubebuilder:default=stdio
	// +optional
	Transport Transport `json:"transport,omitempty"`

	// TargetPort is the loopback port the target listens on when transport is sse.
	// +kubebuilder:default=8080
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=65535
	// +optional
	TargetPort int32 `json:"targetPort,omitempty"`

	// Schedule is a standard 5-field cron expression controlling evaluation cadence.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=9
	Schedule string `json:"schedule"`

	// Active enables or pauses scheduled evaluations.
	// +kubebuilder:default=true
	// +optional
	Active *bool `json:"active,omitempty"`

	// CredentialsSecretRef names a Secret (keys: username, token) for private repositories.
	// +optional
	CredentialsSecretRef string `json:"credentialsSecretRef,omitempty"`

	// AgentSuite lists the OpenCodeAgents run, in order, against this server.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	AgentSuite []AgentReference `json:"agentSuite"`

	// TimeoutSeconds bounds a whole evaluation run.
	// +kubebuilder:default=900
	// +kubebuilder:validation:Minimum=60
	// +optional
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`

	// RunHistoryLimit is how many terminal MCPEvaluationRuns to keep per server.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=0
	// +optional
	RunHistoryLimit int32 `json:"runHistoryLimit,omitempty"`
}

// MCPServerStatus defines the observed state of MCPServer.
type MCPServerStatus struct {
	// LastEvaluationDate is when the most recent run was created.
	// +optional
	LastEvaluationDate *metav1.Time `json:"lastEvaluationDate,omitempty"`

	// NextScheduledTime is the next cron fire time.
	// +optional
	NextScheduledTime *metav1.Time `json:"nextScheduledTime,omitempty"`

	// OverallRiskStatus mirrors the risk category of the last completed run.
	// +optional
	OverallRiskStatus string `json:"overallRiskStatus,omitempty"`

	// LastRunRef is the name of the most recently created MCPEvaluationRun.
	// +optional
	LastRunRef string `json:"lastRunRef,omitempty"`

	// LastFinalScore is the final score of the last completed run.
	// +optional
	LastFinalScore int32 `json:"lastFinalScore,omitempty"`

	// Conditions represent the latest available observations of the server's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// IsActive returns whether scheduled evaluations are enabled (defaults to true).
func (s *MCPServerSpec) IsActive() bool {
	return s.Active == nil || *s.Active
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcps
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repositoryUrl`
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Active",type=boolean,JSONPath=`.spec.active`
// +kubebuilder:printcolumn:name="Risk",type=string,JSONPath=`.status.overallRiskStatus`
// +kubebuilder:printcolumn:name="LastRun",type=string,JSONPath=`.status.lastRunRef`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MCPServer is the Schema for the mcpservers API.
type MCPServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPServerSpec   `json:"spec,omitempty"`
	Status MCPServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPServerList contains a list of MCPServer.
type MCPServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPServer{}, &MCPServerList{})
}
