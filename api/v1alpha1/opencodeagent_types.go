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

// ModelSpec identifies the LLM provider and model an agent runs on.
type ModelSpec struct {
	// ProviderID is the OpenCode provider identifier (e.g. "anthropic").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ProviderID string `json:"providerID"`

	// ModelID is the provider-specific model identifier (e.g. "claude-sonnet-4-6").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ModelID string `json:"modelID"`
}

// AgentConfig holds execution tuning for an agent.
type AgentConfig struct {
	// TimeoutMs bounds a single agent prompt round-trip in milliseconds.
	// +kubebuilder:default=30000
	// +kubebuilder:validation:Minimum=1000
	// +optional
	TimeoutMs int32 `json:"timeoutMs,omitempty"`

	// RetryCount is the number of structured-output retries OpenCode performs
	// when the model's answer does not validate against the schema.
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +optional
	RetryCount int32 `json:"retryCount,omitempty"`
}

// OutputFormatSpec declares the structured-output contract for the agent.
type OutputFormatSpec struct {
	// Type is the output format type. Only "json_schema" is supported.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=json_schema
	Type string `json:"type"`

	// Schema is an arbitrary JSON Schema document the agent's answer must satisfy.
	// +kubebuilder:validation:Required
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	Schema runtime.RawExtension `json:"schema"`
}

// OpenCodeAgentSpec defines the desired state of OpenCodeAgent.
type OpenCodeAgentSpec struct {
	// Role is a free-form persona label (e.g. "StaticSecurityAuditor").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Role string `json:"role"`

	// Model selects the provider/model the agent runs on.
	// +kubebuilder:validation:Required
	Model ModelSpec `json:"model"`

	// Config tunes timeouts and retries.
	// +optional
	Config AgentConfig `json:"config,omitempty"`

	// SystemPrompt is the persona instruction injected into every session.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SystemPrompt string `json:"systemPrompt"`

	// OutputFormat declares the JSON schema the agent must answer with.
	// +kubebuilder:validation:Required
	OutputFormat OutputFormatSpec `json:"outputFormat"`
}

// OpenCodeAgentStatus defines the observed state of OpenCodeAgent.
type OpenCodeAgentStatus struct {
	// Conditions represent the latest available observations of the agent's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oca
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.role`
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.model.providerID`
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.model.modelID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenCodeAgent is the Schema for the opencodeagents API.
type OpenCodeAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenCodeAgentSpec   `json:"spec,omitempty"`
	Status OpenCodeAgentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenCodeAgentList contains a list of OpenCodeAgent.
type OpenCodeAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenCodeAgent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenCodeAgent{}, &OpenCodeAgentList{})
}
