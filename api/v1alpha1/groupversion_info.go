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

// Package v1alpha1 contains API Schema definitions for the security v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=security.eval.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "security.eval.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// Label and annotation keys shared between the reconcilers and the evaluator runner.
const (
	// LabelRun identifies the MCPEvaluationRun that owns a Job/Pod.
	LabelRun = "security.eval.io/run"
	// LabelServer identifies the MCPServer an MCPEvaluationRun/Job/Pod belongs to.
	LabelServer = "security.eval.io/server"
	// LabelRole marks the role of a pod (e.g. evaluation-pod) for NetworkPolicy selection.
	LabelRole = "security.eval.io/role"
	// LabelNetPhase is flipped from "clone" to "evaluate" by the run controller once
	// init containers finish; NetworkPolicies key on it to narrow egress.
	LabelNetPhase = "security.eval.io/net-phase"

	// RoleEvaluationPod is the LabelRole value for evaluation Job pods.
	RoleEvaluationPod = "evaluation-pod"
	// NetPhaseClone allows git/registry egress during the cloner init container.
	NetPhaseClone = "clone"
	// NetPhaseEvaluate allows only LLM API + apiserver + DNS egress.
	NetPhaseEvaluate = "evaluate"

	// AnnotationTriggerNow forces an immediate evaluation run when set to "true" on an MCPServer.
	AnnotationTriggerNow = "security.eval.io/trigger-now"

	// RunFinalizer guarantees Job cleanup when an MCPEvaluationRun is deleted.
	RunFinalizer = "security.eval.io/run-cleanup"
)
