package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	security "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRetainedRunMetricsSurviveCollectorRestart(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = security.AddToScheme(scheme)
	now := time.Now()
	old := &security.MCPEvaluationRun{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "evals", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))}, Spec: security.MCPEvaluationRunSpec{ServerRef: "demo"}, Status: security.MCPEvaluationRunStatus{Phase: security.PhaseCompleted}}
	newest := old.DeepCopy()
	newest.Name = "new"
	newest.CreationTimestamp = metav1.NewTime(now)
	newest.Status.Phase = security.PhaseFailed
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(old, newest).Build()
	const expected = `# HELP mcp_evaluation_last_run_failed Whether the latest terminal run for a server failed.
# TYPE mcp_evaluation_last_run_failed gauge
mcp_evaluation_last_run_failed{namespace="evals",server="demo"} 1
`
	for i := 0; i < 2; i++ {
		if err := testutil.CollectAndCompare(NewRunMetrics(reader), strings.NewReader(expected), "mcp_evaluation_last_run_failed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := reader.Delete(context.Background(), newest); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewRunMetrics(reader))
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
	if err := testutil.CollectAndCompare(NewRunMetrics(reader), strings.NewReader(strings.ReplaceAll(expected, "} 1", "} 0")), "mcp_evaluation_last_run_failed"); err != nil {
		t.Fatal(err)
	}
}

func TestTelemetryOnlyInjectedIntoEvaluator(t *testing.T) {
	run := &security.MCPEvaluationRun{ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: "evals", Annotations: map[string]string{"security.eval.io/traceparent": "00-11111111111111111111111111111111-2222222222222222-01"}}}
	server := &security.MCPServer{ObjectMeta: metav1.ObjectMeta{Name: "server"}}
	r := &MCPEvaluationRunReconciler{Images: ImageConfig{OTelEndpoint: "http://otel-collector.observability.svc:4318"}}
	job := r.buildJob(run, server)
	for _, c := range append(job.Spec.Template.Spec.InitContainers, job.Spec.Template.Spec.Containers...) {
		found := false
		for _, e := range c.Env {
			if e.Name == "OTEL_EXPORTER_OTLP_ENDPOINT" {
				found = true
			}
		}
		if found != (c.Name == "evaluator") {
			t.Fatalf("telemetry exposure for container %s: %v", c.Name, found)
		}
	}
}
