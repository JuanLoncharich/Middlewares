package controller

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	security "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RunMetrics reads retained CR status from the informer cache on every scrape.
// It remains accurate across retries, controller restarts, and leader changes.
// Consumers use max across manager replicas, never sum duplicated snapshots.
type RunMetrics struct {
	Reader                                   client.Reader
	runs, oldest, failed, finished, scrapeOK *prometheus.Desc
}

func NewRunMetrics(reader client.Reader) *RunMetrics {
	return &RunMetrics{Reader: reader,
		runs:     prometheus.NewDesc("mcp_evaluation_runs", "Retained evaluation runs by phase (not a lifetime counter).", []string{"namespace", "phase"}, nil),
		oldest:   prometheus.NewDesc("mcp_evaluation_oldest_active_seconds", "Age of the oldest active retained evaluation.", []string{"namespace"}, nil),
		failed:   prometheus.NewDesc("mcp_evaluation_last_run_failed", "Whether the latest terminal run for a server failed.", []string{"namespace", "server"}, nil),
		finished: prometheus.NewDesc("mcp_evaluation_last_finished_timestamp_seconds", "Latest terminal evaluation completion time.", []string{"namespace", "server"}, nil),
		scrapeOK: prometheus.NewDesc("mcp_evaluation_status_scrape_success", "Whether cached evaluation status could be read.", nil, nil),
	}
}

func (m *RunMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{m.runs, m.oldest, m.failed, m.finished, m.scrapeOK} {
		ch <- d
	}
}

func (m *RunMetrics) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	list := &security.MCPEvaluationRunList{}
	if err := m.Reader.List(ctx, list); err != nil {
		ch <- prometheus.MustNewConstMetric(m.scrapeOK, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(m.scrapeOK, prometheus.GaugeValue, 1)
	counts := map[string]map[string]float64{}
	oldest := map[string]float64{}
	latest := map[client.ObjectKey]*security.MCPEvaluationRun{}
	for i := range list.Items {
		run := &list.Items[i]
		if !run.DeletionTimestamp.IsZero() {
			continue
		}
		if counts[run.Namespace] == nil {
			counts[run.Namespace] = map[string]float64{}
		}
		phase := string(run.Status.Phase)
		if phase == "" {
			phase = "Pending"
		}
		counts[run.Namespace][phase]++
		if !run.Status.Phase.IsTerminal() {
			start := run.CreationTimestamp.Time
			if run.Status.StartTime != nil {
				start = run.Status.StartTime.Time
			}
			age := time.Since(start).Seconds()
			if age > oldest[run.Namespace] {
				oldest[run.Namespace] = age
			}
		} else {
			key := client.ObjectKey{Namespace: run.Namespace, Name: run.Spec.ServerRef}
			if previous := latest[key]; previous == nil || run.CreationTimestamp.After(previous.CreationTimestamp.Time) {
				latest[key] = run
			}
		}
	}
	for ns, phases := range counts {
		for _, phase := range []string{"Pending", "Cloning", "Running", "Evaluating", "Completed", "Failed"} {
			ch <- prometheus.MustNewConstMetric(m.runs, prometheus.GaugeValue, phases[phase], ns, phase)
		}
		ch <- prometheus.MustNewConstMetric(m.oldest, prometheus.GaugeValue, oldest[ns], ns)
	}
	for key, run := range latest {
		failed := float64(0)
		if run.Status.Phase == security.PhaseFailed {
			failed = 1
		}
		ch <- prometheus.MustNewConstMetric(m.failed, prometheus.GaugeValue, failed, key.Namespace, key.Name)
		if run.Status.CompletionTime != nil {
			ch <- prometheus.MustNewConstMetric(m.finished, prometheus.GaugeValue, float64(run.Status.CompletionTime.Unix()), key.Namespace, key.Name)
		}
	}
}
