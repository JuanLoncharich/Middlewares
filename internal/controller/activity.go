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
	"errors"
	"net"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/security-eval/mcp-eval-operator/api/v1alpha1"
)

// ActivityServer serves GET /active-runs -> {"activeRuns": N}, the number of
// MCPEvaluationRuns that have not reached a terminal phase.
//
// It exists for KEDA's metrics-api scaler: the GPU Vigil on the on-demand
// node scales 0 -> 1 while evaluations are in flight and back to 0 when the
// platform is idle. KEDA's kubernetes-workload scaler cannot do this because
// it only counts pods in the ScaledObject's own namespace, and evaluation
// pods (mcp-evals) and the scanner (security-gateways) live apart.
//
// Reads come from the manager's informer cache (no extra API-server load) and
// it runs on every replica, not only the leader, so the Service behind it is
// answered by whichever operator pod is up.
type ActivityServer struct {
	Reader client.Reader
	Addr   string
}

// NeedLeaderElection reports false: every replica serves the count.
func (s *ActivityServer) NeedLeaderElection() bool { return false }

// Start runs the HTTP server until ctx is cancelled.
func (s *ActivityServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/active-runs", s.handleActiveRuns)
	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *ActivityServer) handleActiveRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, err := CountActiveRuns(r.Context(), s.Reader)
	if err != nil {
		// Fail loudly: KEDA then keeps the last known replica count instead of
		// acting on a fabricated zero.
		http.Error(w, "cannot list MCPEvaluationRuns: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"activeRuns": n})
}

// CountActiveRuns counts MCPEvaluationRuns (all namespaces) whose phase is not
// terminal. A run with no phase yet counts as active: it was just created and
// is about to need a scanner.
func CountActiveRuns(ctx context.Context, reader client.Reader) (int, error) {
	var runs securityv1alpha1.MCPEvaluationRunList
	if err := reader.List(ctx, &runs); err != nil {
		return 0, err
	}
	active := 0
	for i := range runs.Items {
		switch runs.Items[i].Status.Phase {
		case securityv1alpha1.PhaseCompleted, securityv1alpha1.PhaseFailed:
		default:
			active++
		}
	}
	return active, nil
}
