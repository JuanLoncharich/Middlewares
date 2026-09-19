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
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

const (
	apiServerProbeTimeout  = 3 * time.Second
	apiServerProbeCacheTTL = 5 * time.Second
)

// NewAPIServerReadinessCheck returns a healthz.Checker that verifies the
// manager can actually reach the Kubernetes API server (and that the API
// server considers itself ready) via a cheap request to its /readyz endpoint.
// Unlike healthz.Ping, /readyz then reflects real control-plane connectivity.
// Results are cached for apiServerProbeCacheTTL so probe frequency never
// hammers the API server.
func NewAPIServerReadinessCheck(cfg *rest.Config) healthz.Checker {
	client, err := kubernetes.NewForConfig(rest.CopyConfig(cfg))
	if err != nil {
		return func(*http.Request) error {
			return fmt.Errorf("building API-server readiness client: %w", err)
		}
	}

	var (
		mu        sync.Mutex
		lastProbe time.Time
		lastOK    bool
		lastErr   error
	)
	return func(*http.Request) error {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(lastProbe) < apiServerProbeCacheTTL {
			if lastOK {
				return nil
			}
			return lastErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), apiServerProbeTimeout)
		defer cancel()
		_, err := client.Discovery().RESTClient().Get().AbsPath("/readyz").DoRaw(ctx)
		lastProbe = time.Now()
		if err != nil {
			lastOK = false
			lastErr = fmt.Errorf("API server unreachable: %w", err)
			return lastErr
		}
		lastOK = true
		lastErr = nil
		return nil
	}
}
