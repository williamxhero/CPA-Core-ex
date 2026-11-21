package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestProviderSchedulingUnlimitedRetryDoesNotPollWithoutTrustedHint(t *testing.T) {
	f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) {
		emit("{\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"code\":\"rate_limit_exceeded\",\"message\":\"rate limited\"}}")
	})
	cfg := f.inventory.server.cfg
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	f.inventory.manager.SetConfig(cfg)
	f.inventory.manager.SetRetryConfig(0, time.Second, 3)
	f.inventory.manager.SetUpstreamErrorRetryLimit(-1)

	status, body := f.request(t, "http", nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("want actual upstream 429, got %d: %s", status, body)
	}
	f.assertAttempts(t, "A,P,B")
}
