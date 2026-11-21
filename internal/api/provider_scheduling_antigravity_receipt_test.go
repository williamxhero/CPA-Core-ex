package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestProviderSchedulingAntigravityCountsOneSendPerHTTPDispatch(t *testing.T) {
	const generation = `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"antigravity-result"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}}`
	for _, mode := range []string{"off", "shadow", "enforce"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", mode, stream), func(t *testing.T) {
				f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, req *http.Request) {
					if strings.Contains(req.URL.Path, ":streamGenerateContent") {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: %s\n\n", generation)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, generation)
				})
				cfg := *f.cfg
				cfg.Routing.ProviderScheduling.Mode = mode
				f.manager.SetConfig(&cfg)
				ctx := coreauth.WithRequestBudget(coreauth.WithProviderSchedulingCaller(t.Context(), "fixture", "antigravity"))
				res := f.request(ctx, stream)
				if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "antigravity-result") {
					t.Fatalf("downstream status=%d body=%s", res.Code, res.Body)
				}
				f.assertCalls(t, "A")
				budget, ok := coreauth.RequestBudgetSnapshotFromContext(ctx)
				if !ok || budget.Attempts != 1 || budget.RoundAttempts != 1 || budget.ActiveWait != 0 {
					t.Fatalf("one actual upstream HTTP dispatch should count once: %+v", budget)
				}
				if mode != "off" {
					trace, ok := f.manager.RoutingTrace(res.Header().Get("X-Request-ID"))
					if !ok || trace.SendCount != 1 {
						t.Fatalf("one actual upstream HTTP dispatch should have one recorded send: %+v", trace)
					}
				}
			})
		}
	}
}

func TestProviderSchedulingAntigravityRejectsOverflowingRetryAfter(t *testing.T) {
	for _, test := range []struct {
		name, header, retryInfo, wantSource, wantHeader string
	}{
		{name: "duration overflow", header: "9223372037"},
		{name: "uint64 overflow", header: "18446744073709551616"},
		{name: "valid RetryInfo survives invalid header", header: "9223372037", retryInfo: "4s", wantSource: "retry_info", wantHeader: "4"},
		{name: "valid long header survives", header: "486000", wantSource: "retry_after", wantHeader: "486000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", test.header)
				w.WriteHeader(http.StatusTooManyRequests)
				if test.retryInfo == "" {
					_, _ = io.WriteString(w, scheduledAntigravity429Body)
					return
				}
				_, _ = fmt.Fprintf(w, `{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":%q}]}}`, test.retryInfo)
			})
			ctx := coreauth.WithRequestBudget(t.Context())
			res := f.request(ctx, false)
			f.assertCalls(t, "A")
			budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
			if budget.UpstreamCategory != "antigravity_resource_exhausted" || budget.ActiveWait != 0 || len(f.clock.waits) != 0 {
				t.Fatalf("expected one terminal Antigravity limit without waiting: %+v", budget)
			}
			if got := res.Header().Get("Retry-After"); res.Code != http.StatusTooManyRequests ||
				got != test.wantHeader || budget.UpstreamRetrySource != test.wantSource || budget.UpstreamRetryAt.IsZero() != (test.wantSource == "") {
				t.Fatalf("status=%d Retry-After=%q (want %q), retry source=%q (want %q), retry at=%v", res.Code, got, test.wantHeader,
					budget.UpstreamRetrySource, test.wantSource, budget.UpstreamRetryAt)
			}
		})
	}
}
