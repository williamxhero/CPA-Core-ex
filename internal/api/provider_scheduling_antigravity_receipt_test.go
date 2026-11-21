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
