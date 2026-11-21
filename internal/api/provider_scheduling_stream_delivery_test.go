package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestProviderSchedulingCompletedResponsesDeliveryIsNotCancellation(t *testing.T) {
	const generation = `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"delivered-result"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}}`
	f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, ":streamGenerateContent") {
			t.Error("fixture expects streaming inference")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", generation)
	})
	for range 25 {
		ctx := coreauth.WithRequestBudget(coreauth.WithProviderSchedulingCaller(t.Context(), "fixture", "antigravity"))
		res := f.request(ctx, true)
		body, _ := io.ReadAll(res.Result().Body)
		if res.Code != http.StatusOK || !strings.Contains(string(body), "event: response.completed") ||
			!strings.Contains(string(body), "delivered-result") {
			t.Fatalf("fixture did not deliver a normal Responses terminal: %d %s", res.Code, body)
		}
		id := res.Header().Get("X-Request-ID")
		deadline := time.Now().Add(time.Second)
		for {
			receipt, ok := f.manager.RoutingTrace(id)
			if ok && receipt.Terminal != nil {
				if receipt.Terminal.Code != "succeeded" || receipt.Terminal.Status != http.StatusOK || receipt.SendCount != 1 {
					t.Fatalf("delivered Responses stream recorded wrong terminal: %+v (%d sends)", *receipt.Terminal, receipt.SendCount)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no terminal receipt for completed stream %s", id)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
