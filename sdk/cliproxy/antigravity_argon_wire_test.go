package cliproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestAntigravityArgonEffortOnWire(t *testing.T) {
	resetAntigravityCapabilityCache()
	t.Cleanup(resetAntigravityCapabilityCache)
	// Renaming one tier must not revoke its entitlement from the family route.
	cfg := &config.Config{OAuthModelAlias: map[string][]config.OAuthModelAlias{"antigravity": {{Name: "gemini-4-argon-low", Alias: "custom-argon-low"}}}}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.SetUpstreamErrorRetryLimit(0)
	manager.RegisterExecutor(runtimeexecutor.NewAntigravityExecutor(cfg))
	svc := &Service{cfg: cfg, coreManager: manager}
	captured := make(chan [2]string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == antigravityModelsPath {
			_, _ = io.WriteString(w, `{"models":{"gemini-4-argon-low":{},"gemini-4-argon-medium":{},"gemini-4-argon-high":{}}}`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		captured <- [2]string{ojson.GetBytes(body, "model").String(), ojson.GetBytes(body, "request.generationConfig.thinkingConfig.thinkingLevel").String()}
		data := `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"totalTokenCount":2}}}`
		if strings.Contains(r.URL.Path, "streamGenerateContent") {
			w.Header().Set("Content-Type", "text/event-stream")
			data = "data: " + data + "\n\n"
		}
		_, _ = io.WriteString(w, data)
	}))
	defer server.Close()
	a := antigravityTestAuth("wire-argon", server.URL)
	a.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	a, err := manager.Register(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(a.ID) })
	svc.registerModelsForAuth(t.Context(), a)
	svc.WaitAntigravityProbes()
	for _, tc := range []struct {
		model, effort, wantID string
		stream                bool
	}{
		{"gemini-4-argon", "low", "gemini-4-argon-low", false},
		{"gemini-4-argon", "medium", "gemini-4-argon-medium", true},
		{"gemini-4-argon", "high", "gemini-4-argon-high", false},
		{"gemini-4-argon", "", "gemini-4-argon-medium", false},
		{"gemini-4-argon-high", "low", "gemini-4-argon-high", false},
	} {
		t.Run(tc.model+"-"+tc.effort, func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"OK"}],"reasoning_effort":%q}`, tc.model, tc.effort))
			if tc.effort == "" {
				payload = []byte(`{"model":"gemini-4-argon","messages":[{"role":"user","content":"OK"}]}`)
			}
			req := coreexecutor.Request{Model: tc.model, Payload: payload}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, Stream: tc.stream, OriginalRequest: payload}
			if tc.stream {
				out, err := manager.ExecuteStream(t.Context(), []string{"antigravity"}, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for chunk := range out.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else if _, err := manager.Execute(t.Context(), []string{"antigravity"}, req, opts); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-captured:
				if got != [2]string{tc.wantID, tc.effort} {
					t.Fatalf("wire (model,level) = %v, want %s %s", got, tc.wantID, tc.effort)
				}
			default:
				t.Fatal("no upstream request")
			}
		})
	}
}
