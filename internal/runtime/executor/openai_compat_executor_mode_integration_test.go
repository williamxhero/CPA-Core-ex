package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestOpenAICompatModelModeSurvivesRetryFallback(t *testing.T) {
	tests := []struct {
		name, model, wantPath, body string
	}{
		{"latest-gpt", "gpt-6.1-sol", "/responses", `{"id":"resp-1","object":"response","model":"gpt-6.1-sol","output":[]}`},
		{"image", "gpt-image-2.6", "/images/generations", `{"created":1,"data":[{"b64_json":"AA=="}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				attempts++
				if attempts == 1 {
					http.Error(w, `{"error":{"message":"temporary"}}`, http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			exec := NewOpenAICompatExecutor("compat", &config.Config{})
			auth := &cliproxyauth.Auth{Provider: "compat", Attributes: map[string]string{"base_url": server.URL, "api_key": "key"}}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}
			payload := []byte(fmt.Sprintf(`{"model":%q,"input":"hello"}`, tt.model))
			if tt.name == "image" {
				opts.SourceFormat = sdktranslator.FromString("openai-image")
				payload = []byte(fmt.Sprintf(`{"model":%q,"prompt":"hello"}`, tt.model))
			}
			req := cliproxyexecutor.Request{Model: tt.model, Payload: payload}
			if _, err := exec.Execute(context.Background(), auth, req, opts); err == nil {
				t.Fatal("first attempt unexpectedly succeeded")
			}
			if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
				t.Fatalf("fallback attempt failed: %v", err)
			}
			if len(paths) != 2 || paths[0] != tt.wantPath || paths[1] != tt.wantPath {
				t.Fatalf("upstream paths = %#v, want two %s attempts", paths, tt.wantPath)
			}
		})
	}
}
