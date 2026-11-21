package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/gemini"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestProviderSchedulingGeminiStreamUsesCompatibleUpstream(t *testing.T) {
	const model = "scheduling-gemini-stream"
	const goodChunk = `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"compatible-output"}]},"finishReason":"STOP"}]}`
	for _, client := range []struct {
		name, path, body string
	}{
		{"native", "/v1beta/models/" + model + ":streamGenerateContent?alt=sse", `{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`},
		{"translated", "/v1/chat/completions", `{"model":"` + model + `","messages":[{"role":"user","content":"hello"}],"stream":true}`},
	} {
		for _, methods := range []struct {
			name string
			list []string
		}{
			{"generation_family", []string{"generateContent", "countTokens"}},
			{"stream_method", []string{"streamGenerateContent"}},
			{"unknown_methods", nil},
		} {
			t.Run(client.name+"/"+methods.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
				manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
				manager.SetConfig(cfg)
				manager.SetRetryConfig(0, 0, 0)
				manager.RegisterExecutor(runtimeexecutor.NewGeminiExecutor(cfg))

				var mu sync.Mutex
				var calls []string
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					key := r.Header.Get("x-goog-api-key")
					mu.Lock()
					calls = append(calls, key)
					mu.Unlock()
					if !strings.HasSuffix(r.URL.Path, "/models/"+model+":streamGenerateContent") {
						t.Errorf("unexpected upstream method: %s %s", r.Method, r.URL)
					}
					if key == "count-only" {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"error":{"code":400,"message":"generation unsupported"}}`)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: %s\n\n", goodChunk)
				}))
				t.Cleanup(target.Close)

				addRoute := func(id, priority string, generationMethods []string) {
					t.Helper()
					if _, err := manager.Register(context.Background(), &coreauth.Auth{
						ID: id, Provider: "gemini", Status: coreauth.StatusActive,
						Attributes: map[string]string{"api_key": id, "base_url": target.URL, "priority": priority},
					}); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(id, "gemini", []*registry.ModelInfo{{
						ID: model, SupportedGenerationMethods: generationMethods,
					}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				}
				addRoute("count-only", "20", []string{"countTokens"})
				addRoute("generation", "10", methods.list)

				app := gin.New()
				base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
				app.POST("/v1beta/models/*action", gemini.NewGeminiAPIHandler(base).GeminiHandler)
				app.POST("/v1/chat/completions", openai.NewOpenAIAPIHandler(base).ChatCompletions)
				req := httptest.NewRequest(http.MethodPost, client.path, strings.NewReader(client.body))
				req.Header.Set("Content-Type", "application/json")
				res := httptest.NewRecorder()
				app.ServeHTTP(res, req)

				mu.Lock()
				defer mu.Unlock()
				if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "compatible-output") || strings.Join(calls, ",") != "generation" {
					t.Fatalf("expected a streaming response and only the compatible upstream, got status=%d body=%s calls=%v", res.Code, res.Body, calls)
				}
			})
		}
	}
}

func TestProviderSchedulingGeminiStreamAcceptsCompatibleOpenAIUpstream(t *testing.T) {
	const model = "scheduling-gemini-translated-out"
	const chunk = `{"id":"test","object":"chat.completion.chunk","model":"scheduling-gemini-translated-out","choices":[{"index":0,"delta":{"role":"assistant","content":"translated-output"},"finish_reason":"stop"}]}`
	var mu sync.Mutex
	var requestedPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPath = r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", chunk)
	}))
	t.Cleanup(target.Close)
	cfg := &config.Config{}
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor("openai-compatibility", cfg))
	const id = "compat-gemini-stream"
	if _, err := manager.Register(t.Context(), &coreauth.Auth{
		ID: id, Provider: "openai-compatibility", Status: coreauth.StatusActive,
		Attributes: map[string]string{"api_key": id, "base_url": target.URL + "/v1", "compat_name": "openai-compatibility"},
	}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "openai-compatibility", []*registry.ModelInfo{{
		ID: model, SupportedGenerationMethods: []string{"chat.completions"},
	}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })

	app := gin.New()
	base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
	app.POST("/v1beta/models/*action", gemini.NewGeminiAPIHandler(base).GeminiHandler)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/"+model+":streamGenerateContent?alt=sse", strings.NewReader(`{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	app.ServeHTTP(res, req)

	mu.Lock()
	defer mu.Unlock()
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "translated-output") || requestedPath != "/v1/chat/completions" {
		t.Fatalf("expected an OpenAI-backed Gemini stream, got status=%d body=%s upstream path=%q", res.Code, res.Body, requestedPath)
	}
}
