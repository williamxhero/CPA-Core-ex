package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func boundaryRequest(t *testing.T, f *inventoryHarness, driver *handlers.BaseAPIHandler, model string, stream bool, want int) (*httptest.ResponseRecorder, string) {
	t.Helper()
	a := sdkaccess.NewManager()
	a.SetProviders([]sdkaccess.Provider{schedulingHTTPAccess{}})
	h := openai.NewOpenAIResponsesAPIHandler(driver)
	engine := gin.New()
	engine.POST("/v1/responses", AuthMiddleware(a), h.Responses)
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[{"role":"user","content":"request-CANARY"}],"stream":%t}`, model, stream)))
	r.Header.Set("Authorization", "Bearer open")
	r.Header.Set("X-Request-ID", "spoof-CANARY")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("inference status=%d want=%d %s", w.Code, want, w.Body.String())
	}
	id := w.Header().Get("X-Request-ID")
	if parsed, err := uuid.Parse(id); err != nil || parsed.Version() != 7 {
		t.Fatalf("missing server-generated correlation: header=%q body=%s", id, w.Body)
	}
	raw := string(f.request("observability/routing/"+id, 200))
	if ojson.Get(raw, "request_id").String() != id || ojson.Get(raw, "model").String() != model || strings.Contains(raw, "CANARY") {
		t.Fatalf("correlation or redaction failed: %s", raw)
	}
	return w, raw
}

func TestProviderSchedulingHomeTracePublic(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Home.Enabled = true
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce", Models: []string{"capacity-gate-model"}}
			m.SetConfig(&cfg)
			var upstream string
			for _, a := range m.List() {
				if a.Attributes["api_key"] == "A" {
					upstream = a.Attributes["base_url"]
				}
			}
			if upstream == "" {
				t.Fatal("fixture has no upstream base URL")
			}
			dispatch := &budgetHomeDispatch{baseURL: upstream}
			m.PublishHomeDispatch(dispatch, executionregistry.New(), 1)
			_, raw := boundaryRequest(t, f.inventory, handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m), "capacity-gate-model", stream, http.StatusOK)
			if ojson.Get(raw, "stages.0.source").String() != "home" || ojson.Get(raw, "stages.0.coverage").String() != "partial" ||
				ojson.Get(raw, "stages.0.counts.selected").Int() != 1 || ojson.Get(raw, "stages.0.selected_resource_id").Exists() ||
				ojson.Get(raw, "stages.0.candidates.0.refresh.state").String() != "unknown" ||
				ojson.Get(raw, "send_count").Int() != 1 || ojson.Get(raw, "wait_ms").Int() != 0 || !stream && ojson.Get(raw, "terminal.code").String() != "succeeded" {
				t.Fatalf("missing Home dispatch or fabricated data: %s", raw)
			}
			f.mu.Lock()
			sends := strings.Join(f.attempts, ",")
			f.mu.Unlock()
			if dispatch.calls.Load() != 1 || sends != "A" {
				t.Fatalf("Home dispatches=%d actual upstream calls=%s", dispatch.calls.Load(), sends)
			}
		})
	}
}

type boundaryPlugin struct {
	*budgetNestedRouter
	calls atomic.Int32
	fail  bool
}

func (p *boundaryPlugin) ExecutePluginExecutor(ctx context.Context, id string, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	p.calls.Add(1)
	if p.fail {
		return coreexecutor.Response{}, &coreauth.Error{HTTPStatus: 429, Message: "raw-plugin-CANARY"}
	}
	if p.budgetNestedRouter.handler != nil {
		return p.budgetNestedRouter.ExecutePluginExecutor(ctx, id, req, opts)
	}
	return coreexecutor.Response{Payload: []byte(`{"id":"fixture","object":"response","output":[],"status":"completed"}`)}, nil
}

func (p *boundaryPlugin) ExecutePluginExecutorStream(context.Context, string, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	p.calls.Add(1)
	if p.fail {
		return nil, &coreauth.Error{HTTPStatus: 429, Message: "raw-plugin-CANARY"}
	}
	chunks := make(chan coreexecutor.StreamChunk, 1)
	chunks <- coreexecutor.StreamChunk{Payload: []byte("event: response.completed\ndata: " + combinedCapacitySuccess + "\n\n")}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func TestProviderSchedulingPluginTracePublic(t *testing.T) {
	for _, scenario := range []string{"direct", "nested", "denied", "denied-stream", "direct-stream", "failed", "failed-stream"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			denied := strings.HasPrefix(scenario, "denied")
			failed := strings.HasPrefix(scenario, "failed")
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce", Models: []string{"budget-bridge", "capacity-gate-model"}}
			if denied {
				cfg.Routing.ProviderScheduling.AllowedFunding = []string{"subscription"}
			}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, time.Second, 1)
			driver := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m)
			plugin := &boundaryPlugin{budgetNestedRouter: &budgetNestedRouter{}, fail: failed}
			if scenario == "nested" {
				plugin.budgetNestedRouter.handler = driver
			}
			driver.SetModelRouterHost(plugin)
			want := http.StatusOK
			if denied {
				want = http.StatusServiceUnavailable
			} else if failed {
				want = http.StatusTooManyRequests
			}
			w, raw := boundaryRequest(t, f.inventory, driver, "budget-bridge", strings.HasSuffix(scenario, "-stream"), want)
			stage := ojson.Get(raw, "stages.0").Raw
			if ojson.Get(stage, "source").String() != "plugin" || ojson.Get(stage, "coverage").String() != "partial" {
				t.Fatalf("missing opaque-plugin stage: %s", raw)
			}
			sends := int64(0)
			if scenario == "nested" {
				sends = 1
				if len(ojson.Get(raw, "stages").Array()) < 2 || ojson.Get(raw, "stages.1.model").String() != "budget-bridge" ||
					ojson.Get(raw, "terminal.code").String() != "succeeded" {
					t.Fatalf("nested provider did not use origin trace and terminal: %s", raw)
				}
			}
			if denied {
				if plugin.calls.Load() != 0 || ojson.Get(w.Body.String(), "error.code").String() != "no_available_route" ||
					ojson.Get(w.Body.String(), "error.request_id").String() != w.Header().Get("X-Request-ID") ||
					ojson.Get(stage, "reason").String() != "funding_ineligible" || ojson.Get(raw, "terminal.code").String() != "no_available_route" {
					t.Fatalf("unbound denial not correlated or entered plugin: body=%s trace=%s calls=%d", w.Body, raw, plugin.calls.Load())
				}
			} else if failed {
				if plugin.calls.Load() != 1 || ojson.Get(w.Body.String(), "error.code").String() != "external_executor_failed" ||
					ojson.Get(raw, "terminal.code").String() != "external_executor_failed" || w.Header().Get("Retry-After") != "" ||
					strings.Contains(w.Body.String(), "CANARY") || ojson.Get(stage, "transport_visibility").String() != "unknown" {
					t.Fatalf("opaque plugin status not safely attributed: body=%s trace=%s calls=%d", w.Body, raw, plugin.calls.Load())
				}
			} else if plugin.calls.Load() != 1 || ojson.Get(stage, "transport_visibility").String() != "unknown" ||
				ojson.Get(stage, "counts.selected").Int() != 1 || !strings.HasSuffix(scenario, "-stream") && ojson.Get(raw, "terminal.code").String() != "succeeded" {
				t.Fatalf("plugin dispatch not accurately recorded: trace=%s calls=%d", raw, plugin.calls.Load())
			}
			f.mu.Lock()
			actual := len(f.attempts)
			f.mu.Unlock()
			if ojson.Get(raw, "send_count").Int() != sends || int64(actual) != sends || ojson.Get(raw, "wait_ms").Int() != 0 {
				t.Fatalf("incorrect or duplicate send accounting: actual=%d trace=%s", actual, raw)
			}
		})
	}
}
