package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const bridgePluginID = "scheduling-bridge-fixture"
const bridgeModel = "scheduling-bridge-model"
const bridgeBoundModel = "scheduling-bridge-bound-model"
const bridgeResponse = `{"id":"bridge-fixture","object":"response","output":[],"status":"completed"}`

type schedulingHTTPBridgePlugin struct {
	send func(context.Context, pluginapi.ExecutorRequest) ([]byte, error)
}

func (*schedulingHTTPBridgePlugin) Identifier() string { return bridgePluginID }

func (*schedulingHTTPBridgePlugin) RouteModel(_ context.Context, req pluginapi.ModelRouteRequest) (pluginapi.ModelRouteResponse, error) {
	if req.RequestedModel != bridgeModel {
		return pluginapi.ModelRouteResponse{}, nil
	}
	return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetSelf}, nil
}

func (p *schedulingHTTPBridgePlugin) Execute(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	body, err := p.send(ctx, req)
	return pluginapi.ExecutorResponse{Payload: body}, err
}

func (p *schedulingHTTPBridgePlugin) ExecuteStream(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	body, err := p.send(ctx, req)
	if err != nil {
		return pluginapi.ExecutorStreamResponse{}, err
	}
	chunks := make(chan pluginapi.ExecutorStreamChunk, 1)
	chunks <- pluginapi.ExecutorStreamChunk{Payload: body}
	close(chunks)
	return pluginapi.ExecutorStreamResponse{Chunks: chunks}, nil
}

func (*schedulingHTTPBridgePlugin) CountTokens(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	return pluginapi.ExecutorResponse{}, nil
}

func (*schedulingHTTPBridgePlugin) HttpRequest(context.Context, pluginapi.ExecutorHTTPRequest) (pluginapi.ExecutorHTTPResponse, error) {
	return pluginapi.ExecutorHTTPResponse{}, nil
}

func TestProviderSchedulingPluginHTTPBridgeCountsOneSend(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			var actual atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual.Add(1)
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":"+bridgeResponse+"}\n\n")
				} else {
					fmt.Fprint(w, bridgeResponse)
				}
			}))
			t.Cleanup(upstream.Close)
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, time.Second, 1)
			driver := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m)
			plugin := &schedulingHTTPBridgePlugin{send: func(ctx context.Context, req pluginapi.ExecutorRequest) ([]byte, error) {
				resp, err := req.HTTPClient.Do(ctx, pluginapi.HTTPRequest{Method: http.MethodPost, URL: upstream.URL, Body: req.Payload})
				return resp.Body, err
			}}
			registerSchedulingHTTPBridge(t, m, driver, plugin, false)
			_, raw := boundaryRequest(t, f.inventory, driver, bridgeModel, stream, http.StatusOK)
			if actual.Load() != 1 || ojson.Get(raw, "send_count").Int() != 1 || ojson.Get(raw, "round_sends").Int() != 1 {
				t.Fatalf("wire sends=%d, trace=%s; want one send in this round", actual.Load(), raw)
			}
		})
	}
}

func registerSchedulingHTTPBridge(t *testing.T, m *coreauth.Manager, driver *handlers.BaseAPIHandler, plugin *schedulingHTTPBridgePlugin, bind bool) {
	t.Helper()
	host := pluginhost.New()
	host.RegisterPluginForTest(bridgePluginID, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{
		ModelRouter: plugin, Executor: plugin,
		ExecutorInputFormats: []string{"openai-response"}, ExecutorOutputFormats: []string{"openai-response"},
	}})
	driver.SetModelRouterHost(host)
	if !bind {
		return
	}
	catalog := registry.GetGlobalRegistry()
	host.RegisterExecutors(m, catalog)
	auth, errRegister := m.Register(coreauth.WithSkipPersist(t.Context()), &coreauth.Auth{
		ID: bridgePluginID + "-credential", Provider: bridgePluginID, Status: coreauth.StatusActive,
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	catalog.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: bridgeBoundModel}})
	t.Cleanup(func() { catalog.UnregisterClient(auth.ID) })
}

func schedulingHTTPBridgeRequest(t *testing.T, f *inventoryHarness, driver *handlers.BaseAPIHandler, payload string, wantStatus int) string {
	t.Helper()
	access := sdkaccess.NewManager()
	access.SetProviders([]sdkaccess.Provider{schedulingHTTPAccess{}})
	engine := gin.New()
	engine.POST("/v1/responses", AuthMiddleware(access), openai.NewOpenAIResponsesAPIHandler(driver).Responses)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer open")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Errorf("status=%d want=%d: %s", rec.Code, wantStatus, rec.Body)
	}
	return readSchedulingTraceForTest(t, f, rec.Header().Get("X-Request-ID"))
}

func TestProviderSchedulingPluginHTTPBridgeHostedToolSendsOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		model   string
		profile *pluginapi.HTTPWireProfile
	}{
		{name: "credential-default", model: bridgeBoundModel},
		{name: "credential-profile", model: bridgeBoundModel, profile: &pluginapi.HTTPWireProfile{HTTP1Only: true}},
		{name: "direct-default", model: bridgeModel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var actual atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual.Add(1)
				if r.Method != http.MethodPost {
					t.Errorf("upstream method=%s; want POST", r.Method)
				}
				fmt.Fprint(w, bridgeResponse)
			}))
			t.Cleanup(upstream.Close)

			f := newInventoryHarness(t, t.TempDir())
			m := f.manager
			cfg := *f.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, time.Second, 1)
			driver := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m)
			plugin := &schedulingHTTPBridgePlugin{send: func(ctx context.Context, req pluginapi.ExecutorRequest) ([]byte, error) {
				httpReq := pluginapi.HTTPRequest{Method: http.MethodPost, URL: upstream.URL, Body: req.Payload, WireProfile: tc.profile}
				resp, errFirst := req.HTTPClient.Do(ctx, httpReq)
				if errFirst != nil {
					return nil, errFirst
				}
				if _, errRepeat := req.HTTPClient.Do(ctx, httpReq); errRepeat == nil {
					t.Error("host bridge allowed the hosted tool request to replay")
				}
				return resp.Body, nil
			}}
			registerSchedulingHTTPBridge(t, m, driver, plugin, tc.model == bridgeBoundModel)
			payload := fmt.Sprintf(`{"model":%q,"input":[],"tools":[{"type":"web_search"}]}`, tc.model)
			raw := schedulingHTTPBridgeRequest(t, f, driver, payload, http.StatusOK)
			if actual.Load() != 1 || ojson.Get(raw, "send_count").Int() != 1 || !ojson.Get(raw, "replay_unsafe").Bool() {
				t.Fatalf("wire sends=%d trace=%s; want one send and replay protection", actual.Load(), raw)
			}
		})
	}
}

func TestProviderSchedulingPluginHTTPBridgeSharesRouteCap(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cap         int
		nestedFirst bool
		directSends int32
		nativeSends int
		wantStatus  int
	}{
		{name: "one-slot-direct-first", cap: 1, directSends: 1, wantStatus: http.StatusServiceUnavailable},
		{name: "one-slot-nested-first", cap: 1, nestedFirst: true, nativeSends: 1, wantStatus: http.StatusServiceUnavailable},
		{name: "two-slots", cap: 2, nestedFirst: true, directSends: 1, nativeSends: 1, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var actual atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual.Add(1)
				fmt.Fprint(w, bridgeResponse)
			}))
			t.Cleanup(upstream.Close)
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, time.Second, tc.cap)
			driver := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m)
			plugin := &schedulingHTTPBridgePlugin{send: func(ctx context.Context, req pluginapi.ExecutorRequest) ([]byte, error) {
				nested := func() error {
					_, errModel := driver.ExecuteModel(ctx, handlers.ModelExecutionRequest{
						EntryProtocol: "openai-response", ExitProtocol: "openai-response", Model: "capacity-gate-model",
						Body: []byte(`{"model":"capacity-gate-model","input":[]}`), SkipRouterPluginID: bridgePluginID,
					})
					if errModel != nil {
						return errModel.Error
					}
					return nil
				}
				if tc.nestedFirst {
					if errNested := nested(); errNested != nil {
						return nil, errNested
					}
				}
				resp, errSend := req.HTTPClient.Do(ctx, pluginapi.HTTPRequest{Method: http.MethodPost, URL: upstream.URL, Body: req.Payload})
				if errSend != nil {
					return nil, errSend
				}
				if !tc.nestedFirst {
					if errNested := nested(); errNested != nil {
						return nil, errNested
					}
				}
				return resp.Body, nil
			}}
			registerSchedulingHTTPBridge(t, m, driver, plugin, false)
			_, raw := boundaryRequest(t, f.inventory, driver, bridgeModel, false, tc.wantStatus)
			f.mu.Lock()
			nativeSends := len(f.attempts)
			f.mu.Unlock()
			want := int64(tc.directSends) + int64(tc.nativeSends)
			if actual.Load() != tc.directSends || nativeSends != tc.nativeSends ||
				ojson.Get(raw, "send_count").Int() != want || ojson.Get(raw, "round_sends").Int() != want ||
				ojson.Get(raw, "round").Int() != 0 || ojson.Get(raw, "wait_ms").Int() != 0 {
				t.Fatalf("host wire sends=%d, nested wire sends=%d, trace=%s; want host=%d nested=%d in the same round",
					actual.Load(), nativeSends, raw, tc.directSends, tc.nativeSends)
			}
		})
	}
}

func TestProviderSchedulingPluginHTTPBridgeOpaqueTransportIsUnknown(t *testing.T) {
	var actual atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual.Add(1)
		fmt.Fprint(w, bridgeResponse)
	}))
	t.Cleanup(upstream.Close)
	f := newInventoryHarness(t, t.TempDir())
	m := f.manager
	cfg := *f.server.cfg
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	m.SetConfig(&cfg)
	driver := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m)
	plugin := &schedulingHTTPBridgePlugin{send: func(ctx context.Context, req pluginapi.ExecutorRequest) ([]byte, error) {
		reqHTTP, errNew := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, strings.NewReader(string(req.Payload)))
		if errNew != nil {
			return nil, errNew
		}
		resp, errDo := upstream.Client().Do(reqHTTP)
		if errDo != nil {
			return nil, errDo
		}
		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				t.Error(errClose)
			}
		}()
		return io.ReadAll(resp.Body)
	}}
	registerSchedulingHTTPBridge(t, m, driver, plugin, false)
	_, raw := boundaryRequest(t, f, driver, bridgeModel, false, http.StatusOK)
	if actual.Load() != 1 || ojson.Get(raw, "send_count").Int() != 0 ||
		ojson.Get(raw, "stages.0.transport_visibility").String() != "unknown" {
		t.Fatalf("host invented visibility into independent plugin traffic: wire=%d trace=%s", actual.Load(), raw)
	}
}
