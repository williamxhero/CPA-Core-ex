package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
)

// Only the explicitly selected isolated process fixture calls this helper.
// It installs real native executors/routes, never a gate result or selection fake.
func installExternalInferenceGateRoutes(t *testing.T, f *inventoryHarness, roots *x509.CertPool, endpoint, serverName, model string) {
	t.Helper()
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || !net.ParseIP(host).IsLoopback() || serverName == "" || model == "" {
		t.Fatal("controlled native fixture requires loopback TLS endpoint, verified name and synthetic model")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}}
	previous := http.DefaultTransport
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = previous; tr.CloseIdleConnections() })
	f.manager.SetConfig(f.server.cfg)
	f.manager.SetRoundTripperProvider(gateFixedTransport{tr})
	for _, a := range f.manager.List() {
		if a.SourcePluginID != "" {
			continue
		}
		ws, _ := strconv.ParseBool(a.Attributes["websockets"])
		metadataWS, _ := a.Metadata["websockets"].(bool)
		metadataText, _ := a.Metadata["websockets"].(string)
		metadataParsed, _ := strconv.ParseBool(metadataText)
		if ws || metadataWS || metadataParsed {
			t.Fatal("native external fixture cannot isolate direct upstream WS; use dedicated WS fixture")
		}
		switch a.Provider {
		case "codex":
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(f.server.cfg))
		case "claude":
			f.manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(f.server.cfg))
		default:
			if a.Attributes["compat_name"] == "" {
				continue
			}
			f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	base := handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager)
	chat := openai.NewOpenAIAPIHandler(base)
	responses := openai.NewOpenAIResponsesAPIHandler(base)
	f.server.engine.POST("/v1/chat/completions", chat.ChatCompletions)
	f.server.engine.POST("/v1/responses", responses.Responses)
	f.server.engine.GET("/v1/responses", responses.ResponsesWebsocket)
}

func maybeInstallExternalInferenceGateRoutes(t *testing.T, f *inventoryHarness, roots *x509.CertPool, endpoint, address string) {
	if os.Getenv("GATE_FIXTURE_ROUTES") != "1" {
		return
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("gate process fixture must listen on literal loopback")
	}
	name, model := os.Getenv("GATE_FIXTURE_TLS_SERVER_NAME"), os.Getenv("GATE_FIXTURE_MODEL")
	if name == "" || model == "" {
		t.Fatal("explicit GATE_FIXTURE_TLS_SERVER_NAME and GATE_FIXTURE_MODEL required")
	}
	installExternalInferenceGateRoutes(t, f, roots, endpoint, name, model)
}

func TestInferenceGateExternalFixtureUsesRealNativeHTTPAndDownstreamWS(t *testing.T) {
	var aSends, bSends atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/responses") {
			t.Error("unexpected native business endpoint")
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") == "Bearer synthetic-A" {
			aSends.Add(1)
		} else if r.Header.Get("Authorization") == "Bearer synthetic-B" {
			bSends.Add(1)
		} else {
			t.Error("unattributed native source")
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[]}}\n\n")
	}))
	defer upstream.Close()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	f := newInventoryHarness(t, t.TempDir())
	installExternalInferenceGateRoutes(t, f, roots, upstream.Listener.Addr().String(), upstream.Certificate().DNSNames[0], "gate-model")
	source := gateSource(t, f)
	var key string
	for _, a := range f.manager.List() {
		if a.Index == source["auth_index"] {
			key = a.Attributes["api_key"]
		}
	}
	f.manager.SetSelector(&gatePreferASelector{key: key})
	downstream := httptest.NewServer(f.server.engine)
	defer downstream.Close()
	client := &http.Client{Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	send := func(stream bool) {
		t.Helper()
		payload := `{"model":"gate-model","input":[],"stream":false}`
		if stream {
			payload = `{"model":"gate-model","input":[],"stream":true}`
		}
		r, err := client.Post(downstream.URL+"/v1/responses", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("native fixture status=%d", r.StatusCode)
		}
	}
	send(false)
	wsTurn := gateWSTurns(t, downstream.URL, "gate-model")
	wsTurn()
	gatePost(t, f, gateOp(source, 0, "d0704f85-3f6a-4392-a620-af38325f0a96", "owner-a", "pause"), 200)
	aBefore, bBefore := aSends.Load(), bSends.Load()
	send(false)
	send(true)
	wsTurn()
	if key == "synthetic-A" {
		if aSends.Load() != aBefore || bSends.Load() != bBefore+3 {
			t.Fatal("native fixture pause bypass/failover")
		}
	} else {
		if bSends.Load() != bBefore || aSends.Load() != aBefore+3 {
			t.Fatal("native fixture pause bypass/failover")
		}
	}
}
