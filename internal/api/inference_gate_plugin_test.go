package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

// This opt-in test loads the actual published-SDK-compatible debug DLL. It is
// deliberately skipped without an explicit controlled artifact, never faked.
func TestInferenceGateCompiledOpenCode(t *testing.T) {
	pluginDir := os.Getenv("GATE_TEST_PLUGIN_DIR")
	if pluginDir == "" {
		t.Skip("explicit isolated compiled-plugin directory required")
	}
	var aSends, bSends atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gate-test-counts" {
			json.NewEncoder(w).Encode(map[string]int32{"A": aSends.Load(), "B": bSends.Load()})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/models") {
			fmt.Fprint(w, `{"data":[{"id":"glm-5.2"}]}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected controlled plugin path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer SYNTHETIC-A":
			aSends.Add(1)
		case "Bearer SYNTHETIC-B":
			bSends.Add(1)
		default:
			t.Error("unattributed plugin request")
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Stream bool `json:"stream"`
		}
		json.Unmarshal(body, &req)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"id":"x","object":"chat.completion","model":"glm-5.2","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	os.MkdirAll(authDir, 0700)
	for _, key := range []string{"A", "B"} {
		os.WriteFile(filepath.Join(authDir, key+".json"), []byte(fmt.Sprintf(`{"type":"opencode-go","api_key":"SYNTHETIC-%s","base_url":%q}`, key, upstream.URL+"/v1")), 0600)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    opencode-go-cliproxyapi:\n      enabled: true\n      allow-http: true\n      base-url: %q\n      api-keys: [{name: a, value: SYNTHETIC-A}, {name: b, value: SYNTHETIC-B}]\n", filepath.ToSlash(authDir), filepath.ToSlash(pluginDir), upstream.URL+"/v1")
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(text), 0600)
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	host.ApplyConfig(context.Background(), cfg)
	defer host.ShutdownAll()
	if !host.HasQuotaProviderForPlugin("opencode-go-cliproxyapi") {
		t.Fatal("actual DLL not loaded")
	}
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	f := newInventoryHarness(t, dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	f.manager.SetConfig(f.server.cfg)
	host.RegisterModels(context.Background(), registry.GetGlobalRegistry())
	host.RegisterExecutors(f.manager, registry.GetGlobalRegistry())
	for _, a := range f.manager.List() {
		result := host.ModelsForAuth(context.Background(), a)
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if len(result.Models) == 0 {
			t.Fatal("compiled plugin did not expose real source models")
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, result.Models)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	if err = f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	var sources struct {
		Sources []map[string]any `json:"sources"`
	}
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	if source == nil {
		t.Fatal("actual host source association missing")
	}
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	rh := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.GET("/v1/responses", rh.ResponsesWebsocket)
	downstream := httptest.NewServer(f.server.engine)
	defer downstream.Close()
	send := func(stream bool) {
		t.Helper()
		r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"opencode-go/glm-5.2","messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, stream)))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("actual plugin route status=%d body=%s", r.StatusCode, b)
		}
	}
	send(false)
	send(true)
	wsTurn := gateWSTurns(t, downstream.URL, "opencode-go/glm-5.2")
	wsTurn()
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	gatePost(t, f, gateOp(source, 0, "2c4fca80-a4a9-4557-832d-4f3298d72d1e", "credential-auto/v1/8b7ab885-790a-43dd-8096-f71c07d9e37e", "pause"), 200)
	before := aSends.Load()
	send(false)
	send(true)
	wsTurn()
	if aSends.Load() != before || bSends.Load() == 0 {
		t.Fatalf("compiled source gate/failover violated A=%d->%d B=%d", before, aSends.Load(), bSends.Load())
	}
	runGatePluginSmoke(t, os.Getenv("GATE_TEST_SMOKE_OPENCODE_DIR"), downstream.URL, upstream.URL, source["auth_index"].(string), "opencode-go/glm-5.2", "2c4fca80-a4a9-4557-832d-4f3298d72d1e")
}

func TestInferenceGateCompiledQwen(t *testing.T) {
	pluginDir := os.Getenv("GATE_TEST_PLUGIN_DIR")
	if pluginDir == "" {
		t.Skip("explicit isolated compiled-plugin directory required")
	}
	var aSends, bSends atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gate-test-counts" {
			json.NewEncoder(w).Encode(map[string]int32{"A": aSends.Load(), "B": bSends.Load()})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/models") {
			fmt.Fprint(w, `{"data":[{"id":"qwen3.8-max"}]}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected controlled plugin path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer SYNTHETIC-A":
			aSends.Add(1)
		case "Bearer SYNTHETIC-B":
			bSends.Add(1)
		default:
			t.Error("unattributed plugin request")
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Stream bool `json:"stream"`
		}
		json.Unmarshal(body, &req)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"id":"x","object":"chat.completion","model":"qwen3.8-max","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	os.MkdirAll(authDir, 0700)
	for _, key := range []string{"A", "B"} {
		os.WriteFile(filepath.Join(authDir, key+".json"), []byte(fmt.Sprintf(`{"type":"qwen","api_key":"SYNTHETIC-%s"}`, key)), 0600)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      allow-http: true\n      command: quota-stub\n      base-url: %q\n      api-keys: [{name: a, value: SYNTHETIC-A}, {name: b, value: SYNTHETIC-B}]\n", filepath.ToSlash(authDir), filepath.ToSlash(pluginDir), upstream.URL+"/v1")
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(text), 0600)
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	host.ApplyConfig(context.Background(), cfg)
	defer host.ShutdownAll()
	if !host.HasQuotaProviderForPlugin("qwen-cliproxyapi") {
		t.Fatal("actual DLL not loaded")
	}
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	f := newInventoryHarness(t, dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	f.manager.SetConfig(f.server.cfg)
	host.RegisterModels(context.Background(), registry.GetGlobalRegistry())
	host.RegisterExecutors(f.manager, registry.GetGlobalRegistry())
	for _, a := range f.manager.List() {
		result := host.ModelsForAuth(context.Background(), a)
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if len(result.Models) == 0 {
			t.Fatal("compiled plugin did not expose real source models")
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, result.Models)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	if err = f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	var sources struct {
		Sources []map[string]any `json:"sources"`
	}
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	if source == nil {
		t.Fatal("actual host source association missing")
	}
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	rh := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.GET("/v1/responses", rh.ResponsesWebsocket)
	downstream := httptest.NewServer(f.server.engine)
	defer downstream.Close()
	send := func(stream bool) {
		t.Helper()
		r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"qwen3.8-max","messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, stream)))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("actual plugin route status=%d body=%s", r.StatusCode, b)
		}
	}
	send(false)
	send(true)
	wsTurn := gateWSTurns(t, downstream.URL, "qwen3.8-max")
	wsTurn()
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	gatePost(t, f, gateOp(source, 0, "2c4fca80-a4a9-4557-832d-4f3298d72d1e", "credential-auto/v1/8b7ab885-790a-43dd-8096-f71c07d9e37e", "pause"), 200)
	before := aSends.Load()
	send(false)
	send(true)
	wsTurn()
	if aSends.Load() != before || bSends.Load() == 0 {
		t.Fatalf("compiled source gate/failover violated A=%d->%d B=%d", before, aSends.Load(), bSends.Load())
	}
	runGatePluginSmoke(t, os.Getenv("GATE_TEST_SMOKE_QWEN_DIR"), downstream.URL, upstream.URL, source["auth_index"].(string), "qwen3.8-max", "2c4fca80-a4a9-4557-832d-4f3298d72d1e")
}

func TestInferenceGateCompiledQwenNativeWrapper(t *testing.T) {
	pluginDir := os.Getenv("GATE_TEST_PLUGIN_DIR")
	if pluginDir == "" {
		t.Skip("explicit isolated compiled-plugin directory required")
	}
	var aSends, bSends atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gate-test-counts" {
			json.NewEncoder(w).Encode(map[string]int32{"A": aSends.Load(), "B": bSends.Load()})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/models") {
			fmt.Fprint(w, `{"data":[{"id":"qwen3.8-max"}]}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected controlled plugin path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer SYNTHETIC-A":
			aSends.Add(1)
		case "Bearer SYNTHETIC-B":
			bSends.Add(1)
		default:
			t.Error("unattributed plugin request")
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Stream bool `json:"stream"`
		}
		json.Unmarshal(body, &req)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"id":"x","object":"chat.completion","model":"qwen3.8-max","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	os.MkdirAll(authDir, 0700)
	for _, key := range []string{"A", "B"} {
		os.WriteFile(filepath.Join(authDir, key+".json"), []byte(fmt.Sprintf(`{"type":"qwen","api_key":"SYNTHETIC-%s","base_url":%q}`, key, upstream.URL+"/v1")), 0600)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      allow-http: true\n      command: quota-stub\n      base-url: %q\n      api-keys: [{name: a, value: SYNTHETIC-A}, {name: b, value: SYNTHETIC-B}]\n", filepath.ToSlash(authDir), filepath.ToSlash(pluginDir), upstream.URL+"/v1")
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(text), 0600)
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	host.ApplyConfig(context.Background(), cfg)
	defer host.ShutdownAll()
	if !host.HasQuotaProviderForPlugin("qwen-cliproxyapi") {
		t.Fatal("actual DLL not loaded")
	}
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	f := newInventoryHarness(t, dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	f.manager.SetConfig(f.server.cfg)
	host.RegisterModels(context.Background(), registry.GetGlobalRegistry())
	host.RegisterExecutors(f.manager, registry.GetGlobalRegistry())
	for _, a := range f.manager.List() {
		f.manager.RegisterExecutor(pluginhost.NewPluginRefreshCompatExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg), host, f.server.cfg))
		result := host.ModelsForAuth(context.Background(), a)
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if len(result.Models) == 0 {
			t.Fatal("compiled plugin did not expose real source models")
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, result.Models)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	if err = f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	var sources struct {
		Sources []map[string]any `json:"sources"`
	}
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	if source == nil {
		t.Fatal("actual host source association missing")
	}
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	rh := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.GET("/v1/responses", rh.ResponsesWebsocket)
	downstream := httptest.NewServer(f.server.engine)
	defer downstream.Close()
	send := func(stream bool) {
		t.Helper()
		r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"qwen3.8-max","messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, stream)))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("actual plugin route status=%d body=%s", r.StatusCode, b)
		}
	}
	send(false)
	send(true)
	wsTurn := gateWSTurns(t, downstream.URL, "qwen3.8-max")
	wsTurn()
	json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s["auth_index"] && a.Attributes["api_key"] == "SYNTHETIC-A" {
				source = s
			}
		}
	}
	gatePost(t, f, gateOp(source, 0, "2c4fca80-a4a9-4557-832d-4f3298d72d1e", "credential-auto/v1/8b7ab885-790a-43dd-8096-f71c07d9e37e", "pause"), 200)
	before := aSends.Load()
	send(false)
	send(true)
	wsTurn()
	if aSends.Load() != before || bSends.Load() == 0 {
		t.Fatalf("compiled source gate/failover violated A=%d->%d B=%d", before, aSends.Load(), bSends.Load())
	}
	runGatePluginSmoke(t, os.Getenv("GATE_TEST_SMOKE_QWEN_DIR"), downstream.URL, upstream.URL, source["auth_index"].(string), "qwen3.8-max", "2c4fca80-a4a9-4557-832d-4f3298d72d1e")
}

func runGatePluginSmoke(t *testing.T, dir, base, upstream, index, model, op string) {
	t.Helper()
	if dir == "" {
		return
	}
	cmd := exec.Command("go", "test", "-tags", "debug,live", "./tests/...", "-run", "^TestLiveControlledInferenceGate$", "-count=1", "-timeout", "30s")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CPA_GATE_CONTROLLED_BASE="+base, "CPA_GATE_CONTROLLED_COUNTS="+upstream+"/gate-test-counts", "CPA_GATE_CONTROLLED_KEY=test-password", "CPA_GATE_CONTROLLED_INDEX="+index, "CPA_GATE_CONTROLLED_MODEL="+model, "CPA_GATE_CONTROLLED_OP="+op)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("controlled canonical plugin live smoke: %v\n%s", err, out)
	}
	t.Logf("controlled canonical plugin live smoke: %s", out)
}
