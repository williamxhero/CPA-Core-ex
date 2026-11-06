package pluginhost_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type identityCallbackProvider struct {
	call     func(context.Context, string, []byte) ([]byte, error)
	runs     int
	filename string
	body     json.RawMessage
}

func (p *identityCallbackProvider) Identifier() string { return "qwen" }
func (p *identityCallbackProvider) ParseAuth(_ context.Context, req pluginapi.AuthParseRequest) (pluginapi.AuthParseResponse, error) {
	return pluginapi.AuthParseResponse{Handled: true, Auth: pluginapi.AuthData{ID: req.FileName, Provider: "qwen", StorageJSON: req.RawJSON, Attributes: map[string]string{coreauth.AttributeResourceID: "forged-plugin-marker"}}}, nil
}
func (p *identityCallbackProvider) StartLogin(ctx context.Context, _ pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	body, _ := json.Marshal(pluginapi.HostAuthSaveRequest{Name: p.filename, JSON: p.body})
	if _, err := p.call(ctx, pluginabi.MethodHostAuthSave, body); err != nil {
		return pluginapi.AuthLoginStartResponse{}, err
	}
	p.runs++
	return pluginapi.AuthLoginStartResponse{State: fmt.Sprintf("identity-fixture-state-%d", p.runs), URL: "https://synthetic.invalid/authorize"}, nil
}
func (*identityCallbackProvider) PollLogin(context.Context, pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}, nil
}
func (*identityCallbackProvider) RefreshAuth(_ context.Context, req pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
	return pluginapi.AuthRefreshResponse{Auth: pluginapi.AuthData{Provider: "qwen", ID: req.AuthID, StorageJSON: req.StorageJSON}}, nil
}

func TestResourceIdentityHostSaveThroughManagementHTTP(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	source := []byte(fmt.Sprintf("server: {port: 8317}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nplugins:\n  enabled: true\n  configs:\n    cpa-credential-qwen:\n      enabled: true\n      api-keys: [{name: fixture, value: fixture-key}]\n", filepath.ToSlash(authDir)))
	if err := os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(source)
	if err != nil {
		t.Fatal(err)
	}
	store := sdkAuth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	host := pluginhost.New()
	host.SetAuthManager(manager)
	p := &identityCallbackProvider{call: pluginhost.IdentityCallbackFixture(host, cfg), filename: "qwen.json", body: json.RawMessage(`{"type":"qwen","api_key":"fixture-key","disabled":true}`)}
	host.RegisterPluginForTest("cpa-credential-qwen", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: p}})
	h := management.NewHandler(cfg, path, manager)
	h.SetLocalPassword("test-password")
	h.SetPluginHost(host)
	defer func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	}()
	engine := gin.New()
	group := engine.Group("/v8/management")
	group.Use(h.Middleware())
	group.POST("/oauth/auth-url", h.StartOAuthV8)
	group.GET("/resources", h.Resources)
	group.GET("/resource-bindings", h.ResourceBindings)
	group.GET("/credentials", h.ListAuthFiles)
	request := func(method, route, body string, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(method, "/v8/management/"+route, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: %d %s", route, rec.Code, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	request("POST", "oauth/auth-url", `{"provider":"qwen"}`, 200)
	state := fmt.Sprintf("identity-fixture-state-%d", p.runs)
	t.Cleanup(func() { management.CancelOAuthSession(state) })
	var view struct{ Bindings []resource.Binding }
	if err = json.Unmarshal(request("GET", "resource-bindings", "", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Bindings) != 1 || len(view.Bindings[0].Targets) != 2 {
		t.Fatal("callback ACK preceded source enrollment/runtime binding")
	}
	id := view.Bindings[0].Targets[0].ResourceID
	// A plugin rewriting its envelope without host metadata must retain the marker
	// and inherited manual disablement, without being treated as an external copy.
	p.body = json.RawMessage(`{"type":"qwen","api_key":"fixture-key","label":"renamed"}`)
	request("POST", "oauth/auth-url", `{"provider":"qwen"}`, 200)
	state2 := fmt.Sprintf("identity-fixture-state-%d", p.runs)
	t.Cleanup(func() { management.CancelOAuthSession(state2) })
	var snapshot resource.Snapshot
	if err = json.Unmarshal(request("GET", "resources", "", 200), &snapshot); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range snapshot.Resources {
		if r.ResourceID == id {
			found = true
			if r.Identity != "valid" || !r.Manual.Disabled {
				t.Fatal("callback lost marker/manual state")
			}
		}
	}
	if !found {
		t.Fatal("callback replaced durable identity")
	}
	// A provider-family replacement cannot reuse the old issued file identity.
	p.body = json.RawMessage(`{"type":"codex","api_key":"fixture-key"}`)
	request("POST", "oauth/auth-url", `{"provider":"qwen"}`, 500)
	var unchanged resource.Snapshot
	if err = json.Unmarshal(request("GET", "resources", "", 200), &unchanged); err != nil {
		t.Fatal(err)
	}
	for _, r := range unchanged.Resources {
		if r.ResourceID == id && (r.Family != "qwen" || r.Identity != "valid") {
			t.Fatal("family replacement modified issued source")
		}
	}
	p.body = json.RawMessage(`{"type":"qwen","api_key":"fixture-key"}`)
	// Publication failure must not publish another runtime auth or acknowledge save.
	if err = os.Remove(filepath.Join(dir, ".resource-catalog", "seal.key")); err != nil {
		t.Fatal(err)
	}
	p.filename = "not-published.json"
	request("POST", "oauth/auth-url", `{"provider":"qwen"}`, 500)
	if strings.Contains(string(request("GET", "credentials", "", 200)), "not-published") {
		t.Fatal("failed publication registered runtime auth")
	}
	request("GET", "resource-bindings", "", 503)
}
