package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

func pluginInventoryFixture(t *testing.T) (*inventoryHarness, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	t.Cleanup(trap.Close)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: native-canary, base-url: https://native.invalid/v1, keys: [{api-key: native-secret-canary}]}]\nplugins:\n  enabled: true\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      base-url: %q\n      api-keys: [{name: qwen-label-canary, value: qwen-secret-canary}]\n    opencode-go-cliproxyapi:\n      enabled: false\n      base-url: %q\n      api-keys: [{name: opencode-label-canary, value: opencode-secret-canary}]\n    example: {enabled: true, config1: ignored-secret-canary}\n", filepath.ToSlash(authDir), trap.URL, trap.URL)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"qwen.json": `{"type":"qwen","api_key":"qwen-secret-canary"}`, "opencode.json": `{"type":"opencode-go","api_key":"opencode-secret-canary","disabled":true}`, "panel.json": `{"type":"qwen","api_key":"panel-secret-canary","base_url":"https://panel.invalid/v1"}`, "native.json": `{"type":"codex","access_token":"token-secret-canary"}`} {
		if err := os.WriteFile(filepath.Join(authDir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	host := identityTestHost()
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	f := newInventoryHarness(t, dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	f.watcher.SetPluginAuthParser(host)
	return f, &calls
}

func TestResourcePluginCurrentInventory(t *testing.T) {
	f, calls := pluginInventoryFixture(t)
	s := f.snapshot()
	if len(s.Resources) != 11 {
		t.Fatalf("want native provider/key, two plugin providers/keys, example descriptor and four files; got %d", len(s.Resources))
	}
	known, unsupported, disabled := 0, 0, 0
	for _, r := range s.Resources {
		if r.Family == "unsupported" {
			unsupported++
			if r.Readiness != "unsupported" || len(r.Members) != 0 {
				t.Fatal("unknown plugin must not invent credentials")
			}
			continue
		}
		known++
		if r.Identity != "valid" || r.Readiness != "ready" {
			t.Fatalf("known source not ready: %+v", r)
		}
		if r.Manual.Disabled {
			disabled++
		}
		if r.Capabilities.Query || r.Capabilities.Gate {
			t.Fatal("inventory is not query or gate capability")
		}
	}
	if known != 10 || unsupported != 1 || disabled != 3 {
		t.Fatalf("coverage known=%d unsupported=%d disabled=%d", known, unsupported, disabled)
	}
	body := string(f.request("resources", 200))
	for _, canary := range []string{"secret-canary", "label-canary", callsStringMarker} {
		if strings.Contains(body, canary) {
			t.Fatal("inventory leaked secret/source")
		}
	}
	var caps resource.Capabilities
	if err := json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
		t.Fatal(err)
	}
	if !caps.Inventory || !caps.Durable || caps.Query || caps.Gate {
		t.Fatalf("incorrect capabilities: %+v", caps)
	}
	if calls.Load() != 0 {
		t.Fatal("inventory contacted upstream")
	}
}

const callsStringMarker = "http://127.0.0.1:"

func TestResourcePluginEffectiveVersions(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	before := f.snapshot()
	// Source edits are in-place; physical replacement remains a distinct fence.
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "qwen-label-canary", "renamed"))
	if err = os.WriteFile(f.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	renamed := f.snapshot()
	for i, r := range before.Resources {
		if r.CredentialVersion != renamed.Resources[i].CredentialVersion || r.Incarnation != renamed.Resources[i].Incarnation {
			t.Fatal("rename replaced credential identity")
		}
	}
	// Same file, same secret, changed fallback endpoint must invalidate config AND file authority.
	data = []byte(strings.ReplaceAll(string(data), "base-url:", "base-url:"))
	var doc map[string]any
	if err = yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	plugins := doc["plugins"].(map[string]any)["configs"].(map[string]any)
	plugins["qwen-cliproxyapi"].(map[string]any)["base-url"] = "https://changed.invalid/v1"
	data, err = yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	changed := 0
	for _, r := range after.Resources {
		if r.Family == "qwen" && r.CredentialVersion > rowByID(t, renamed, r.ResourceID).CredentialVersion {
			changed++
		}
	}
	if changed != 3 {
		t.Fatalf("fallback endpoint must fence provider, config key and fallback file, not explicit panel file: changed=%d", changed)
	}
}

func TestResourcePluginProjectionBinding(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	body := f.request("resources", 200)
	var view struct {
		Resources []struct {
			resource.Row
			Sources []resource.Target `json:"source_bindings"`
		}
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	bound := 0
	for _, r := range view.Resources {
		if len(r.Sources) > 0 {
			bound++
			if len(r.Sources) != 1 || r.Sources[0].ResourceID == r.ResourceID {
				t.Fatal("projection must retain distinct issued targets")
			}
		}
	}
	if bound != 4 {
		t.Fatalf("want bidirectional verified config/file bindings for two plugins, got %d", bound)
	}
	// An unrelated copy with the same secret is not an independent proof of association.
	if err := os.WriteFile(filepath.Join(f.authDir, "duplicate.json"), []byte(`{"type":"qwen","api_key":"qwen-secret-canary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	view.Resources = nil
	if err := json.Unmarshal(f.request("resources", 200), &view); err != nil {
		t.Fatal(err)
	}
	for _, r := range view.Resources {
		if r.Family == "qwen" && len(r.Sources) > 0 {
			t.Fatal("ambiguous file projection was guessed")
		}
	}
}

func TestResourcePluginManagementProvenance(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	f.handler.SetConfig(resourceSaveConfig(t, f))
	body := f.request("config/plugins/configs", 200)
	var plugins map[string]map[string]any
	if err := json.Unmarshal(body, &plugins); err != nil {
		t.Fatal(err)
	}
	// Copying a host marker to a different provider is not a valid save.
	qwen := plugins["qwen-cliproxyapi"]["api-keys"].([]any)[0].(map[string]any)
	open := plugins["opencode-go-cliproxyapi"]["api-keys"].([]any)[0].(map[string]any)
	open["resource-id"] = qwen["resource-id"]
	forged, _ := json.Marshal(plugins)
	req := httptest.NewRequest(http.MethodPut, "/v8/management/config/plugins/configs", strings.NewReader(string(forged)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.engine.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Fatalf("cross-provider copied marker accepted: %d", rec.Code)
	}
	if string(f.request("config/plugins/configs", 200)) != string(body) {
		t.Fatal("rejected write changed source")
	}
}

// A controlled external plugin returns forged reserved attributes deliberately.
// The host, not the plugin, must assign the issued source binding.
type identityCanaryParser struct{ binder coreauth.SourceIdentityBinder }

func (identityCanaryParser) ParseAuth(_ context.Context, req pluginapi.AuthParseRequest) (*coreauth.Auth, bool, error) {
	if req.Provider != "qwen" && req.Provider != "opencode-go" {
		return nil, false, nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(req.RawJSON, &metadata); err != nil {
		return nil, true, err
	}
	return &coreauth.Auth{SourcePluginID: map[string]string{"qwen": "qwen-cliproxyapi", "opencode-go": "opencode-go-cliproxyapi"}[req.Provider], ID: req.FileName, FileName: req.FileName, Provider: req.Provider, Metadata: metadata, Attributes: map[string]string{coreauth.AttributeResourceID: "plugin-forged-marker", coreauth.AttributeProviderResourceID: "plugin-forged-parent"}}, true, nil
}
func TestResourcePluginHostBinding(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	sdkAuth.RegisterPluginAuthParser(identityCanaryParser{})
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	if err := f.manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var bindings struct {
		Bindings []struct {
			Scope   resource.Version  `json:"scope"`
			Targets []resource.Target `json:"targets"`
		}
	}
	if err := json.Unmarshal(f.request("resource-bindings", 200), &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Bindings) != 4 {
		t.Fatalf("want bound native and three plugin files, got %d", len(bindings.Bindings))
	}
	projected := 0
	for _, b := range bindings.Bindings {
		if b.Scope != f.snapshot().Version {
			t.Fatal("binding scope not host-owned/current")
		}
		if len(b.Targets) == 2 {
			projected++
		}
		for _, target := range b.Targets {
			if target.ResourceID == "plugin-forged-marker" {
				t.Fatal("trusted plugin marker")
			}
		}
	}
	if projected != 2 {
		t.Fatalf("want two config/file bindings, got %d", projected)
	}
}

func (p identityCanaryParser) BindAuths(path string, data []byte, auths []*coreauth.Auth) error {
	if p.binder != nil {
		return p.binder.BindAuths(path, data, auths)
	}
	return nil
}
func TestResourcePluginWatcherBinding(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	for _, a := range f.manager.List() {
		f.manager.Remove(context.Background(), a.ID)
	}
	f.watcher.SetPluginAuthParser(identityCanaryParser{binder: f.handler.SourceIdentityBinder()})
	auths, err := f.watcher.SnapshotAuthFile(filepath.Join(f.authDir, "qwen.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range auths {
		if _, err = f.manager.Register(coreauth.WithSkipPersist(context.Background()), a); err != nil {
			t.Fatal(err)
		}
	}
	var view struct{ Bindings []resource.Binding }
	if err = json.Unmarshal(f.request("resource-bindings", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Bindings) != 1 || len(view.Bindings[0].Targets) != 2 {
		t.Fatalf("watcher did not publish host binding: %+v", view)
	}
}

func TestResourcePluginHostConversionBinding(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	for _, a := range f.manager.List() {
		f.manager.Remove(context.Background(), a.ID)
	}
	host := identityTestHost()
	f.handler.SetPluginHost(host)
	path := filepath.Join(f.authDir, "qwen.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// This public host conversion is also used by plugin refresh; the controlled
	// plugin omits host markers and attempts to supply conflicting attributes.
	a := host.AuthDataToCoreAuth(pluginapi.AuthData{Provider: "qwen", ID: "qwen.json", StorageJSON: raw, Attributes: map[string]string{coreauth.AttributeResourceID: "forged"}}, path, "qwen.json")
	if a == nil {
		t.Fatal("host rejected valid plugin credential")
	}
	if _, err = f.manager.Register(coreauth.WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	var view struct{ Bindings []resource.Binding }
	if err = json.Unmarshal(f.request("resource-bindings", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Bindings) != 1 || len(view.Bindings[0].Targets) != 2 {
		t.Fatalf("host conversion lost binding: %+v", view)
	}
}

func TestResourcePluginOwnedStorageSave(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	host := identityTestHost()
	f.handler.SetPluginHost(host)
	path := filepath.Join(f.authDir, "qwen.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := host.AuthDataToCoreAuth(pluginapi.AuthData{Provider: "qwen", ID: "qwen.json", StorageJSON: raw}, path, "qwen.json")
	before := f.snapshot()
	id := a.Attributes[coreauth.AttributeResourceID]
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
	a.Metadata["label"] = "changed-host-label"
	if _, err = f.manager.Storage().Save(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := rowByID(t, f.snapshot(), id)
	if after.Identity != "valid" || after.Readiness != "ready" || after.CredentialVersion != rowByID(t, before, id).CredentialVersion {
		t.Fatal("owned plugin save lost/fenced issued source marker")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err = json.Unmarshal(saved, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["resource_id"] != id {
		t.Fatal("host storage dropped marker")
	}
}

func TestResourcePluginBootBinding(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	var view struct {
		Bindings []struct {
			resource.Binding
			AuthIndex string `json:"auth_index"`
			Alias     string `json:"runtime_alias"`
		}
	}
	if err := json.Unmarshal(f.request("resource-bindings", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Bindings) != 5 {
		t.Fatalf("boot left pre-enrollment native-config/file auths unbound: %d", len(view.Bindings))
	}
	for _, b := range view.Bindings {
		if b.AuthIndex == "" || b.Alias != b.Targets[0].ResourceID {
			t.Fatal("missing host index / opaque durable alias")
		}
	}
}

func TestResourcePluginLifecycleAndAccess(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	before := f.snapshot()
	// The two reads share actual management authorization and cache controls.
	for _, route := range []string{"resources", "resource-bindings"} {
		req := httptest.NewRequest(http.MethodGet, "/v8/management/"+route, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		f.server.engine.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("unauthorized %s returned %d", route, rec.Code)
		}
	}
	f.close()
	host := identityTestHost()
	sdkAuth.RegisterPluginAuthParser(host)
	f = newInventoryHarness(t, f.dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	restarted := f.snapshot()
	if restarted.InstanceID != before.InstanceID || restarted.BootEpoch == before.BootEpoch {
		t.Fatal("restart scope incorrect")
	}
	for _, r := range before.Resources {
		if rowByID(t, restarted, r.ResourceID).Target != r.Target {
			t.Fatal("restart replaced issued identity")
		}
	}
	// External file-object replacement remains unowned even with exact bytes.
	path := filepath.Join(f.authDir, "qwen.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(f.authDir, "replacement.tmp")
	if err = os.WriteFile(temp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(temp, path); err != nil {
		t.Fatal(err)
	}
	f.request("resource-bindings", 503)
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	ambiguous := 0
	for _, r := range after.Resources {
		if r.Identity == "ambiguous" {
			ambiguous++
		}
	}
	for _, r := range after.Resources {
		if r.Family == "qwen" && r.Kind == "provider" && r.Readiness != "not_ready" {
			t.Fatal("provider hid ambiguous file projection")
		}
	}
	if ambiguous != 1 {
		t.Fatalf("replacement not fenced: %d", ambiguous)
	}
	var bindings struct{ Bindings []resource.Binding }
	if err = json.Unmarshal(f.request("resource-bindings", 200), &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Bindings) != 4 {
		t.Fatalf("unproven replacement received binding: %d", len(bindings.Bindings))
	}
}

type identityMultiParser struct{ identityCanaryParser }

func (p identityMultiParser) ParseAuths(ctx context.Context, req pluginapi.AuthParseRequest) ([]*coreauth.Auth, bool, error) {
	a, handled, err := p.ParseAuth(ctx, req)
	if err != nil || !handled {
		return nil, handled, err
	}
	if req.Provider != "qwen" {
		return []*coreauth.Auth{a}, true, nil
	}
	b := a.Clone()
	a.ID += "-one"
	b.ID += "-two"
	return []*coreauth.Auth{a, b}, true, nil
}
func TestResourcePluginVirtualChildrenStayUnbound(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	sdkAuth.RegisterPluginAuthParser(identityMultiParser{})
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	if err := f.manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	var bindings struct{ Bindings []resource.Binding }
	if err := json.Unmarshal(f.request("resource-bindings", 200), &bindings); err != nil {
		t.Fatal(err)
	}
	// Both qwen files were expanded: only native and OpenCode remain bound.
	if len(bindings.Bindings) != 2 {
		t.Fatalf("virtual auths incorrectly given file-level identity: %d", len(bindings.Bindings))
	}
}

type identityHostProvider struct{ family string }

func (p identityHostProvider) Identifier() string { return p.family }
func (p identityHostProvider) ParseAuth(_ context.Context, req pluginapi.AuthParseRequest) (pluginapi.AuthParseResponse, error) {
	return pluginapi.AuthParseResponse{Handled: true, Auth: pluginapi.AuthData{ID: req.FileName, Provider: p.family, StorageJSON: req.RawJSON, Attributes: map[string]string{coreauth.AttributeResourceID: "plugin-forged-marker"}}}, nil
}
func (identityHostProvider) StartLogin(context.Context, pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	return pluginapi.AuthLoginStartResponse{}, fmt.Errorf("not supported by fixture")
}
func (identityHostProvider) PollLogin(context.Context, pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
	return pluginapi.AuthLoginPollResponse{}, fmt.Errorf("not supported by fixture")
}
func (identityHostProvider) RefreshAuth(_ context.Context, req pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
	return pluginapi.AuthRefreshResponse{Auth: pluginapi.AuthData{Provider: req.AuthProvider, ID: req.AuthID, StorageJSON: req.StorageJSON}}, nil
}
func TestResourcePluginUnknownProviderProvenance(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	host := pluginhost.New()
	host.RegisterPluginForTest("opencode-go-cliproxyapi", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: identityHostProvider{family: "opencode-go"}}})
	host.RegisterPluginForTest("arbitrary-plugin", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: identityHostProvider{family: "qwen"}}})
	f.handler.SetPluginHost(host)
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	if err := f.manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var bindings struct{ Bindings []resource.Binding }
	if err := json.Unmarshal(f.request("resource-bindings", 200), &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Bindings) != 2 {
		t.Fatalf("unknown plugin claiming qwen family was trusted: %d", len(bindings.Bindings))
	}
}

func identityTestHost() *pluginhost.Host {
	host := pluginhost.New()
	for id, family := range map[string]string{"qwen-cliproxyapi": "qwen", "opencode-go-cliproxyapi": "opencode-go"} {
		host.RegisterPluginForTest(id, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: identityHostProvider{family: family}}})
	}
	return host
}

func TestResourcePluginReorderAndKeyReplacement(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	write := func(plugins map[string]map[string]any) {
		t.Helper()
		body, err := json.Marshal(plugins)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPut, "/v8/management/config/plugins/configs", strings.NewReader(string(body)))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		rec := httptest.NewRecorder()
		f.server.engine.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("plugin config write: %d %s", rec.Code, rec.Body.String())
		}
		if err = f.handler.ReconcileResourceInventory(); err != nil {
			t.Fatal(err)
		}
		f.handler.SetConfig(resourceSaveConfig(t, f))
	}
	read := func() map[string]map[string]any {
		t.Helper()
		var plugins map[string]map[string]any
		if err := json.Unmarshal(f.request("config/plugins/configs", 200), &plugins); err != nil {
			t.Fatal(err)
		}
		return plugins
	}
	plugins := read()
	qwen := plugins["qwen-cliproxyapi"]
	qwen["api-keys"] = append(qwen["api-keys"].([]any), map[string]any{"name": "second", "value": "second-secret-canary"})
	write(plugins)
	before := f.snapshot()
	plugins = read()
	keys := plugins["qwen-cliproxyapi"]["api-keys"].([]any)
	first := keys[0].(map[string]any)
	id := first["resource-id"].(string)
	first["name"] = "second" // Same label as the other key must not map identity.
	keys[0], keys[1] = keys[1], keys[0]
	write(plugins)
	reordered := f.snapshot()
	old := rowByID(t, before, id)
	renamed := rowByID(t, reordered, id)
	if old.CredentialVersion != renamed.CredentialVersion || old.Incarnation != renamed.Incarnation {
		t.Fatal("reorder/rename replaced durable credential")
	}
	plugins = read()
	keys = plugins["qwen-cliproxyapi"]["api-keys"].([]any)
	keys[1].(map[string]any)["value"] = "replacement-secret-canary"
	write(plugins)
	replaced := rowByID(t, f.snapshot(), id)
	if replaced.CredentialVersion != renamed.CredentialVersion+1 || replaced.IdentityVersion != renamed.IdentityVersion+1 || replaced.Incarnation == renamed.Incarnation {
		t.Fatal("changed config key reused old credential authority")
	}
	if len(replaced.SourceBindings) != 0 || replaced.BindingState != "unmaterialized" {
		t.Fatal("old materialized key was rebound to new config secret by label")
	}
}

func TestResourcePluginExpandedCredentialPublication(t *testing.T) {
	t.Setenv("SPEC92_PLUGIN_KEY", "qwen-secret-canary")
	f, _ := pluginInventoryFixture(t)
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.ReplaceAll(string(raw), "value: qwen-secret-canary", "value: '${SPEC92_PLUGIN_KEY}'")
	if updated == string(raw) {
		t.Fatal("fixture source value not found")
	}
	if err = os.WriteFile(f.path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	var old resource.Row
	for _, r := range before.Resources {
		if r.Family == "qwen" && r.Kind == "credential" && r.ParentID != "" {
			old = r
		}
	}
	t.Setenv("SPEC92_PLUGIN_KEY", "changed-env-secret-canary")
	if err = f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	next := rowByID(t, after, old.ResourceID)
	if next.CredentialVersion != old.CredentialVersion+1 || after.Revision <= before.Revision {
		t.Fatal("expanded credential change not published/fenced")
	}
	f.close()
	host := identityTestHost()
	sdkAuth.RegisterPluginAuthParser(host)
	f = newInventoryHarness(t, f.dir, host)
	f.handler.SetPluginHost(host)
	if rowByID(t, f.snapshot(), old.ResourceID).Target != next.Target {
		t.Fatal("effective credential version was not durable")
	}
}

func TestResourcePluginOnlyTypedSaveFencing(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	req := httptest.NewRequest(http.MethodDelete, "/v8/management/config/api-keys", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	rec := httptest.NewRecorder()
	f.server.engine.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("remove synthetic native config: %d", rec.Code)
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	stale := resourceSaveConfig(t, f)
	fresh := resourceSaveConfig(t, f)
	before := f.snapshot()
	item := fresh.Plugins.Configs["qwen-cliproxyapi"]
	testField(testField(&item.Raw, "api-keys").Content[0], "name").Value = "typed-rename"
	fresh.Plugins.Configs["qwen-cliproxyapi"] = item
	if err := config.SaveConfigPreserveComments(f.path, fresh); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	for _, old := range before.Resources {
		next := rowByID(t, f.snapshot(), old.ResourceID)
		if old.Incarnation != next.Incarnation || old.CredentialVersion != next.CredentialVersion {
			t.Fatal("typed plugin rename replaced credentials")
		}
	}
	if err := config.SaveConfigPreserveComments(f.path, stale); err == nil {
		t.Fatal("plugin-only stale writer restored obsolete source")
	}
	f.snapshot()
}

func TestResourcePluginConfigurationProjectsToFiles(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	before := f.snapshot()
	editInventoryConfig(t, f.path, func(root *yaml.Node) {
		qwen := testField(testField(testField(root, "plugins"), "configs"), "qwen-cliproxyapi")
		var protocols yaml.Node
		if err := yaml.Unmarshal([]byte("{messages: false, chat-completions: true}"), &protocols); err != nil {
			t.Fatal(err)
		}
		qwen.Content = append(qwen.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "protocols"}, protocols.Content[0])
	})
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	changed := 0
	for _, r := range after.Resources {
		if r.Family == "qwen" && r.Kind == "credential" && r.ParentID == "" {
			old := rowByID(t, before, r.ResourceID)
			if r.CredentialVersion != old.CredentialVersion {
				t.Fatal("non-credential plugin config changed credential authority")
			}
			if r.ConfigVersion == old.ConfigVersion+1 {
				changed++
			}
		}
	}
	if changed != 2 {
		t.Fatalf("plugin configuration was not projected to both configured and panel files: %d", changed)
	}
}

func TestResourcePluginCatalogCloseDoesNotRemoveCredentials(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	f.close()
	// Reusing a file store after catalog shutdown/opt-out must not retain a closed
	// identity validator that silently suppresses otherwise valid credentials.
	if err := f.manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var view struct {
		Files []json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(f.request("credentials", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Files) != 4 {
		t.Fatalf("closed catalog removed file credentials on reload: %d", len(view.Files))
	}
}
