package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/store"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

func TestResourceInventoryOptInAndAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("server: {port: 0}\nmanagement: {secret-key: test-password}\napi-keys:\n  codex: [{name: decoy-name, keys: [{api-key: decoy-secret}]}]\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(original)
	if err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("test-password")
	t.Cleanup(func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	})
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	request := func(route string, authorized bool, want int) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v8/management/"+route, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		if authorized {
			req.Header.Set("Authorization", "Bearer test-password")
		}
		w := httptest.NewRecorder()
		s.engine.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s: status=%d want=%d body=%s", route, w.Code, want, w.Body.String())
		}
		return w.Body.String()
	}
	body := request("resource-capabilities", true, http.StatusOK)
	var caps struct {
		Inventory bool   `json:"inventory"`
		Gate      bool   `json:"gate"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Inventory || caps.Gate || caps.Reason != "not_enabled" {
		t.Fatalf("unexpected defaults: %s", body)
	}
	request("resources", true, http.StatusServiceUnavailable)
	for _, route := range []string{"resource-capabilities", "resources"} {
		request(route, false, http.StatusUnauthorized)
		s.managementRoutesEnabled.Store(false)
		request(route, true, http.StatusNotFound)
		s.managementRoutesEnabled.Store(true)
		cfg.Home.Enabled = true
		request(route, true, http.StatusNotFound)
		cfg.Home.Enabled = false
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("read-only inventory changed configuration")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("default inventory created persistent state")
	}
}
func TestResourceInventoryCompleteSources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANAGEMENT_PASSWORD", "")
	var calls atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer trap.Close()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n", filepath.ToSlash(authDir))
	for _, family := range []string{"gemini", "interactions", "vertex", "codex", "claude", "xai", "meta", "openai-compatibility"} {
		text += fmt.Sprintf("  %s:\n    - name: decoy-name\n      base-url: %q\n", family, trap.URL+"/secret-url-decoy")
		if family == "openai-compatibility" {
			text += "      disabled: true\n"
		}
		text += "      keys: [{api-key: decoy-key, weight: 0, excluded-models: ['*']}, {api-key: ''}]\n"
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "decoy-account.json"), []byte(`{"type":"codex","disabled":true,"email":"decoy-email","access_token":"decoy-token"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	store := &sdkAuth.FileTokenStore{}
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	if err = manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	w, err := watcher.NewWatcher(path, authDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	}()
	w.SetConfig(cfg)
	for _, auth := range w.SnapshotCoreAuths() {
		if _, err = manager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatal(err)
		}
	}
	h := management.NewHandler(cfg, path, manager)
	h.SetLocalPassword("test-password")
	t.Cleanup(func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	})
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	req := httptest.NewRequest(http.MethodGet, "/v8/management/resources", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	rec := httptest.NewRecorder()
	s.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete opt-in inventory: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var snapshot resource.Snapshot
	if err = json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete || len(snapshot.Resources) != 25 {
		t.Fatalf("want 8 providers + 16 keys + disabled file, got %s", rec.Body.String())
	}
	disabled, excluded, zero := 0, 0, 0
	for _, row := range snapshot.Resources {
		if row.Manual.Disabled {
			disabled++
		}
		if row.Manual.Excluded {
			excluded++
		}
		if row.Manual.ZeroWeight {
			zero++
		}
		if row.Identity != "valid" || row.Readiness != "ready" || row.Routing != "unknown" || !row.Capabilities.Inventory || row.Capabilities.Query || row.Capabilities.Gate {
			t.Fatal("source identity/capability/readiness axes were conflated")
		}
	}
	if disabled != 4 || excluded != 8 || zero != 8 {
		t.Fatalf("manual source state lost: disabled=%d excluded=%d zero=%d", disabled, excluded, zero)
	}
	for _, decoy := range []string{"decoy", "secret-url", dir, trap.URL, "api-key", "access_token", "email", "auth_index"} {
		if strings.Contains(rec.Body.String(), decoy) {
			t.Fatalf("inventory leaked %q", decoy)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("inventory contacted upstream %d times", calls.Load())
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.engine.ServeHTTP(rec, req.Clone(context.Background()))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("GET mutated source")
	}
}

type inventoryHarness struct {
	t                  *testing.T
	dir, path, authDir string
	handler            *management.Handler
	server             *Server
	watcher            *watcher.Watcher
	manager            *coreauth.Manager
}

func newInventoryHarness(t *testing.T, dir string, parsers ...sdkAuth.PluginAuthParser) *inventoryHarness {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex:\n    - name: first\n      base-url: https://synthetic.invalid/v1\n      keys: [{api-key: synthetic-A}]\n    - name: second\n      base-url: https://synthetic.invalid/v1\n      keys: [{api-key: synthetic-B}]\n", filepath.ToSlash(authDir))
		if err = os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	store := &sdkAuth.FileTokenStore{}
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	if err = manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var h *management.Handler
	w, err := watcher.NewWatcher(path, authDir, func(next *config.Config) {
		if h != nil {
			h.SetConfig(next)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsers) > 0 {
		w.SetPluginAuthParser(parsers[0])
	}
	w.SetConfig(cfg)
	for _, auth := range w.SnapshotCoreAuths() {
		if _, err = manager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatal(err)
		}
	}
	h = management.NewHandler(cfg, path, manager)
	h.SetLocalPassword("test-password")
	w.SetResourceInventoryHook(h.ReconcileResourceInventory)
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	f := &inventoryHarness{t: t, dir: dir, path: path, authDir: authDir, handler: h, server: s, watcher: w, manager: manager}
	t.Cleanup(f.close)
	return f
}
func (f *inventoryHarness) close() {
	f.t.Helper()
	if f.watcher != nil {
		if err := f.watcher.Stop(); err != nil {
			f.t.Error(err)
		}
		f.watcher = nil
	}
	if f.handler != nil {
		if err := f.handler.CloseResourceCatalog(); err != nil {
			f.t.Error(err)
		}
		f.handler = nil
	}
}
func (f *inventoryHarness) request(route string, want int) []byte {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v8/management/"+route, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != want {
		f.t.Fatalf("%s status=%d want=%d body=%s", route, w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}
func (f *inventoryHarness) snapshot() resource.Snapshot {
	f.t.Helper()
	var s resource.Snapshot
	if err := json.Unmarshal(f.request("resources", 200), &s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestResourceIdentityRestart(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	before := f.snapshot()
	f.close()
	f = newInventoryHarness(t, dir)
	after := f.snapshot()
	if before.InstanceID != after.InstanceID || before.InstanceIncarnation != after.InstanceIncarnation {
		t.Fatal("restart changed persistent instance identity")
	}
	if before.BootEpoch == after.BootEpoch {
		t.Fatal("boot epoch must be distinct from persistent identity")
	}
	if before.Revision != after.Revision {
		t.Fatal("unchanged restart advanced snapshot revision")
	}
	if len(after.Resources) != 4 {
		t.Fatalf("lost resources: %+v", after)
	}
	for i, row := range before.Resources {
		if row.Target != after.Resources[i].Target {
			t.Fatal("restart changed resource lifecycle")
		}
	}
}
func TestResourceIdentityKeyReplacement(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	before := f.snapshot()
	f.close()
	path := filepath.Join(dir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-C", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	f = newInventoryHarness(t, dir)
	after := f.snapshot()
	old := before.Resources[1]
	next := after.Resources[1]
	if old.ResourceID != next.ResourceID {
		t.Fatal("logical source marker was not retained")
	}
	if old.Incarnation == next.Incarnation || next.IdentityVersion <= old.IdentityVersion || next.CredentialVersion <= old.CredentialVersion || next.ConfigVersion <= old.ConfigVersion || after.Revision <= before.Revision {
		t.Fatal("key replacement did not fence old observations")
	}
	if before.Resources[3].Target != after.Resources[3].Target {
		t.Fatal("unrelated credential changed")
	}
}
func testField(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func editInventoryConfig(t *testing.T, path string, edit func(*yaml.Node)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc.Content[0])
	data, err = yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func rowByID(t *testing.T, s resource.Snapshot, id string) resource.Row {
	t.Helper()
	for _, r := range s.Resources {
		if r.ResourceID == id {
			return r
		}
	}
	t.Fatalf("missing resource %s", id)
	return resource.Row{}
}
func TestResourceIdentityMembershipAndRename(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	before := f.snapshot()
	f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		groups := testField(testField(root, "api-keys"), "codex")
		g := groups.Content[0]
		testField(g, "name").Value = "renamed"
		groups.Content[0], groups.Content[1] = groups.Content[1], groups.Content[0]
		var key yaml.Node
		if err := yaml.Unmarshal([]byte("{api-key: synthetic-C}"), &key); err != nil {
			t.Fatal(err)
		}
		keys := testField(g, "keys")
		keys.Content = append(keys.Content, key.Content[0])
	})
	f = newInventoryHarness(t, dir)
	after := f.snapshot()
	old := before.Resources[0]
	next := rowByID(t, after, old.ResourceID)
	if next.MembershipVersion <= old.MembershipVersion || next.ConfigVersion <= old.ConfigVersion || len(next.Members) != 2 {
		t.Fatal("provider member change did not fence old whole-provider observations")
	}
	for _, old := range before.Resources {
		next := rowByID(t, after, old.ResourceID)
		if next.Incarnation != old.Incarnation || next.CredentialVersion != old.CredentialVersion {
			t.Fatal("rename/reorder changed account identity")
		}
	}
	if after.Revision <= before.Revision {
		t.Fatal("source change did not advance snapshot")
	}
}
func TestResourceIdentityUnprovenBindings(t *testing.T) {
	t.Run("copied marker", func(t *testing.T) {
		dir := t.TempDir()
		f := newInventoryHarness(t, dir)
		before := f.snapshot()
		f.close()
		editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
			groups := testField(testField(root, "api-keys"), "codex")
			a := testField(groups.Content[0], "keys").Content[0]
			b := testField(groups.Content[1], "keys").Content[0]
			testField(b, "resource-id").Value = testField(a, "resource-id").Value
		})
		f = newInventoryHarness(t, dir)
		after := f.snapshot()
		count := 0
		for _, r := range after.Resources {
			if r.ResourceID == before.Resources[1].ResourceID {
				count++
				if r.Identity != "ambiguous" || r.Readiness != "not_ready" {
					t.Fatal("copied identities were advertised as ready")
				}
			}
		}
		if count != 2 {
			t.Fatal("ambiguous source rows disappeared")
		}
	})
	t.Run("tombstone", func(t *testing.T) {
		dir := t.TempDir()
		f := newInventoryHarness(t, dir)
		before := f.snapshot()
		f.close()
		path := filepath.Join(dir, "config.yaml")
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		editInventoryConfig(t, path, func(root *yaml.Node) {
			groups := testField(testField(root, "api-keys"), "codex")
			groups.Content = groups.Content[1:]
		})
		f = newInventoryHarness(t, dir)
		if len(f.snapshot().Resources) != 2 {
			t.Fatal("deleted source remained in inventory")
		}
		f.close()
		if err = os.WriteFile(path, saved, 0600); err != nil {
			t.Fatal(err)
		}
		f = newInventoryHarness(t, dir)
		restored := rowByID(t, f.snapshot(), before.Resources[1].ResourceID)
		if restored.Identity != "ambiguous" || restored.Readiness != "not_ready" {
			t.Fatal("deleted identity resurrected from copied source envelope")
		}
		f.close()
		editInventoryConfig(t, path, func(root *yaml.Node) {
			g := testField(testField(root, "api-keys"), "codex").Content[0]
			for _, n := range []*yaml.Node{g, testField(g, "keys").Content[0]} {
				for i := 0; i+1 < len(n.Content); i += 2 {
					if n.Content[i].Value == "resource-id" {
						n.Content = append(n.Content[:i], n.Content[i+2:]...)
						break
					}
				}
			}
		})
		f = newInventoryHarness(t, dir)
		fresh := f.snapshot().Resources[1]
		if fresh.ResourceID == before.Resources[1].ResourceID || fresh.Identity != "valid" {
			t.Fatal("unmarked recreation did not receive a new issued identity")
		}
	})
}
func TestResourceInventorySingleWriter(t *testing.T) {
	dir := t.TempDir()
	first := newInventoryHarness(t, dir)
	before := first.snapshot()
	second := newInventoryHarness(t, dir)
	second.request("resources", 503)
	var caps resource.Capabilities
	if err := json.Unmarshal(second.request("resource-capabilities", 200), &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Inventory || caps.Durable || caps.Gate || caps.Reason != "not_ready" {
		t.Fatalf("contending writer advertised support: %+v", caps)
	}
	second.close()
	first.close()
	third := newInventoryHarness(t, dir)
	after := third.snapshot()
	if before.InstanceID != after.InstanceID {
		t.Fatal("writer lock handoff replaced instance identity")
	}
}
func TestResourceInventoryWatcherPublication(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	before := f.snapshot()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.path, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-C", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	f.request("resources", 503)
	f.watcher.ReloadConfigIfChanged()
	after := f.snapshot()
	old := before.Resources[1]
	next := rowByID(t, after, old.ResourceID)
	if next.Incarnation == old.Incarnation || after.Revision <= before.Revision {
		t.Fatal("watcher published stale credential identity")
	}
}
func TestResourceInventoryPublicationRecovery(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	before := f.snapshot()
	// Block the next source backup, after the signed intent can become durable.
	// The existing ledger stays intact; corruption is not a publication fault injector.
	backup := fmt.Sprintf("%s.%s.%d.catalog-v1-backup", f.path, before.InstanceID, before.Revision+1)
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	editInventoryConfig(t, f.path, func(root *yaml.Node) {
		keys := testField(testField(testField(root, "api-keys"), "codex").Content[0], "keys")
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("{api-key: synthetic-C}"), &doc); err != nil {
			t.Fatal(err)
		}
		keys.Content = append(keys.Content, doc.Content[0])
	})
	f.watcher.ReloadConfigIfChanged()
	f.request("resources", 503)
	f.close()
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	f = newInventoryHarness(t, dir)
	after := f.snapshot()
	if after.InstanceID != before.InstanceID || after.InstanceIncarnation != before.InstanceIncarnation {
		t.Fatal("failed publication lost durable instance identity instead of recovering intent")
	}
	if len(after.Resources) != 5 {
		t.Fatal("recovery lost source rows")
	}
	for _, old := range before.Resources {
		next := rowByID(t, after, old.ResourceID)
		if next.Identity != "valid" {
			t.Fatal("recovery could not prove unchanged identity")
		}
	}
	f.close()
	f = newInventoryHarness(t, dir)
	again := f.snapshot()
	if after.Revision != again.Revision {
		t.Fatal("recovered publication was replayed twice")
	}
}
func TestResourceInventoryNativeGroupRoundTrip(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	before := f.snapshot()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CodexKey) != 2 {
		t.Fatalf("fixture did not reach real config synthesis: %d", len(cfg.CodexKey))
	}
	zero := 0
	cfg.CodexKey[0].Weight = &zero
	if err = config.SaveConfigPreserveComments(f.path, cfg); err != nil {
		t.Fatal(err)
	}
	f.watcher.ReloadConfigIfChanged()
	after := f.snapshot()
	for _, old := range before.Resources {
		next := rowByID(t, after, old.ResourceID)
		if old.Kind == "credential" && next.Incarnation != old.Incarnation {
			t.Fatal("manual weight save changed credential account identity")
		}
	}
	if !rowByID(t, after, before.Resources[1].ResourceID).Manual.ZeroWeight {
		t.Fatal("legacy config write did not retain manual weight")
	}
	if len(after.Resources) != 4 {
		t.Fatal("native groups were flattened in catalog")
	}
}
func TestResourceInventoryStorageIntegrity(t *testing.T) {
	for _, name := range []string{"catalog.json", "seal.key"} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryHarness(t, t.TempDir())
			f.snapshot()
			path := filepath.Join(f.dir, ".resource-catalog", name)
			if err := os.WriteFile(path, []byte("synthetic-corruption"), 0600); err != nil {
				t.Fatal(err)
			}
			f.request("resources", 503)
			var caps resource.Capabilities
			if err := json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
				t.Fatal(err)
			}
			if caps.Inventory || caps.Durable || caps.Gate || caps.Reason != "not_ready" {
				t.Fatalf("corrupt storage advertised readiness: %+v", caps)
			}
		})
	}
}
func TestResourceInventoryAuthFileLifecycle(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	f.snapshot()
	store := &sdkAuth.FileTokenStore{}
	store.SetBaseDir(f.authDir)
	auth := &coreauth.Auth{ID: "synthetic.json", FileName: "synthetic.json", Provider: "codex", Disabled: true, Metadata: map[string]any{"type": "codex", "email": "synthetic-account", "access_token": "synthetic-token"}}
	if _, err := store.Save(coreauth.WithAuthCreationIntent(context.Background()), auth); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.authDir, "synthetic.json")); err != nil {
		t.Fatal(err)
	}
	f.watcher.DispatchPersistedAuthUpdate(watcher.AuthUpdate{Action: watcher.AuthUpdateActionAdd, ID: auth.ID, Auth: auth})
	after := f.snapshot()
	if len(after.Resources) != 5 {
		t.Fatal("watcher did not publish new file source")
	}
	var first resource.Row
	for _, r := range after.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			first = r
		}
	}
	if !first.Manual.Disabled || first.Identity != "valid" {
		t.Fatal("disabled file identity was not inventoried")
	}
	loaded, err := store.List(context.Background())
	if err != nil || len(loaded) != 1 {
		t.Fatalf("file reload: %v count=%d", err, len(loaded))
	}
	changed := loaded[0]
	changed.Metadata["access_token"] = "synthetic-rotated-token"
	if _, err = store.Save(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	f.watcher.DispatchPersistedAuthUpdate(watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: changed.ID, Auth: changed})
	next := rowByID(t, f.snapshot(), first.ResourceID)
	if next.Incarnation == first.Incarnation || next.CredentialVersion <= first.CredentialVersion {
		t.Fatal("unproven same-account token refresh did not fence old observations")
	}
	old := next
	if err = os.Rename(filepath.Join(f.authDir, "synthetic.json"), filepath.Join(f.authDir, "renamed.json")); err != nil {
		t.Fatal(err)
	}
	f.watcher.DispatchPersistedAuthUpdate(watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: "renamed.json", Auth: changed})
	next = rowByID(t, f.snapshot(), first.ResourceID)
	if next.Target != old.Target {
		t.Fatal("proven file rename changed account identity")
	}
	loaded, err = store.List(context.Background())
	if err != nil || len(loaded) != 1 {
		t.Fatal("renamed source reload failed")
	}
	changed = loaded[0]
	changed.Metadata["email"] = "synthetic-other-account"
	if _, err = store.Save(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	f.watcher.DispatchPersistedAuthUpdate(watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: changed.ID, Auth: changed})
	next = rowByID(t, f.snapshot(), first.ResourceID)
	if next.Incarnation == old.Incarnation || next.IdentityVersion <= old.IdentityVersion {
		t.Fatal("account swap did not invalidate observations")
	}
}

func TestResourceInventoryUnsupportedStorage(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	f.snapshot()
	f.close()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	// Construction, local path setup and manager setup perform no repository I/O.
	unsupported := store.NewGitTokenStore("", "", "", "")
	unsupported.SetBaseDir(filepath.Join(t.TempDir(), "auth"))
	manager := coreauth.NewManager(unsupported, nil, nil)
	h := management.NewHandler(cfg, f.path, manager)
	h.SetLocalPassword("test-password")
	t.Cleanup(func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	})
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	f.server = s
	f.request("resources", 503)
	var caps resource.Capabilities
	if err = json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Inventory || caps.Durable || caps.Gate || caps.Reason != "unsupported_storage" {
		t.Fatalf("non-file backend advertised durability: %+v", caps)
	}
}
func TestResourceInventoryAmbiguitySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.snapshot()
	f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		groups := testField(testField(root, "api-keys"), "codex")
		a := testField(groups.Content[0], "keys").Content[0]
		b := testField(groups.Content[1], "keys").Content[0]
		testField(b, "resource-id").Value = testField(a, "resource-id").Value
	})
	f = newInventoryHarness(t, dir)
	before := f.snapshot()
	f.close()
	f = newInventoryHarness(t, dir)
	after := f.snapshot()
	if before.Revision != after.Revision {
		t.Fatal("unchanged ambiguous input advanced revision")
	}
	for _, r := range after.Resources {
		if r.Kind == "credential" && r.Identity != "ambiguous" {
			t.Fatal("restart guessed copied identity continuity")
		}
	}
}

func TestResourceInventoryStateDirectoryCannotOverlapAuth(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	f.snapshot()
	f.close()
	editInventoryConfig(t, f.path, func(root *yaml.Node) {
		settings := testField(root, "resource-catalog")
		settings.Content = append(settings.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "state-dir"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: f.authDir})
	})
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	store := &sdkAuth.FileTokenStore{}
	store.SetBaseDir(f.authDir)
	h := management.NewHandler(cfg, f.path, coreauth.NewManager(store, nil, nil))
	t.Cleanup(func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	})
	entries, err := os.ReadDir(f.authDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("rejected catalog polluted watched auth directory")
	}
}
func TestResourceIdentityMarkersReachAuthManager(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.snapshot()
	f.close()
	f = newInventoryHarness(t, dir)
	snapshot := f.snapshot()
	auths := f.manager.List()
	if len(auths) != 2 {
		t.Fatalf("real manager loaded %d auths", len(auths))
	}
	for _, auth := range auths {
		marker := auth.Attributes["resource_id"]
		if marker == "" {
			t.Fatal("source identity marker was erased by runtime config flattening")
		}
		row := rowByID(t, snapshot, marker)
		if row.Kind != "credential" || auth.Attributes["provider_resource_id"] != row.ParentID {
			t.Fatal("runtime marker points at another source group")
		}
	}
}

func TestResourceIdentityCopiedEnvelopeFencesObservation(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	before := f.snapshot()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(f.dir, "replacement.yaml")
	if err = os.WriteFile(replacement, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, f.path); err != nil {
		t.Fatal(err)
	}
	f.request("resources", 503)
	f.close()
	f = newInventoryHarness(t, f.dir)
	after := f.snapshot()
	if after.Revision <= before.Revision {
		t.Fatal("copied source envelope reused an old observation revision")
	}
	for _, row := range after.Resources {
		if row.Identity != "ambiguous" || row.Readiness != "not_ready" {
			t.Fatal("unproven delete/recreate was treated as proven rename")
		}
	}
}
func TestResourceInventoryFilteredRowsSurviveTypedSave(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.snapshot()
	f.close()
	editInventoryConfig(t, f.path, func(root *yaml.Node) {
		var groups yaml.Node
		if err := yaml.Unmarshal([]byte("[{name: active, base-url: 'https://synthetic.invalid/v1', keys: [{api-key: synthetic-M}]}, {name: keyless, base-url: 'https://synthetic.invalid/v1', keys: [{api-key: ''}]}]"), &groups); err != nil {
			t.Fatal(err)
		}
		providers := testField(root, "api-keys")
		providers.Content = append(providers.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "meta"}, groups.Content[0])
	})
	f = newInventoryHarness(t, dir)
	before := f.snapshot()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MetaKey) != 1 {
		t.Fatal("fixture must exercise the real keyless-row filter")
	}
	zero := 0
	cfg.MetaKey[0].Weight = &zero
	if err = config.SaveConfigPreserveComments(f.path, cfg); err != nil {
		t.Fatal(err)
	}
	f.watcher.ReloadConfigIfChanged()
	after := f.snapshot()
	if len(after.Resources) != len(before.Resources) {
		t.Fatal("typed runtime save erased filtered source rows")
	}
	for _, old := range before.Resources {
		rowByID(t, after, old.ResourceID)
	}
}
func TestResourceIdentityInheritedCredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		group := testField(testField(root, "api-keys"), "codex").Content[0]
		var headers yaml.Node
		if err := yaml.Unmarshal([]byte("{Authorization: synthetic-header-decoy}"), &headers); err != nil {
			t.Fatal(err)
		}
		group.Content = append(group.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "headers"}, headers.Content[0])
	})
	f = newInventoryHarness(t, dir)
	before := f.snapshot()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	cfg.CodexKey[0].Weight = &zero
	if err = config.SaveConfigPreserveComments(f.path, cfg); err != nil {
		t.Fatal(err)
	}
	f.watcher.ReloadConfigIfChanged()
	after := f.snapshot()
	for _, old := range before.Resources {
		next := rowByID(t, after, old.ResourceID)
		if old.Kind == "credential" && (next.Incarnation != old.Incarnation || next.CredentialVersion != old.CredentialVersion) {
			t.Fatal("layout-only movement of inherited credentials invalidated proven identity")
		}
	}
	if !rowByID(t, after, before.Resources[1].ResourceID).Manual.ZeroWeight {
		t.Fatal("manual edit was not published")
	}
}

func TestResourceInventoryStorageFailureCannotBeHealedByWatcher(t *testing.T) {
	for _, name := range []string{"catalog.json", "seal.key"} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryHarness(t, t.TempDir())
			f.snapshot()
			path := filepath.Join(f.dir, ".resource-catalog", name)
			corrupt := []byte("synthetic-corruption")
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			editInventoryConfig(t, f.path, func(root *yaml.Node) {
				testField(testField(testField(root, "api-keys"), "codex").Content[0], "name").Value = "source-edit-after-storage-failure"
			})
			f.watcher.ReloadConfigIfChanged()
			f.request("resources", 503)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(corrupt) {
				t.Fatal("watcher silently repaired damaged durable identity state")
			}
		})
	}
}

func TestResourceInventoryNestedFileSources(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.close()
	nested := filepath.Join(f.authDir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "synthetic.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex","disabled":true,"access_token":"nested-secret-decoy"}`), 0600); err != nil {
		t.Fatal(err)
	}
	f = newInventoryHarness(t, dir)
	before := f.snapshot()
	if len(before.Resources) != 5 {
		t.Fatalf("complete inventory omitted nested file-store credential: rows=%d", len(before.Resources))
	}
	old := before.Resources[4]
	if old.Kind != "credential" || !old.Manual.Disabled || old.Readiness != "ready" {
		t.Fatal("nested source state was not inventoried")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(data), "nested-secret-decoy", "replacement-secret-decoy", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	f.request("resources", 503)
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	next := rowByID(t, after, old.ResourceID)
	if next.Incarnation == old.Incarnation || next.CredentialVersion <= old.CredentialVersion {
		t.Fatal("nested source replacement escaped lifecycle fencing")
	}
	for _, decoy := range []string{"nested-secret-decoy", "replacement-secret-decoy", path} {
		if strings.Contains(string(f.request("resources", 200)), decoy) {
			t.Fatal("nested source leaked private data")
		}
	}
}

func TestResourceInventoryV8ConfigHTTPRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		var groups yaml.Node
		if err := yaml.Unmarshal([]byte("[{name: disabled, base-url: 'https://synthetic.invalid', disabled: true, keys: [{api-key: synthetic-compat}, {api-key: ''}]}, {name: empty, base-url: 'https://synthetic.invalid', keys: []}]"), &groups); err != nil {
			t.Fatal(err)
		}
		providers := testField(root, "api-keys")
		providers.Content = append(providers.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "openai-compatibility"}, groups.Content[0])
	})
	f = newInventoryHarness(t, dir)
	before := f.snapshot()
	body := f.request("config/api-keys", 200)
	req := httptest.NewRequest(http.MethodPut, "/v8/management/config/api-keys", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.engine.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("marked config roundtrip: %d %s", rec.Code, rec.Body.String())
	}
	f.watcher.ReloadConfigIfChanged()
	after := f.snapshot()
	if len(after.Resources) != len(before.Resources) {
		t.Fatal("v8 HTTP roundtrip flattened or dropped source rows")
	}
	for _, old := range before.Resources {
		next := rowByID(t, after, old.ResourceID)
		if next.Target != old.Target || next.Manual != old.Manual {
			t.Fatal("unchanged v8 HTTP roundtrip changed resource identity or manual state")
		}
	}
}

func TestResourceInventoryRecoveryRejectsConflictingEdit(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	before := f.snapshot()
	backup := fmt.Sprintf("%s.%s.%d.catalog-v1-backup", f.path, before.InstanceID, before.Revision+1)
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	editInventoryConfig(t, f.path, func(root *yaml.Node) {
		keys := testField(testField(testField(root, "api-keys"), "codex").Content[0], "keys")
		var key yaml.Node
		if err := yaml.Unmarshal([]byte("{api-key: new-key-decoy}"), &key); err != nil {
			t.Fatal(err)
		}
		keys.Content = append(keys.Content, key.Content[0])
	})
	f.watcher.ReloadConfigIfChanged()
	f.request("resources", 503)
	if _, err := os.Stat(filepath.Join(dir, ".resource-catalog", "journal.json")); err != nil {
		t.Fatal("fixture did not reach durable intent")
	}
	f.close()
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(data), "new-key-decoy", "conflicting-key-decoy", 1)
	if err = os.WriteFile(f.path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	f = newInventoryHarness(t, dir)
	f.request("resources", 503)
	var caps resource.Capabilities
	if err = json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
		t.Fatal(err)
	}
	if caps.Inventory || caps.Durable || caps.Gate || caps.Query {
		t.Fatal("conflicting recovery fabricated readiness")
	}
	after, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != changed {
		t.Fatal("recovery overwrote an external edit")
	}
}
