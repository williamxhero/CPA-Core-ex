package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type sourceViewBinding struct {
	resource.Binding
	AuthIndex    string `json:"auth_index"`
	RuntimeAlias string `json:"runtime_alias"`
}
type sourceBindingView struct {
	Version  int                    `json:"version"`
	Sources  []resource.QuotaSource `json:"sources"`
	Bindings []sourceViewBinding    `json:"bindings"`
}

func sourceViewFileDigests(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// The catalog holds this synchronization file exclusively on Windows; it is not durable content.
		if d.IsDir() || d.Name() == "writer.lock" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[relative] = sha256.Sum256(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestCredentialQuotaSourceBindingsNativePublicView(t *testing.T) {
	var egress atomic.Int32
	f := quotaOAuthFixture(t, credentialquota.NetworkOptions{LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
		egress.Add(1)
		return nil, errors.New("read must not resolve upstream")
	}})
	before := sourceViewFileDigests(t, f.dir)
	var caps struct {
		CredentialQuery struct {
			Version        int  `json:"version"`
			Sources        bool `json:"sources"`
			ScopedQuery    bool `json:"scoped_query"`
			SourceBindings bool `json:"source_bindings"`
		} `json:"credential_query"`
		Gate  bool `json:"gate"`
		Query bool `json:"query"`
	}
	if err := json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
		t.Fatal(err)
	}
	if !caps.CredentialQuery.SourceBindings {
		t.Fatal("validated producer did not advertise optional source_bindings view")
	}
	if caps.CredentialQuery.Version != 1 || !caps.CredentialQuery.Sources || !caps.CredentialQuery.ScopedQuery || caps.Gate || caps.Query {
		t.Fatal("additive capability widened existing semantics")
	}
	var view sourceBindingView
	raw := f.request("credential-quota/sources", 200)
	for _, secret := range []string{"QUOTA-SECRET-CANARY", "synthetic-A", "synthetic-B"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("source view leaked credential")
		}
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view.Version != 1 || view.Sources == nil || view.Bindings == nil || len(view.Bindings) != 3 {
		t.Fatalf("missing complete explicit binding array: %s", raw)
	}
	var old struct {
		Bindings []sourceViewBinding `json:"bindings"`
	}
	if err := json.Unmarshal(f.request("resource-bindings", 200), &old); err != nil {
		t.Fatal(err)
	}
	expected := map[string]sourceViewBinding{}
	for _, b := range old.Bindings {
		expected[b.AuthIndex] = b
	}
	if len(expected) != len(view.Bindings) {
		t.Fatal("combined view lost old binding coverage")
	}
	seen := map[string]bool{}
	for _, b := range view.Bindings {
		if b.AuthIndex == "" || seen[b.AuthIndex] || !reflect.DeepEqual(expected[b.AuthIndex], b) || b.RuntimeAlias != b.Targets[0].ResourceID {
			t.Fatal("combined binding differs from exact old host-issued object")
		}
		seen[b.AuthIndex] = true
		found := false
		for _, s := range view.Sources {
			if s.AuthIndex == b.AuthIndex {
				if !reflect.DeepEqual(s.Binding, b.Binding) {
					t.Fatal("same-view descriptor/binding disagrees")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("binding has no same-auth source descriptor")
		}
	}
	// An old client ignoring additive fields still receives the unchanged source
	// schema; native OAuth remains a native descriptor, not a binding/gate ACK.
	var legacy struct {
		Version int                    `json:"version"`
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Version != 1 || !reflect.DeepEqual(legacy.Sources, view.Sources) {
		t.Fatal("old source client semantics changed")
	}
	oauth := false
	for _, s := range view.Sources {
		if s.Protocol == "codex-oauth-wham" {
			oauth = true
			if s.State != "ready" || !s.ManualDisabled {
				t.Fatal("native/manual source semantics changed")
			}
		}
	}
	if !oauth || egress.Load() != 0 {
		t.Fatal("native source omitted or read performed egress")
	}
	if !reflect.DeepEqual(before, sourceViewFileDigests(t, f.dir)) {
		t.Fatal("source/binding read mutated persisted state")
	}
}

func TestCredentialQuotaSourceBindingsAuthenticatedNoStore(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	for _, path := range []string{"credential-quota/sources", "resource-capabilities"} {
		for _, authorized := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/unauthorized", true: "/admin"}[authorized], func(t *testing.T) {
				req := httptest.NewRequest("GET", "/v8/management/"+path, nil)
				req.RemoteAddr = "127.0.0.1:1234"
				if authorized {
					req.Header.Set("Authorization", "Bearer test-password")
				}
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, req)
				expected := 401
				if authorized {
					expected = 200
				}
				if w.Code != expected || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("auth/no-store mismatch status=%d expected=%d cache=%q", w.Code, expected, w.Header().Get("Cache-Control"))
				}
			})
		}
	}
}

func TestCredentialQuotaSourceBindingsRuntimeCredentialsRemainFenced(t *testing.T) {
	for _, field := range []string{"api_key", "base_url", "header:Authorization"} {
		t.Run(field, func(t *testing.T) {
			f := newInventoryHarness(t, t.TempDir())
			var before sourceBindingView
			if err := json.Unmarshal(f.request("credential-quota/sources", 200), &before); err != nil {
				t.Fatal(err)
			}
			var selected *coreauth.Auth
			for _, a := range f.manager.List() {
				if a.Attributes["api_key"] == "synthetic-A" {
					selected = a
					break
				}
			}
			if selected == nil {
				t.Fatal("missing actual configured A")
			}
			selected.Attributes[field] = "changed-secret-canary"
			if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), selected); err != nil {
				t.Fatal(err)
			}
			persisted := sourceViewFileDigests(t, f.dir)
			var after sourceBindingView
			raw := f.request("credential-quota/sources", 200)
			if err := json.Unmarshal(raw, &after); err != nil {
				t.Fatal(err)
			}
			if len(after.Bindings) != len(before.Bindings)-1 {
				t.Fatalf("changed runtime authority was not fenced (%s): %s", field, raw)
			}
			for _, b := range after.Bindings {
				if b.AuthIndex == selected.Index {
					t.Fatal("stale runtime binding retained")
				}
			}
			unavailable := false
			for _, s := range after.Sources {
				if s.Reason == "runtime_binding_unavailable" {
					unavailable = true
				}
			}
			if !unavailable || strings.Contains(string(raw), "secret-canary") {
				t.Fatal("missing honest unbound source or leaked credential")
			}
			if !reflect.DeepEqual(persisted, sourceViewFileDigests(t, f.dir)) {
				t.Fatal("read adopted runtime edit")
			}
		})
	}
}

func TestCredentialQuotaSourceBindingsUnpublishedSourceFailsClosed(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	old := f.request("credential-quota/sources", 200)
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.ReplaceAll(raw, []byte("synthetic-A"), []byte("replacement-secret-canary"))
	if bytes.Equal(raw, changed) {
		t.Fatal("fixture did not change selected source")
	}
	if err = os.WriteFile(f.path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	body := f.request("credential-quota/sources", 503)
	if bytes.Contains(body, []byte("secret-canary")) {
		t.Fatal("failure leaked source")
	}
	if err = f.watcher.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	var after sourceBindingView
	if err = json.Unmarshal(f.request("credential-quota/sources", 200), &after); err != nil {
		t.Fatal(err)
	}
	var before sourceBindingView
	if err = json.Unmarshal(old, &before); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, after) {
		t.Fatal("source replacement did not fence old view")
	}
	for _, b := range after.Bindings {
		if b.Scope == before.Bindings[0].Scope {
			t.Fatal("old whole scope survived source replacement")
		}
	}
}

func TestCredentialQuotaSourceBindingsPluginAndUnboundEquivalence(t *testing.T) {
	f, calls := pluginInventoryFixture(t)
	before := sourceViewFileDigests(t, f.dir)
	var view sourceBindingView
	raw := f.request("credential-quota/sources", 200)
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Bindings []sourceViewBinding `json:"bindings"`
	}
	if err := json.Unmarshal(f.request("resource-bindings", 200), &legacy); err != nil {
		t.Fatal(err)
	}
	expected := map[string]sourceViewBinding{}
	for _, b := range legacy.Bindings {
		expected[b.AuthIndex] = b
	}
	if len(view.Bindings) != len(expected) || len(expected) == 0 {
		t.Fatal("incomplete plugin bindings")
	}
	for _, b := range view.Bindings {
		if !reflect.DeepEqual(expected[b.AuthIndex], b) {
			t.Fatal("plugin binding differs from old exact host projection")
		}
	}
	qwen, opencode, unbound := false, false, false
	for _, s := range view.Sources {
		if s.Protocol == "qwen-coding-plan-cli" {
			qwen = true
			if s.State != "needs_configuration" {
				t.Fatal("unverified Qwen account promoted")
			}
		}
		if s.Protocol == "opencode-go-usage" {
			opencode = true
			if s.State != "unsupported" {
				t.Fatal("missing native quota provider promoted")
			}
		}
		if s.AuthIndex == "" && s.Reason == "runtime_binding_unavailable" {
			unbound = true
		}
	}
	if !qwen || !opencode || !unbound || calls.Load() != 0 {
		t.Fatal("plugin/unbound coverage omitted or read contacted upstream")
	}
	if strings.Contains(string(raw), "secret-canary") || !reflect.DeepEqual(before, sourceViewFileDigests(t, f.dir)) {
		t.Fatal("read leaked secrets or mutated source")
	}
}

func TestCredentialQuotaSourceBindingsEmptyArrays(t *testing.T) {
	dir := t.TempDir()
	text := "server: {port: 0}\nmanagement: {secret-key: test-password}\nresource-catalog: {enabled: true}\noauth: {auth-dir: " + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "auth"))) + "}\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	var v sourceBindingView
	raw := f.request("credential-quota/sources", 200)
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 || v.Sources == nil || v.Bindings == nil || len(v.Sources) != 0 || len(v.Bindings) != 0 {
		t.Fatalf("empty view is not explicit arrays: %s", raw)
	}
}

// This external plugin boundary delays metadata only; Fetch/Reset must never be
// invoked by the side-effect-free source view.
type sourceViewQuotaProvider struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*sourceViewQuotaProvider) Identifier() string { return "opencode-go" }
func (p *sourceViewQuotaProvider) DescribeQuota(ctx context.Context, _ pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
	p.once.Do(func() { close(p.entered) })
	select {
	case <-p.release:
	case <-ctx.Done():
		return pluginapi.QuotaDescribeResponse{}, ctx.Err()
	}
	return pluginapi.QuotaDescribeResponse{ScopedHTTP: true, DefaultQuotaBaseURL: "https://opencode.ai"}, nil
}
func (*sourceViewQuotaProvider) FetchQuota(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	panic("source read fetched quota")
}
func (*sourceViewQuotaProvider) ResetQuota(context.Context, pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error) {
	panic("source read reset quota")
}

func TestCredentialQuotaSourceBindingsConcurrentPublicationFailsClosed(t *testing.T) {
	for _, change := range []string{"unpublished-source", "published-scope", "lost-seal"} {
		t.Run(change, func(t *testing.T) {
			f, calls := pluginInventoryFixture(t)
			p := &sourceViewQuotaProvider{entered: make(chan struct{}), release: make(chan struct{})}
			host := identityTestHost()
			host.RegisterPluginForTest("opencode-go-cliproxyapi", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: identityHostProvider{family: "opencode-go"}, QuotaProvider: p}})
			f.handler.SetPluginHost(host)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequest("GET", "/v8/management/credential-quota/sources", nil).WithContext(ctx)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Authorization", "Bearer test-password")
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); f.server.engine.ServeHTTP(w, req) }()
			select {
			case <-p.entered:
			case <-ctx.Done():
				t.Fatal("actual plugin descriptor did not enter")
			}
			if change == "lost-seal" {
				if err := os.Remove(filepath.Join(f.dir, ".resource-catalog", "seal.key")); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.ReplaceAll(raw, []byte("native-secret-canary"), []byte("replacement-secret-canary"))
				if err = os.WriteFile(f.path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if change == "published-scope" {
					if err = f.watcher.ReconcileResourceInventory(); err != nil {
						t.Fatal(err)
					}
				}
			}
			close(p.release)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("source view did not complete within unchanged route bound")
			}
			if ctx.Err() != nil {
				t.Fatal("race proof exhausted its context instead of observing the source fence")
			}
			if w.Code != 503 || strings.Contains(w.Body.String(), "secret-canary") {
				t.Fatalf("incoherent view escaped: %d %s", w.Code, w.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatal("source view contacted upstream")
			}
			var caps map[string]any
			if err := json.Unmarshal(f.request("resource-capabilities", 200), &caps); err != nil {
				t.Fatal(err)
			}
			if change != "published-scope" && caps["credential_query"] != nil {
				t.Fatal("unavailable source/storage still advertised current view")
			}
		})
	}
}
