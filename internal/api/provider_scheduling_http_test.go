package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type schedulingHTTPAccess struct{}

func (schedulingHTTPAccess) Identifier() string { return "scheduling-test" }
func (schedulingHTTPAccess) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	const credential = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, credential) {
		return nil, sdkaccess.NewNoCredentialsError()
	}
	switch name := strings.TrimPrefix(auth, credential); name {
	case "limited", "open":
		return &sdkaccess.Result{Provider: "scheduling-test", Principal: name}, nil
	}
	return nil, sdkaccess.NewInvalidCredentialError()
}

type schedulingHTTPFixture struct {
	*inventoryHarness
	mu    sync.Mutex
	calls []string
	url   string
	ids   map[string]string
	auths map[string]*coreauth.Auth
}

func newSchedulingHTTPFixture(t *testing.T, reply func(http.ResponseWriter, *http.Request, string)) *schedulingHTTPFixture {
	t.Helper()
	fixture := &schedulingHTTPFixture{ids: map[string]string{}, auths: map[string]*coreauth.Auth{}}
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		fixture.mu.Lock()
		fixture.calls = append(fixture.calls, key)
		fixture.mu.Unlock()
		if reply != nil {
			reply(w, r, key)
		} else {
			schedulingReply(w, key)
		}
	}))
	t.Cleanup(trap.Close)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: scheduling-subscription
      base-url: %q
      priority: 20
      keys: [{api-key: A}]
      models: [{name: service-a, alias: public-scheduling-model}]
    - name: scheduling-balance
      base-url: %q
      priority: 10
      keys: [{api-key: C}]
      models: [{name: service-c, alias: public-scheduling-model}]
`, filepath.ToSlash(authDir), trap.URL+"/v1", trap.URL+"/v1")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.inventoryHarness = newInventoryHarness(t, dir)
	for _, a := range fixture.manager.List() {
		key := a.Attributes["api_key"]
		fixture.auths[key] = a
		if a.ResourceIdentity == nil || len(a.ResourceIdentity.Targets) == 0 {
			t.Fatalf("missing issued credential identity for %q", key)
		}
		fixture.ids[key] = a.ResourceIdentity.Targets[0].ResourceID
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "public-scheduling-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	policy := fmt.Sprintf(`
routing:
  provider-scheduling:
    mode: enforce
    resources:
      %q: {funding: subscription, max-concurrent: 1}
      %q: {funding: prepaid, max-concurrent: 1}
    caller-funding:
      %q: [subscription]
`, fixture.ids["A"], fixture.ids["C"], fmt.Sprintf("%x", sha256.Sum256([]byte("scheduling-test\x00limited"))))
	enrolled, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(append(enrolled, []byte(policy)...))
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.SetConfig(cfg)
	fixture.manager.SetSelector(&coreauth.FillFirstSelector{})
	for _, a := range fixture.auths {
		fixture.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, cfg))
	}
	access := sdkaccess.NewManager()
	access.SetProviders([]sdkaccess.Provider{schedulingHTTPAccess{}})
	openAI := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, fixture.manager))
	fixture.server.engine.POST("/v1/chat/completions", AuthMiddleware(access), openAI.ChatCompletions)
	proxy := httptest.NewServer(fixture.server.engine)
	t.Cleanup(proxy.Close)
	fixture.url = proxy.URL
	return fixture
}

func schedulingReply(w http.ResponseWriter, key string) {
	fmt.Fprintf(w, `{"id":"scheduled","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, key)
}

func (f *schedulingHTTPFixture) requestModel(ctx context.Context, caller string, payload string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", f.url+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+caller)
	req.Header.Set("Content-Type", "application/json")
	// Untrusted membership/funding hints must not override the server-side policy.
	req.Header.Set("X-Access-Principal", "open")
	req.Header.Set("X-Allow-Prepaid", "true")
	return http.DefaultClient.Do(req)
}

const simpleSchedulingChat = `{"model":"public-scheduling-model","messages":[{"role":"user","content":"synthetic"}]}`

func (f *schedulingHTTPFixture) assertReply(t *testing.T, ctx context.Context, caller string, status int, want string) {
	t.Helper()
	resp, err := f.requestModel(ctx, caller, simpleSchedulingChat)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status || want != "" && !strings.Contains(string(body), want) {
		t.Fatalf("client %s got %d %s; want %d %s", caller, resp.StatusCode, body, status, want)
	}
}

func TestProviderSchedulingHTTPRespectsAuthorizedFundingOnFallback(t *testing.T) {
	f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, r *http.Request, key string) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), `"model":"service-c"`) {
			t.Errorf("fallback lost per-auth mapping: %s, %v", body, err)
		}
		schedulingReply(w, key)
	})
	a, ok := f.manager.GetByID(f.auths["A"].ID)
	if !ok {
		t.Fatal("seed auth absent")
	}
	a.Unavailable = true
	a.NextRetryAfter = time.Now().Add(135 * time.Hour)
	if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f.assertReply(t, ctx, "open", 200, `"content":"C"`)
	f.assertReply(t, ctx, "limited", 503, `no_available_route`)
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != "[C]" {
		t.Fatalf("upstream calls = %v, want only the authorized fallback", f.calls)
	}
}

func TestProviderSchedulingHTTPReservesLastSlotBeforeDispatch(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enters, releases sync.Once
	f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, r *http.Request, key string) {
		switch key {
		case "A":
			enters.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		schedulingReply(w, key)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer releases.Do(func() { close(release) })
	held := make(chan error, 1)
	go func() {
		resp, err := f.requestModel(ctx, "open", simpleSchedulingChat)
		if err == nil {
			defer func() {
				if errClose := resp.Body.Close(); errClose != nil {
					t.Error(errClose)
				}
			}()
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil || resp.StatusCode != 200 || !strings.Contains(string(body), `"content":"A"`) {
				err = fmt.Errorf("held request: %d %s (%v)", resp.StatusCode, body, readErr)
			}
		}
		held <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first request did not reach A")
	}
	competition, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	f.assertReply(t, competition, "open", 200, `"content":"C"`)
	releases.Do(func() { close(release) })
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	f.assertReply(t, ctx, "open", 200, `"content":"A"`)
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != "[A C A]" {
		t.Fatalf("upstream calls = %v, want [A C A]", f.calls)
	}
}

func TestProviderSchedulingHTTPPreservesRequestedToolAndImageCapabilities(t *testing.T) {
	f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, r *http.Request, key string) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), `"name":"lookup"`) || !strings.Contains(string(body), `"type":"image_url"`) {
			t.Errorf("fallback lost tool/image semantics: %s, %v", body, err)
		}
		schedulingReply(w, key)
	})
	registrar := registry.GetGlobalRegistry()
	registrar.RegisterClient(f.auths["A"].ID, f.auths["A"].Provider, []*registry.ModelInfo{{
		ID: "public-scheduling-model", SupportedParameters: []string{"temperature"}, SupportedInputModalities: []string{"text"},
	}})
	registrar.RegisterClient(f.auths["C"].ID, f.auths["C"].Provider, []*registry.ModelInfo{{
		ID: "public-scheduling-model", SupportedParameters: []string{"tools"}, SupportedInputModalities: []string{"text", "image"},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := f.requestModel(ctx, "open", `{"model":"public-scheduling-model","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/example.png"}}]}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || !strings.Contains(string(body), `"content":"C"`) {
		t.Fatalf("tool/image request got %d %s (%v), want capability-compatible fallback", resp.StatusCode, body, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != "[C]" {
		t.Fatalf("outbound calls = %v, want only the capability-compatible route", f.calls)
	}
}

func TestProviderSchedulingHTTPDistinguishesDisabledKnownModelFromUnknown(t *testing.T) {
	f := newSchedulingHTTPFixture(t, nil)
	cfg, err := config.LoadConfig(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routing.ProviderScheduling.Mode = "enforce"
	for i := range cfg.OpenAICompatibility {
		cfg.OpenAICompatibility[i].Disabled = true
	}
	f.manager.SetConfig(cfg)
	for _, a := range f.auths {
		registry.GetGlobalRegistry().UnregisterClient(a.ID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f.assertReply(t, ctx, "open", 503, `no_available_route`)
	resp, err := f.requestModel(ctx, "open", strings.Replace(simpleSchedulingChat, "public-scheduling-model", "never-registered-unknown-model", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 400 || !strings.Contains(string(body), `"code":"model_not_found"`) {
		t.Fatalf("unknown: %d %s (%v), want protocol 400", resp.StatusCode, body, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 0 {
		t.Fatalf("local outcomes contacted upstream: %v", f.calls)
	}
}
