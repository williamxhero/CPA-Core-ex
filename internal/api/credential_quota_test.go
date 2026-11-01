package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialQuotaSourcesAreReadOnlyAndHonest(t *testing.T) {
	f, calls := pluginInventoryFixture(t)
	var view struct {
		Sources []struct {
			State     string `json:"state"`
			Reason    string `json:"reason"`
			AuthIndex string `json:"auth_index"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Sources) == 0 {
		t.Fatal("source inventory omitted current credentials")
	}
	qwen, unverified := false, false
	for _, s := range view.Sources {
		if s.Reason == "account_authority_unverified" {
			qwen = true
		}
		if s.Reason == "api_key_protocol_unverified" {
			unverified = true
		}
	}
	if !qwen || !unverified {
		t.Fatalf("missing honest source states: %+v", view)
	}
	if calls.Load() != 0 {
		t.Fatal("GET queried upstream")
	}
}

// TestCredentialQuotaProcessFixture is an opt-in compiled ACTUAL Core route host.
// Only external network dependencies are injected. No fake identity/query producer.
func TestCredentialQuotaProcessFixture(t *testing.T) {
	address := os.Getenv("QUOTA_FIXTURE_LISTEN")
	if address == "" {
		t.Skip("isolated process fixture only")
	}
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth")
	if err := os.Mkdir(auth, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"codex.json":    `{"type":"codex","access_token":"QUOTA-SECRET-CANARY","account_id":"synthetic-account","disabled":true}`,
		"opencode.json": `{"type":"opencode-go","api_key":"PLUGIN-SECRET-CANARY","disabled":true}`,
	} {
		if err := os.WriteFile(filepath.Join(auth, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: intermediary, base-url: https://synthetic.invalid/v1, keys: [{api-key: API-KEY-CANARY}]}]\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    opencode-go-cliproxyapi:\n      enabled: true\n      base-url: https://opencode.ai/zen/go/v1\n      api-keys: [{name: test, value: PLUGIN-SECRET-CANARY}]\n", filepath.ToSlash(auth), filepath.ToSlash(os.Getenv("QUOTA_FIXTURE_PLUGIN_DIR")))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	host.ApplyConfig(context.Background(), cfg)
	t.Cleanup(host.ShutdownAll)
	if !host.HasQuotaProviderForPlugin("opencode-go-cliproxyapi") {
		t.Fatal("real compiled existing plugin was not loaded")
	}
	sdkAuth.RegisterPluginAuthParser(host)
	t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
	f := newInventoryHarness(t, dir, host)
	f.handler.SetPluginHost(host)
	host.SetAuthManager(f.manager)
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(os.Getenv("QUOTA_FIXTURE_CA"))
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		t.Fatal("missing controlled TLS CA")
	}
	endpoint := os.Getenv("QUOTA_FIXTURE_UPSTREAM")
	f.handler.SetQuotaNetwork(credentialquota.NetworkOptions{RootCAs: roots, LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}})
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: f.server.engine}
	defer server.Close()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func quotaTLS(t *testing.T, handler http.Handler) (*httptest.Server, credentialquota.NetworkOptions) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	seed.Close()
	template, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template.DNSNames = []string{"chatgpt.com", "opencode.ai"}
	template.IPAddresses = nil
	signer := cert.PrivateKey.(crypto.Signer)
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = [][]byte{der}
	server.TLS = seed.TLS.Clone()
	server.TLS.Certificates[0] = cert
	server.StartTLS()
	t.Cleanup(server.Close)
	root, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	n := credentialquota.NetworkOptions{RootCAs: roots, LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	return server, n
}

func quotaOAuthFixture(t *testing.T, n credentialquota.NetworkOptions) *inventoryHarness {
	t.Helper()
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth")
	os.MkdirAll(auth, 0700)
	if err := os.WriteFile(filepath.Join(auth, "codex.json"), []byte(`{"type":"codex","access_token":"QUOTA-SECRET-CANARY","account_id":"synthetic-account","disabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.handler.SetQuotaNetwork(n)
	return f
}
func quotaSourceFor(t *testing.T, f *inventoryHarness, protocol string) resource.QuotaSource {
	t.Helper()
	var view struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	for _, s := range view.Sources {
		if s.Protocol == protocol {
			return s
		}
	}
	t.Fatalf("missing protocol %s", protocol)
	return resource.QuotaSource{}
}
func queryQuota(t *testing.T, f *inventoryHarness, q resource.QuotaQuery, want int) resource.QuotaObservation {
	t.Helper()
	data, _ := json.Marshal(q)
	req := httptest.NewRequest("POST", "/v8/management/credential-quota/query", strings.NewReader(string(data)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "CANARY") || strings.Contains(w.Body.String(), "synthetic-account") {
		t.Fatal("quota secret leaked")
	}
	if w.Code != want {
		t.Fatalf("query HTTP %d: %s", w.Code, w.Body.String())
	}
	var obs resource.QuotaObservation
	_ = json.Unmarshal(w.Body.Bytes(), &obs)
	return obs
}
func TestCredentialQuotaSelectedOAuthAndFailure(t *testing.T) {
	var calls atomic.Int64
	var mode atomic.Int64
	_, n := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/backend-api/wham/usage" || r.Header.Get("Authorization") != "Bearer QUOTA-SECRET-CANARY" || r.Header.Get("Chatgpt-Account-Id") != "synthetic-account" {
			t.Error("wrong selected OAuth request")
		}
		if mode.Load() == 1 {
			w.WriteHeader(401)
			fmt.Fprint(w, "QUOTA-SECRET-CANARY")
			return
		}
		reset := time.Now().Add(time.Hour).Unix()
		fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":25,"reset_at":%d,"limit_window_seconds":18000},"secondary_window":{"used_percent":50,"reset_at":%d,"limit_window_seconds":604800}}}`, reset, reset)
	}))
	f := quotaOAuthFixture(t, n)
	s := quotaSourceFor(t, f, "codex-oauth-wham")
	if !s.ManualDisabled || calls.Load() != 0 {
		t.Fatal("disabled inventory must not query")
	}
	q := resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex}
	obs := queryQuota(t, f, q, 200)
	if obs.QueryStatus != "success" || !obs.Complete || !obs.RecoveryEligible || len(obs.Windows) != 2 || obs.Windows[0].RemainingFraction != 0.75 {
		t.Fatalf("wrong windows: %+v", obs)
	}
	mode.Store(1)
	obs = queryQuota(t, f, q, 200)
	if obs.QueryStatus != "auth_error" || obs.RecoveryEligible {
		t.Fatal("auth error became evidence")
	}
	q.Targets[0].CredentialVersion++
	queryQuota(t, f, q, 409)
	if calls.Load() != 2 {
		t.Fatal("stale target contacted upstream")
	}
}
