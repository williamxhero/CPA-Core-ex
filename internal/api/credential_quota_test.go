package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type fixtureDenyHTTP struct{}

func (fixtureDenyHTTP) Do(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return pluginapi.HTTPResponse{}, errors.New("fixture startup egress denied")
}
func (fixtureDenyHTTP) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, errors.New("fixture startup egress denied")
}

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

func TestCredentialQuotaCapabilityIsVersionedNotGateACK(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	var caps map[string]any
	json.Unmarshal(f.request("resource-capabilities", 200), &caps)
	capability, ok := caps["credential_query"].(map[string]any)
	if !ok || capability["version"] != float64(1) || capability["scoped_query"] != true || caps["gate"] != false || caps["query"] != false {
		t.Fatalf("missing distinct versioned credential query capability: %+v", caps)
	}
	var view map[string]any
	json.Unmarshal(f.request("credential-quota/sources", 200), &view)
	if view["version"] != float64(1) {
		t.Fatal("unversioned credential query contract")
	}
}

// TestCredentialQuotaProcessFixture is an opt-in compiled ACTUAL Core route host.
// Only external network dependencies are injected. No fake identity/query producer.
func TestCredentialQuotaProcessFixture(t *testing.T) {
	address := os.Getenv("QUOTA_FIXTURE_LISTEN")
	if address == "" {
		t.Skip("isolated process fixture only")
	}
	dir := os.Getenv("QUOTA_FIXTURE_STATE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	auth := filepath.Join(dir, "auth")
	if err := os.MkdirAll(auth, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"codex.json":    `{"type":"codex","access_token":"QUOTA-SECRET-CANARY","account_id":"synthetic-account","disabled":true}`,
		"opencode.json": `{"type":"opencode-go","api_key":"PLUGIN-SECRET-CANARY","disabled":true}`,
	} {
		mode := os.Getenv("QUOTA_FIXTURE_ENDPOINT_MODE")
		if name == "opencode.json" && strings.HasPrefix(mode, "file-explicit-") {
			base := "https://opencode.ai/inference/go/v1"
			if mode == "file-explicit-legacy" {
				base = "https://opencode.ai/zen/go/v1"
			}
			body = strings.TrimSuffix(body, "}") + `,"base_url":` + fmt.Sprintf("%q", base) + `}`
		}
		if _, exists := os.Stat(filepath.Join(auth, name)); os.IsNotExist(exists) {
			if err := os.WriteFile(filepath.Join(auth, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: intermediary, base-url: https://synthetic.invalid/v1, keys: [{api-key: API-KEY-CANARY}]}]\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    opencode-go-cliproxyapi:\n      enabled: true\n      base-url: https://opencode.ai/zen/go/v1\n      api-keys: [{name: test, value: PLUGIN-SECRET-CANARY}]\n", filepath.ToSlash(auth), filepath.ToSlash(os.Getenv("QUOTA_FIXTURE_PLUGIN_DIR")))
	if os.Getenv("QUOTA_FIXTURE_ENDPOINT_MODE") != "" {
		text = strings.Replace(text, "      base-url: https://opencode.ai/zen/go/v1\n", "", 1)
	}
	if _, exists := os.Stat(filepath.Join(dir, "config.yaml")); os.IsNotExist(exists) {
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(actual)
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	// Plugin initialization may refresh its model catalog. Deny all such I/O;
	// only the separately scoped management quota invocation may reach TLS.
	cfg.ProxyURL = "http://127.0.0.1:1"
	host.ApplyConfig(pluginhost.WithQuotaHTTPClient(context.Background(), fixtureDenyHTTP{}), cfg)
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
	maybeInstallExternalInferenceGateRoutes(t, f, roots, endpoint, address)
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
	q := resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}
	obs := queryQuota(t, f, q, 200)
	doc, _ := json.Marshal(obs)
	if !strings.Contains(string(doc), `"timestampProvenance":"upstream_http_date"`) {
		t.Fatal("missing upstream timestamp provenance")
	}
	if obs.QueryStatus != "success" || !obs.Complete || !obs.RecoveryEligible || len(obs.Windows) != 2 || obs.Windows[0].RemainingFraction != 0.75 {
		t.Fatalf("wrong windows: %+v", obs)
	}
	mode.Store(1)
	obs = queryQuota(t, f, q, 200)
	if obs.QueryStatus != "auth_error" || obs.RecoveryEligible {
		t.Fatal("auth error became evidence")
	}
	q.TimeoutMS = 60001
	queryQuota(t, f, q, 400)
	q.TimeoutMS = 0
	q.Targets[0].CredentialVersion++
	queryQuota(t, f, q, 409)
	if calls.Load() != 2 {
		t.Fatal("stale target contacted upstream")
	}
}

func TestCredentialQuotaTLSCertificateVerificationIsRequired(t *testing.T) {
	var calls atomic.Int64
	_, n := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{}`) }))
	n.RootCAs = nil
	f := quotaOAuthFixture(t, n)
	s := quotaSourceFor(t, f, "codex-oauth-wham")
	obs := queryQuota(t, f, resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}, 200)
	if obs.QueryStatus != "network_error" || calls.Load() != 0 {
		t.Fatal("untrusted TLS reached provider request handler")
	}
}

func TestCredentialQuotaWindowAndTransportNegatives(t *testing.T) {
	reset := time.Now().Add(time.Hour).Unix()
	window := fmt.Sprintf(`{"used_percent":25,"reset_at":%d,"limit_window_seconds":18000}`, reset)
	full := `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":` + window + `,"secondary_window":` + window + `}}`
	for _, tc := range []struct {
		name, body, status string
		code               int
		date               string
		complete, recovery bool
	}{
		{name: "complete", body: full, status: "success", complete: true, recovery: true},
		{name: "partial", body: `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":` + window + `}}`, status: "success"},
		{name: "null", body: strings.ReplaceAll(full, `"used_percent":25`, `"used_percent":null`), status: "parse_error"},
		{name: "nonfinite", body: strings.ReplaceAll(full, `"used_percent":25`, `"used_percent":1e999`), status: "parse_error"},
		{name: "missing", body: `{}`, status: "parse_error"},
		{name: "expired", body: strings.ReplaceAll(full, fmt.Sprint(reset), "1"), status: "success", complete: true},
		{name: "badwindow", body: strings.ReplaceAll(full, `"limit_window_seconds":18000`, `"limit_window_seconds":0`), status: "parse_error"},
		{name: "unauthorized", body: "QUOTA-SECRET-CANARY", status: "auth_error", code: 401},
		{name: "429-not-recovery", body: "QUOTA-SECRET-CANARY", status: "rate_limited", code: 429},
		{name: "old-origin-time", body: full, status: "parse_error", date: time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)},
		{name: "future-origin-time", body: full, status: "parse_error", date: time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)},
		{name: "overlimit", body: strings.Repeat("x", (2<<20)+1), status: "parse_error"},
		{name: "redirect", body: full, status: "network_error", code: 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			_, n := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.date != "" {
					w.Header().Set("Date", tc.date)
				}
				if tc.code == 302 {
					w.Header().Set("Location", "https://metadata.google.internal/")
				}
				if tc.code != 0 {
					w.WriteHeader(tc.code)
				}
				fmt.Fprint(w, tc.body)
			}))
			f := quotaOAuthFixture(t, n)
			s := quotaSourceFor(t, f, "codex-oauth-wham")
			obs := queryQuota(t, f, resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}, 200)
			if obs.QueryStatus != tc.status || obs.Complete != tc.complete || obs.RecoveryEligible != tc.recovery {
				t.Fatalf("unexpected result %+v", obs)
			}
			if calls.Load() != 1 {
				t.Fatal("duplicate/fallback request")
			}
		})
	}
}

func TestCredentialQuotaMetadataDNSNeverDials(t *testing.T) {
	for _, ip := range []string{"169.254.169.254", "168.63.129.16", "64:ff9b::a9fe:a9fe", "::ffff:169.254.169.254", "2002:a9fe:a9fe::1", "fe80::1", "127.0.0.1"} {
		t.Run(ip, func(t *testing.T) {
			var dials atomic.Int64
			n := credentialquota.NetworkOptions{LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP(ip)}}, nil
			}, DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, fmt.Errorf("unexpected dial")
			}}
			f := quotaOAuthFixture(t, n)
			s := quotaSourceFor(t, f, "codex-oauth-wham")
			obs := queryQuota(t, f, resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}, 200)
			if obs.QueryStatus != "network_error" || dials.Load() != 0 {
				t.Fatal("DNS/metadata bypass")
			}
		})
	}
}

func TestCredentialQuotaUnknownAccountAndManagementTimeout(t *testing.T) {
	var mode atomic.Int64
	_, n := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 1 {
			<-r.Context().Done()
			return
		}
		reset := time.Now().Add(time.Hour).Unix()
		fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":20,"reset_at":%d,"limit_window_seconds":1},"secondary_window":{"used_percent":20,"reset_at":%d,"limit_window_seconds":1}}}`, reset, reset)
	}))
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth")
	os.MkdirAll(auth, 0700)
	os.WriteFile(filepath.Join(auth, "codex.json"), []byte(`{"type":"codex","access_token":"QUOTA-SECRET-CANARY"}`), 0600)
	f := newInventoryHarness(t, dir)
	f.handler.SetQuotaNetwork(n)
	s := quotaSourceFor(t, f, "codex-oauth-wham")
	q := resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}
	obs := queryQuota(t, f, q, 200)
	if obs.QueryStatus != "success" || obs.AccountProvenance != "unverified" || obs.RecoveryEligible {
		t.Fatal("unknown account recovered")
	}
	mode.Store(1)
	q.TimeoutMS = 50
	obs = queryQuota(t, f, q, 200)
	if obs.QueryStatus != "network_error" || obs.RecoveryEligible {
		t.Fatal("timeout became positive evidence")
	}
}

func TestCredentialQuotaQwenUnverifiedNeverQueries(t *testing.T) {
	f, calls := pluginInventoryFixture(t)
	s := quotaSourceFor(t, f, "qwen-console")
	obs := queryQuota(t, f, resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion}, 200)
	if obs.QueryStatus != "needs_configuration" || obs.AccountProvenance != "unverified" || obs.RecoveryEligible || len(obs.Windows) != 0 || calls.Load() != 0 {
		t.Fatalf("unproven console account was queried/recovered: %+v", obs)
	}
}

func TestCredentialQuotaMixedKeyOAuthFileNeverUsesWham(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth")
	os.MkdirAll(auth, 0700)
	os.WriteFile(filepath.Join(auth, "mixed.json"), []byte(`{"type":"codex","access_token":"OAUTH-LIKE-CANARY","api_key":"INTERMEDIARY-CANARY","base_url":"https://intermediary.invalid/v1"}`), 0600)
	f := newInventoryHarness(t, dir)
	var view struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	json.Unmarshal(f.request("credential-quota/sources", 200), &view)
	for _, s := range view.Sources {
		if s.Protocol == "codex-oauth-wham" {
			t.Fatal("mixed API-key file falsely acquired native OAuth query capability")
		}
	}
}

func TestCredentialQuotaLateResultFencedBySourceReplacement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	_, n := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, `{}`)
	}))
	f := quotaOAuthFixture(t, n)
	s := quotaSourceFor(t, f, "codex-oauth-wham")
	data, _ := json.Marshal(resource.QuotaQuery{Binding: s.Binding, AuthIndex: s.AuthIndex, SourceVersion: s.SourceVersion, TimeoutMS: 1000})
	req := httptest.NewRequest("POST", "/v8/management/credential-quota/query", bytes.NewReader(data))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); f.server.engine.ServeHTTP(w, req); done <- w.Code }()
	<-entered
	path := filepath.Join(f.authDir, "codex.json")
	raw, _ := os.ReadFile(path)
	raw = bytes.Replace(raw, []byte("QUOTA-SECRET-CANARY"), []byte("REPLACEMENT-CANARY"), 1)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	// Deadline releases this request without a wall-clock sleep or upstream success.
	if code := <-done; code != 409 {
		t.Fatalf("late result HTTP %d", code)
	}
}
