package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestV8ManagementReportsQueuedCodexRenewal(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	const name = "queued-renewal.json"
	if err := os.WriteFile(filepath.Join(authDir, name), []byte(`{"type":"codex","access_token":"fixture-access","refresh_token":"fixture-refresh"}`), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	due := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	updated := false
	for _, entry := range f.manager.List() {
		if entry.FileName != name {
			continue
		}
		entry.NextRefreshAfter = due
		if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), entry); err != nil {
			t.Fatal(err)
		}
		updated = true
		break
	}
	if !updated {
		t.Fatal("synthetic OAuth credential missing")
	}
	read := func(endpoint string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		var response struct{ Files []map[string]any }
		if err := json.Unmarshal(w.Body.Bytes(), &response); w.Code != http.StatusOK || err != nil {
			t.Fatalf("credentials from %s: HTTP %d, files=%d, error=%v", endpoint, w.Code, len(response.Files), err)
		}
		for _, entry := range response.Files {
			if entry["name"] == name {
				return entry
			}
		}
		t.Fatalf("synthetic OAuth credential missing from %s", endpoint)
		return nil
	}
	const key = "next_renewal_check_at"
	const v8 = "/v8/management/credentials?name=" + name
	if got := read(v8)[key]; got != nil {
		t.Fatalf("renewal during stopped scheduler: %v", got)
	}
	f.manager.StartAutoRefresh(context.Background(), time.Minute)
	t.Cleanup(f.manager.StopAutoRefresh)
	if got := read(v8)[key]; got != due.Format(time.RFC3339) {
		t.Fatalf("queued renewal = %v, want %s", got, due)
	}
	if got := read("/v0/management/auth-files")[key]; got != nil {
		t.Fatalf("deprecated route unexpectedly publishes renewal schedule: %v", got)
	}
}

func TestCodexRenewalResultsThroughV8Management(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		body           string
		wantState      string
		wantAction     string
		wantSignIn     bool
		wantCode       string
		initialExpired bool
		disabled       bool
		quotaBlocked   bool
		beforeSend     bool
		overlapForce   bool
	}{
		{"unknown-after-send", 200, "{\"access_token\":", "credential_recovery_needed", "recover_credential", false, "refresh_outcome_unknown", false, false, false, false, false},
		{"expired-unknown-after-send", 200, "{\"access_token\":", "credential_recovery_needed", "recover_credential", false, "refresh_outcome_unknown", true, false, false, false, false},
		{"non-definitive-unauthorized", 401, "{\"error\":\"unauthorized\",\"error_description\":\"invalid_grant is not a confirmed code here\"}", "credential_recovery_needed", "recover_credential", false, "refresh_outcome_unknown", false, false, false, false, false},
		{"definitive-invalid-grant", 400, "{\"error\":\"invalid_grant\",\"error_description\":\"not-for-diagnostics@example.invalid renewal-fixture.json\"}", "sign_in_required", "sign_in", true, "invalid_grant", false, false, false, false, false},
		{"success", 200, "{\"access_token\":\"replacement-access\",\"refresh_token\":\"replacement-grant\",\"expires_in\":86400}", "renewal_verified", "", false, "", false, false, false, false, false},
		{"disabled-success", 200, "{\"access_token\":\"replacement-access\",\"refresh_token\":\"replacement-grant\",\"expires_in\":86400}", "renewal_verified", "", false, "", false, true, false, false, false},
		{"quota-blocked-success", 200, "{\"access_token\":\"replacement-access\",\"refresh_token\":\"replacement-grant\",\"expires_in\":86400}", "renewal_verified", "", false, "", false, false, true, false, false},
		{"pre-send-backoff-warning", 200, "{\"access_token\":\"replacement-access\",\"refresh_token\":\"replacement-grant\",\"expires_in\":86400}", "retry_scheduled", "retry", false, "refresh_transport_before_send", false, false, false, true, false},
		{"overlap-force-and-proactive", 200, "{\"access_token\":\"replacement-access\",\"refresh_token\":\"replacement-grant\",\"expires_in\":86400}", "renewal_verified", "", false, "", false, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests, inferenceRequests atomic.Int32
			var failDial atomic.Bool
			failDial.Store(tc.beforeSend)
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			finishExchange := func() { releaseOnce.Do(func() { close(release) }) }
			oauth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/backend-api/codex/responses" {
					inferenceRequests.Add(1)
					if tc.quotaBlocked {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusTooManyRequests)
						fmt.Fprint(w, "{\"error\":{\"type\":\"usage_limit_reached\",\"message\":\"The usage limit has been reached\",\"resets_in_seconds\":3600}}")
						return
					}
					if req.Header.Get("Authorization") != "Bearer synthetic-valid-access" {
						t.Error("unexpected inference access credential")
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"object\":\"response\",\"model\":\"renewal-test-model\",\"status\":\"completed\",\"output\":[]}}\n\n")
					return
				}
				if requests.Add(1) == 1 && tc.overlapForce {
					close(entered)
					<-release
				}
				if err := req.ParseForm(); err != nil || req.Form.Get("refresh_token") != "synthetic-refresh-grant" {
					t.Error("expected the real refresh-token exchange")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer oauth.Close()
			defer finishExchange()
			address, err := url.Parse(oauth.URL)
			if err != nil {
				t.Fatal(err)
			}
			original := http.DefaultTransport
			tr := oauth.Client().Transport.(*http.Transport).Clone()
			tr.TLSClientConfig.ServerName = "127.0.0.1"
			tr.Proxy = nil
			tr.DialContext = func(ctx context.Context, network, host string) (net.Conn, error) {
				if host == "auth.openai.com:443" && failDial.Load() {
					return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "fixture DNS failure", Name: "auth.openai.com"}}
				}
				if host != "auth.openai.com:443" && host != address.Host {
					return nil, fmt.Errorf("unexpected network destination: %s", host)
				}
				return (&net.Dialer{}).DialContext(ctx, network, address.Host)
			}
			http.DefaultTransport = tr
			defer func() { http.DefaultTransport = original; tr.CloseIdleConnections() }()

			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			if err := os.MkdirAll(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			name := "renewal-fixture.json"
			expiry := time.Now().Add(20 * time.Minute)
			if tc.initialExpired {
				expiry = time.Now().Add(-time.Hour)
			}
			body := fmt.Sprintf("{\"type\":\"codex\",\"access_token\":\"synthetic-valid-access\",\"refresh_token\":\"synthetic-refresh-grant\",\"refresh_interval_seconds\":3600,\"disabled\":%t,\"expired\":%q}", tc.disabled, expiry.Format(time.RFC3339))
			if err := os.WriteFile(filepath.Join(authDir, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			f := newInventoryHarness(t, dir)
			f.manager.SetConfig(f.server.cfg)
			var authID string
			for _, auth := range f.manager.List() {
				if auth.FileName == name {
					authID = auth.ID
					auth.Attributes["base_url"] = oauth.URL + "/backend-api/codex"
					if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if authID == "" {
				t.Fatal("synthetic OAuth credential missing")
			}
			f.manager.SetRoundTripperProvider(renewalFixtureTransport{tr})
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
			model := "renewal-test-model"
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
			defer reg.UnregisterClient(authID)

			h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/responses", func(c *gin.Context) {
				c.Request = c.Request.WithContext(handlers.WithPinnedAuthID(c.Request.Context(), authID))
				h.Responses(c)
			})
			sendInference := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(
					fmt.Sprintf("{\"model\":%q,\"input\":[],\"stream\":false}", model)))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, req)
				return w
			}
			if tc.quotaBlocked {
				w := sendInference()
				if w.Code < 400 || inferenceRequests.Load() != 1 {
					t.Fatalf("quota fixture did not reach its first denial: status=%d calls=%d", w.Code, inferenceRequests.Load())
				}
			}
			forceRefresh := func() *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/v8/management/credentials/refresh", strings.NewReader("{\"name\":\""+name+"\"}"))
				req.RemoteAddr = "127.0.0.1:1234"
				req.Header.Set("Authorization", "Bearer test-password")
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, req)
				return w
			}
			f.manager.StartAutoRefresh(context.Background(), 10*time.Millisecond)
			defer f.manager.StopAutoRefresh()
			defer finishExchange()
			if tc.overlapForce {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("proactive renewal did not reach the held OAuth exchange")
				}
				started := make(chan struct{})
				joined := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					close(started)
					joined <- forceRefresh()
				}()
				<-started
				select {
				case got := <-joined:
					t.Fatalf("concurrent force request returned before the held renewal: %d", got.Code)
				case <-time.After(50 * time.Millisecond):
				}
				finishExchange()
				select {
				case w := <-joined:
					if w.Code != http.StatusOK {
						t.Fatalf("concurrent force request did not reuse the successful renewal: status=%d", w.Code)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("force refresh did not finish after the held renewal completed")
				}
			}

			var entry map[string]any
			deadline := time.After(10 * time.Second)
			poll := time.NewTicker(10 * time.Millisecond)
			defer poll.Stop()
			for {
				raw := f.request("credentials?name="+name, http.StatusOK)
				var response struct{ Files []map[string]any }
				if err := json.Unmarshal(raw, &response); err != nil || len(response.Files) != 1 {
					t.Fatalf("expected the eligible credential from management, files=%d error=%v", len(response.Files), err)
				}
				entry = response.Files[0]
				if entry["refresh_error"] != nil || entry["renewal_verified"] == true {
					break
				}
				select {
				case <-deadline:
					t.Fatalf("background renewal did not publish a result, upstream calls=%d", requests.Load())
				case <-poll.C:
				}
			}
			if entry["renewal_state"] != tc.wantState || entry["requires_sign_in"] != tc.wantSignIn || (tc.wantAction != "" && entry["next_action"] != tc.wantAction) {
				t.Fatalf("state=%v requires_sign_in=%v next_action=%v", entry["renewal_state"], entry["requires_sign_in"], entry["next_action"])
			}
			if entry["disabled"] != tc.disabled {
				t.Fatalf("renewal changed manual gate: disabled=%v", entry["disabled"])
			}
			if tc.wantCode != "" {
				failure, _ := entry["refresh_error"].(map[string]any)
				if failure["code"] != tc.wantCode {
					t.Fatalf("code=%v, want %s", failure["code"], tc.wantCode)
				}
				diagnostics, err := json.Marshal([]any{failure, entry["renewal_event"], entry["renewal_diagnostics"]})
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range []string{name, "not-for-diagnostics@example.invalid", "synthetic-valid-access", "synthetic-refresh-grant"} {
					if strings.Contains(string(diagnostics), value) {
						t.Fatal("renewal diagnostics contained identity material")
					}
				}
			} else if entry["last_renewal_verified_at"] == nil {
				t.Fatal("successful renewal did not publish its timestamp")
			}

			if tc.wantState == "credential_recovery_needed" {
				if w := forceRefresh(); w.Code < 400 {
					t.Fatal("management must report that ambiguous refresh was not retried")
				}
			}
			if tc.quotaBlocked {
				if entry["quota_blocked"] != true {
					t.Fatal("rotation cleared the independent quota block")
				}
				w := sendInference()
				if w.Code < 400 || inferenceRequests.Load() != 1 {
					t.Fatalf("renewal allowed quota-blocked inference: status=%d calls=%d", w.Code, inferenceRequests.Load())
				}
			} else if tc.wantState == "credential_recovery_needed" || tc.disabled {
				w := sendInference()
				if tc.initialExpired || tc.disabled {
					if w.Code < 400 || inferenceRequests.Load() != 0 {
						t.Fatalf("blocked credential dispatched inference: status=%d calls=%d", w.Code, inferenceRequests.Load())
					}
				} else if w.Code != http.StatusOK || inferenceRequests.Load() != 1 {
					t.Fatalf("valid access did not reach inference: status=%d calls=%d body=%s", w.Code, inferenceRequests.Load(), w.Body.String())
				}
			}
			if tc.beforeSend {
				next, _ := entry["next_refresh_after"].(string)
				nextAt, err := time.Parse(time.RFC3339, next)
				if err != nil || !nextAt.After(time.Now()) {
					t.Fatalf("pre-send failure did not publish backoff: next=%v %v", next, err)
				}
				if w := forceRefresh(); w.Code < 400 {
					t.Fatal("forced retry should report its own pre-send failure")
				}
				raw := f.request("credentials?name="+name, http.StatusOK)
				if !strings.Contains(string(raw), "\"renewal_warning\":\"repeated_refresh_failures\"") || requests.Load() != 0 {
					t.Fatal("repeated pre-send failure did not publish a warning before submission")
				}
				failDial.Store(false)
				if w := forceRefresh(); w.Code != http.StatusOK {
					t.Fatalf("healthy transport could not renew after safe failures: status=%d", w.Code)
				}
				raw = f.request("credentials?name="+name, http.StatusOK)
				if strings.Contains(string(raw), "renewal_warning") || !strings.Contains(string(raw), "last_renewal_verified_at") {
					t.Fatal("successful recovery did not clear consecutive warning and publish successful timestamp")
				}
			}
			if requests.Load() != 1 {
				t.Fatalf("upstream saw %d requests, want one", requests.Load())
			}
		})
	}
}

type renewalFixtureTransport struct{ transport http.RoundTripper }

func (f renewalFixtureTransport) RoundTripperFor(*coreauth.Auth) http.RoundTripper {
	return f.transport
}
