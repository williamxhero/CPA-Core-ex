package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestProviderSchedulingPersistentPilotWHAMAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	var phase, sendsA, sendsB, reads atomic.Int32
	now := time.Now().UTC().Truncate(time.Second)
	reset := now.Add(3 * time.Hour).Unix()
	weeklyReset := now.Add(5 * 24 * time.Hour).Unix()
	windows := fmt.Sprintf(`"primary_window":{"used_percent":100,"reset_at":%d,"limit_window_seconds":18000},"secondary_window":{"used_percent":25,"reset_at":%d,"limit_window_seconds":604800}`, reset, weeklyReset)
	upstream, network := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		phase := phase.Load()
		w.Header().Set("Date", now.Format(http.TimeFormat))
		switch r.URL.Path {
		case "/backend-api/wham/usage":
			reads.Add(1)
			if key != "Bearer wham-A-CANARY" || r.Header.Get("Chatgpt-Account-Id") != "acct-A-CANARY" {
				t.Error("quota read addressed the wrong account")
			}
			switch phase {
			case 0:
				// Same plan window, but balance is unknown. Not evidence of double zero.
				fmt.Fprintf(w, `{"rate_limit":{"allowed":false,"limit_reached":true,%s},"additional_rate_limits":[]}`, windows)
			case 1:
				w.Header().Set("Date", now.Add(time.Second).Format(http.TimeFormat))
				fmt.Fprintf(w, `{"rate_limit":{"allowed":false,"limit_reached":true,%s},"additional_rate_limits":[],"credits":{"has_credits":false,"unlimited":false,"balance":"0"}}`, windows)
			case 2, 3:
				if phase == 3 {
					w.Header().Set("Date", now.Add(2*time.Second).Format(http.TimeFormat))
				}
				fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,%s},"additional_rate_limits":[],"credits":{"has_credits":false,"unlimited":false,"balance":"0"}}`, strings.Replace(windows, `"used_percent":100`, `"used_percent":25`, 1))
			}
		case "/backend-api/codex/responses":
			switch key {
			case "Bearer wham-A-CANARY":
				if sendsA.Add(1) == 1 {
					raw, _ := io.ReadAll(r.Body)
					if ojson.GetBytes(raw, "model").String() != persistentPilotModel {
						t.Errorf("expected the pilot upstream model; got %q", ojson.GetBytes(raw, "model").String())
					}
					if r.Header.Get("Chatgpt-Account-Id") != "acct-A-CANARY" {
						t.Error("inference did not use the selected account")
					}
					w.Header().Set("X-Codex-Active-Limit", "codex")
					w.Header().Set("X-Codex-Primary-Used-Percent", "100")
					w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
					w.Header().Set("X-Codex-Primary-Reset-At", fmt.Sprint(reset))
					w.WriteHeader(429)
					fmt.Fprintf(w, `{"error":{"type":"usage_limit_reached","limit_window_minutes":300,"resets_at":%d,"message":"RAW-CANARY"}}`, reset)
					return
				}
				if phase == 4 && sendsA.Load() == 4 {
					// The server received the request but sent no response headers.
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				persistentPilotStart(w, "resp-wham-A")
				persistentPilotSucceed(w, "primary-funded")
			case "Bearer wham-B-CANARY":
				sendsB.Add(1)
				persistentPilotStart(w, "resp-wham-B")
				persistentPilotSucceed(w, "backup-funded")
			default:
				t.Error("inference used an unexpected credential")
				w.WriteHeader(500)
			}
		default:
			t.Error("unexpected upstream route")
			w.WriteHeader(500)
		}
	}))
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		label    string
		priority int
	}{{"A", 20}, {"B", 10}} {
		data := fmt.Sprintf(`{"type":"codex","access_token":"wham-%s-CANARY","account_id":"acct-%s-CANARY","priority":%d}`, f.label, f.label, f.priority)
		if err := os.WriteFile(filepath.Join(authDir, f.label+".json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yaml")
	caller := sha256.Sum256([]byte(sdkaccess.DefaultAccessProviderName + "\x00open"))
	yaml := fmt.Sprintf(`access: {api-keys: [open]}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
multimedia: {disable-image-generation: true}
routing:
  retry:
    request-retry: 1
    max-retry-credentials: 1
    upstream-error-retry-limit: 1
  provider-scheduling:
    mode: enforce
    models: [gpt-6.2-sol]
    callers: [%x]
    persistent-retry-models: [gpt-6.2-sol]
`, filepath.ToSlash(authDir), caller)
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store := &sdkauth.FileTokenStore{}
	store.SetBaseDir(authDir)
	m := coreauth.NewManager(store, nil, nil)
	m.SetConfig(cfg)
	clock := newProviderBudgetClock(now, true)
	m.SetContinuityClockForTest(clock)
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	m.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(cfg))
	tr := upstream.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = network.DialContext
	m.SetRoundTripperProvider(scopedQuotaTransport{tr})
	t.Cleanup(tr.CloseIdleConnections)
	s := NewServer(cfg, m, sdkaccess.NewManager(), path)
	t.Cleanup(func() {
		if err := s.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	s.mgmt.SetQuotaNetwork(network)
	f := &inventoryHarness{t: t, server: s, manager: m, handler: s.mgmt}
	var primary, backup *coreauth.Auth
	for _, a := range m.List() {
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: persistentPilotModel}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
		if a.Metadata["access_token"] == "wham-A-CANARY" {
			primary = a
		} else {
			backup = a
		}
	}
	if primary == nil || backup == nil || primary.ResourceIdentity == nil || backup.ResourceIdentity == nil {
		t.Fatal("missing current OAuth bindings")
	}
	setBackup := func(enabled bool) {
		updatePilotAuth(t, f, backup.ID, func(a *coreauth.Auth) {
			a.Disabled, a.Status = !enabled, coreauth.StatusActive
		})
	}
	infer := func(status int, marker string, sendCount int64) string {
		t.Helper()
		w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
		trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
		if w.Code != status || !strings.Contains(w.Body.String(), marker) || ojson.Get(trace, "send_count").Int() != sendCount || strings.Contains(w.Body.String()+trace, "CANARY") {
			t.Fatalf("inference status=%d A=%d B=%d reads=%d body=%s trace=%s", w.Code, sendsA.Load(), sendsB.Load(), reads.Load(), w.Body, trace)
		}
		return trace
	}
	setBackup(false)
	infer(200, "primary-funded", 2)
	if sendsA.Load() != 2 || sendsB.Load() != 0 || reads.Load() != 1 || len(clock.waits) != 1 {
		t.Fatalf("unknown funds acted as a quota gate: sends=%d/%d reads=%d waits=%d", sendsA.Load(), sendsB.Load(), reads.Load(), len(clock.waits))
	}
	phase.Store(1)
	readQuota := func() resource.QuotaObservation {
		t.Helper()
		var roster struct{ Sources []resource.QuotaSource }
		if err := json.Unmarshal(f.request("credential-quota/sources", 200), &roster); err != nil {
			t.Fatal(err)
		}
		for _, source := range roster.Sources {
			if source.SubjectID == primary.ResourceIdentity.Targets[0].ResourceID {
				return queryQuota(t, f, resource.QuotaQuery{Binding: source.Binding, AuthIndex: source.AuthIndex, SourceVersion: source.SourceVersion, SourceID: source.SourceID, SubjectID: source.SubjectID}, 200)
			}
		}
		t.Fatal("primary quota source missing")
		return resource.QuotaObservation{}
	}
	readQuota()
	quotaTrace := infer(503, "no_available_route", 0)
	if ojson.Get(quotaTrace, "last_recovery_wait").Exists() || !strings.Contains(quotaTrace, `"source":"current_quota_gate"`) || !strings.Contains(quotaTrace, `"state":"known","at":`) {
		t.Fatalf("missing authoritative quota evidence or waited for a quota estimate: %s", quotaTrace)
	}
	setBackup(true)
	infer(200, "backup-funded", 1)
	phase.Store(2)
	if obs := readQuota(); len(obs.ClearedQuotaWindows) != 0 {
		t.Fatal("stale WHAM cleared a newer pause")
	}
	infer(200, "backup-funded", 1)
	phase.Store(3)
	if obs := readQuota(); len(obs.ClearedQuotaWindows) != 1 {
		t.Fatal("fresh authoritative WHAM did not clear the window pause")
	}
	infer(200, "primary-funded", 1)
	setBackup(false)
	phase.Store(4)
	infer(200, "primary-funded", 2)
	if sendsA.Load() != 5 || sendsB.Load() != 2 || reads.Load() != 4 {
		t.Fatalf("inference and quota accounting disagree: A=%d B=%d reads=%d", sendsA.Load(), sendsB.Load(), reads.Load())
	}
}
