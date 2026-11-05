package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/middleware"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	log "github.com/sirupsen/logrus"
)

// Exercise registered public management routes with the actual catalog,
// watcher, runtime auth manager and native executor. No upstream is started.
func newProviderKeyMatchFixture(t *testing.T, base string, edits ...func(string) string) *providerGateFixture {
	t.Helper()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  openai-compatibility:\n    - name: not-an-account-a\n      base-url: %q\n      keys: [{api-key: SYNTHETIC-A1}, {api-key: SYNTHETIC-A2}]\n    - name: not-an-account-b\n      base-url: https://api.deepseek.com/v1\n      keys: [{api-key: SYNTHETIC-B1}, {api-key: SYNTHETIC-B2}]\n", filepath.ToSlash(authDir), base)
	for _, edit := range edits {
		text = edit(text)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	for _, a := range f.manager.List() {
		f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
	}
	return &providerGateFixture{f: f}
}

func copyProviderKeyMatch(q map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range q {
		out[k] = v
	}
	out["targets"] = append([]resource.Target{}, q["targets"].([]resource.Target)...)
	return out
}

func TestProviderKeyMatchPublicOriginAndKey(t *testing.T) {
	for _, base := range []string{"https://api.deepseek.com", "https://api.deepseek.com/", "https://api.deepseek.com/v1", "https://api.deepseek.com/v1/", "https://api.deepseek.com:443/v1"} {
		t.Run(base, func(t *testing.T) {
			x := newProviderKeyMatchFixture(t, base)
			for _, key := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2"} {
				q := providerKeyMatchQuery(t, x, key)
				for _, candidate := range []string{key, "SECRET-CANARY", "SYNTHETIC-B1"} {
					signProviderKeyMatch(q, candidate)
					var got map[string]any
					if err := json.Unmarshal(providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 200), &got); err != nil {
						t.Fatal(err)
					}
					if got["matched"] != (candidate == key) || got["authority"] != "runtime_key_match_only" || len(got) != 9 {
						t.Fatal("receipt conflated query credential equality with group, wallet or funding authority")
					}
				}
			}
		})
	}
}

func TestProviderKeyMatchPublicRejectsUnsupportedOrigin(t *testing.T) {
	for _, base := range []string{
		"http://api.deepseek.com", "https://custom.invalid/v1", "https://api.deepseek.com.evil.invalid/v1",
		"https://api.deepseek.com:444/v1", "https://user:SECRET-CANARY@api.deepseek.com/v1",
		"https://api.deepseek.com/v1?query=SECRET-CANARY", "https://api.deepseek.com/v1?",
		"https://api.deepseek.com/v1#SECRET-CANARY", "https://api.deepseek.com/v1#",
		"https://api.deepseek.com/v2", "https://api.deepseek.com/%76%31", "https://api.deepseek.com/v1//",
		"https://api.deepseek.com./v1", "https://api.deepseek.com:/v1", "https://api.deepseek.com:0443/v1",
	} {
		t.Run(base, func(t *testing.T) {
			x := newProviderKeyMatchFixture(t, base)
			q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 422)
		})
	}
}

func TestProviderKeyMatchPublicExactGroupAndSource(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	other := providerKeyMatchQuery(t, x, "SYNTHETIC-B1")
	for name, edit := range map[string]func(map[string]any){
		"subset":           func(q map[string]any) { q["targets"] = q["targets"].([]resource.Target)[:2] },
		"parent-only":      func(q map[string]any) { q["targets"] = q["targets"].([]resource.Target)[:1] },
		"credential-only":  func(q map[string]any) { q["targets"] = q["targets"].([]resource.Target)[1:] },
		"parent-not-first": func(q map[string]any) { a := q["targets"].([]resource.Target); a[0], a[1] = a[1], a[0] },
		"duplicate-target": func(q map[string]any) { a := q["targets"].([]resource.Target); a[2] = a[1] },
		"foreign-child": func(q map[string]any) {
			a := q["targets"].([]resource.Target)
			a[1] = other["targets"].([]resource.Target)[1]
		},
		"other-current-group": func(q map[string]any) { q["targets"] = other["targets"]; q["sourceVersion"] = other["sourceVersion"] },
		"non-member-locator":  func(q map[string]any) { q["auth_index"] = other["auth_index"] },
		"unknown-locator":     func(q map[string]any) { q["auth_index"] = "not-issued" },
		"stale-source":        func(q map[string]any) { q["sourceVersion"] = strings.Repeat("a", 64) },
		"stale-scope":         func(q map[string]any) { s := q["scope"].(resource.Version); s.Revision++; q["scope"] = s },
		"stale-boot": func(q map[string]any) {
			s := q["scope"].(resource.Version)
			s.BootEpoch = uuid.NewString()
			q["scope"] = s
		},
		"stale-target": func(q map[string]any) { q["targets"].([]resource.Target)[1].CredentialVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			copy := copyProviderKeyMatch(q)
			edit(copy)
			signProviderKeyMatch(copy, "SYNTHETIC-A1")
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, copy), "test-password", 409)
		})
	}
	// Changing only the nonce, or using a different member's query credential,
	// cannot reuse a valid challenge even under the same full provider proof.
	for _, mutate := range []func(map[string]any){
		func(q map[string]any) { q["nonce"] = uuid.NewString() },
		func(q map[string]any) { signProviderKeyMatch(q, "SYNTHETIC-A2") },
		func(q map[string]any) {
			m := hmac.New(sha256.New, []byte("SYNTHETIC-A1"))
			fmt.Fprintf(m, "cpa-provider-key-match-v1\n%s\n%s\n%s\n", q["nonce"], q["sourceVersion"], q["auth_index"])
			q["digest"] = hex.EncodeToString(m.Sum(nil))
		},
	} {
		copy := copyProviderKeyMatch(q)
		mutate(copy)
		var got struct{ Matched bool }
		if err := json.Unmarshal(providerKeyMatchRaw(t, x.f, mustProviderJSON(t, copy), "test-password", 200), &got); err != nil || got.Matched {
			t.Fatal("challenge accepted a different nonce, different member key or unfrozen message")
		}
	}
}

func TestProviderKeyMatchPublicAdminAndAvailability(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	for _, token := range []string{"", "wrong-admin", "SYNTHETIC-A1"} {
		providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), token, 401)
	}
	providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 200)
	x.f.server.managementRoutesEnabled.Store(false)
	providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 404)
	x.f.server.managementRoutesEnabled.Store(true)
	x.f.server.cfg.Home.Enabled = true
	providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 404)
}

func TestProviderKeyMatchPublicRequiresActualCurrentMembers(t *testing.T) {
	for _, change := range []string{"missing-member", "missing-key", "unissued-key", "unissued-origin", "forged-source", "partial-routes", "impostor-executor"} {
		t.Run(change, func(t *testing.T) {
			x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
			q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
			for _, a := range x.f.manager.List() {
				if a.Index != q["auth_index"] {
					continue
				}
				switch change {
				case "missing-member":
					x.f.manager.Remove(context.Background(), a.ID)
				case "partial-routes":
					x.f.manager.UnregisterExecutor(a.Provider)
				case "impostor-executor":
					x.f.manager.RegisterExecutor(providerKeyMatchImpostor{runtimeexecutor.NewOpenAICompatExecutor(a.Provider, x.f.server.cfg)})
				default:
					switch change {
					case "missing-key":
						delete(a.Attributes, "api_key")
					case "unissued-key":
						a.Attributes["api_key"] = "SECRET-CANARY"
					case "unissued-origin":
						a.Attributes["base_url"] = "https://custom.invalid/v1"
					case "forged-source":
						a.SourcePluginID = "forged-source"
					}
					if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
						t.Fatal(err)
					}
				}
			}
			want := 503
			if change == "forged-source" {
				want = 409
			}
			if change == "partial-routes" || change == "impostor-executor" {
				// A newly issued but incomplete route receipt is still not eligible.
				e := providerEligibility(t, x.f, resource.Binding{Scope: q["scope"].(resource.Version), Targets: q["targets"].([]resource.Target)})
				if e.Ready || e.Supported {
					t.Fatal("partial runtime routes were declared complete")
				}
				q["sourceVersion"] = e.SourceVersion
				signProviderKeyMatch(q, "SYNTHETIC-A1")
			}
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", want)
		})
	}
}

// A structural wrapper is deliberately not a known native executor.
type providerKeyMatchImpostor struct {
	*runtimeexecutor.OpenAICompatExecutor
}

func TestProviderKeyMatchPublicRejectsHeaderOverrideAndEmptyKey(t *testing.T) {
	for _, mode := range []string{"header-override", "configured-empty-key"} {
		t.Run(mode, func(t *testing.T) {
			x := newProviderKeyMatchFixture(t, "https://api.deepseek.com", func(text string) string {
				if mode == "header-override" {
					return strings.Replace(text, "      keys:", "      headers: {Authorization: 'Bearer SECRET-CANARY'}\n      keys:", 1)
				}
				return strings.Replace(text, "api-key: SYNTHETIC-A1", "api-key: ''", 1)
			})
			q := providerKeyMatchQuery(t, x, "SYNTHETIC-A2")
			for _, a := range x.f.manager.List() {
				if mode == "configured-empty-key" && a.Attributes["api_key"] == "" {
					q["auth_index"] = a.Index
				}
			}
			signProviderKeyMatch(q, "SYNTHETIC-A2")
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 422)
		})
	}
}

func TestProviderKeyMatchPublicNoNetworkMutationOrLogLeak(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	before := x.f.request("inference-gates", 200)
	configBefore, err := os.ReadFile(x.f.path)
	if err != nil {
		t.Fatal(err)
	}
	trap := &gateEgressCounter{}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = trap
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	x.f.manager.SetRoundTripperProvider(gateFixedTransport{rt: trap})
	x.f.handler.SetQuotaNetwork(credentialquota.NetworkOptions{
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			trap.calls.Add(1)
			return nil, fmt.Errorf("controlled quota DNS reached")
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			trap.calls.Add(1)
			return nil, fmt.Errorf("controlled quota dial reached")
		},
	})
	var captured bytes.Buffer
	oldOutput := log.StandardLogger().Out
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	logsDir := filepath.Join(t.TempDir(), "request-logs")
	// Install the real access logger and request-body logger before registering
	// the same public management route/middleware, including error-only mode.
	for _, enabled := range []bool{true, false} {
		x.f.server.engine = gin.New()
		x.f.server.engine.Use(logging.GinLogrusLogger(), logging.GinLogrusRecovery(), middleware.RequestLoggingMiddleware(logging.NewFileRequestLogger(enabled, logsDir, x.f.dir, 0)))
		x.f.server.managementRoutesRegistered.Store(false)
		x.f.server.registerManagementRoutes()
		providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 200)
		signProviderKeyMatch(q, "SECRET-CANARY")
		providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 200)
		providerKeyMatchRaw(t, x.f, []byte(`{"secret":"SECRET-CANARY"}`), "test-password", 400)
		providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "", 401)
	}
	if trap.calls.Load() != 0 {
		t.Fatal("key-match performed business or quota network I/O")
	}
	if !bytes.Equal(before, x.f.request("inference-gates", 200)) {
		t.Fatal("key-match mutated gate state")
	}
	configAfter, err := os.ReadFile(x.f.path)
	if err != nil || !bytes.Equal(configBefore, configAfter) {
		t.Fatal("key-match mutated source configuration")
	}
	for _, secret := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2", "SECRET-CANARY", q["digest"].(string), "api.deepseek.com"} {
		if strings.Contains(captured.String(), secret) {
			t.Fatal("access log leaked key-match secret/context")
		}
	}
	err = filepath.WalkDir(logsDir, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			t.Error("management request/response body was persisted to a request log")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProviderKeyMatchRejectsBorrowedIssuedBinding(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	for _, a := range x.f.manager.List() {
		if a.Index != q["auth_index"] {
			continue
		}
		// Keep the borrowed issued Binding and locator, but remove the actual
		// source provenance so a caller-controlled replacement cannot be rebound.
		a.Attributes[coreauth.AttributeSource] = "forged-source"
		a.Attributes["api_key"] = "SECRET-CANARY"
		if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
			t.Fatal(err)
		}
	}
	signProviderKeyMatch(q, "SECRET-CANARY")
	providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 409)
}

func TestProviderKeyMatchRejectsBorrowedSiblingBinding(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	for _, a := range x.f.manager.List() {
		if a.Attributes["api_key"] != "SYNTHETIC-A2" {
			continue
		}
		a.Attributes[coreauth.AttributeSource] = "forged-sibling-source"
		a.Attributes["api_key"] = "SECRET-CANARY"
		if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
			t.Fatal(err)
		}
	}
	providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 409)
}

func TestProviderKeyMatchPublicRejectsMissingAndMultipleRuntimeBindings(t *testing.T) {
	for _, mode := range []string{"missing", "multiple"} {
		t.Run(mode, func(t *testing.T) {
			x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
			q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
			for _, a := range x.f.manager.List() {
				if a.Index != q["auth_index"] {
					continue
				}
				if mode == "missing" {
					// Clearing provenance forces a missing fresh runtime Binding,
					// even if this auth retained an old issued claim.
					a.Attributes[coreauth.AttributeSource] = ""
					if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
						t.Fatal(err)
					}
				} else {
					// Two live runtime claimants of the same issued child cannot
					// be reduced to whichever locator happens to be selected.
					a.ID += "-ambiguous-runtime"
					a.Index = "ambiguous-runtime-locator"
					a.Attributes[coreauth.AttributeSource] = "unproven-runtime"
					if _, err := x.f.manager.Register(coreauth.WithSkipPersist(context.Background()), a); err != nil {
						t.Fatal(err)
					}
				}
			}
			want := 409
			if mode == "multiple" {
				want = 503
			}
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", want)
		})
	}
}

func TestProviderKeyMatchPublicOnlineEqualityNotReplayCertificate(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	body := mustProviderJSON(t, q)
	first := providerKeyMatchRaw(t, x.f, body, "test-password", 200)
	if second := providerKeyMatchRaw(t, x.f, body, "test-password", 200); !bytes.Equal(first, second) {
		t.Fatal("a current online equality read must not invent a consumed-nonce certificate")
	}
	for _, a := range x.f.manager.List() {
		if a.Index == q["auth_index"] {
			x.f.manager.Remove(context.Background(), a.ID)
		}
	}
	// A previous positive receipt is not authority to skip current validation.
	providerKeyMatchRaw(t, x.f, body, "test-password", 503)
}

func providerKeyMatchRaw(t *testing.T, f *inventoryHarness, body []byte, token string, want int) []byte {
	return providerKeyMatchRawContext(t, context.Background(), f, body, token, want)
}

func providerKeyMatchRawContext(t *testing.T, ctx context.Context, f *inventoryHarness, body []byte, token string, want int) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v8/management/inference-gates/providers/key-match", bytes.NewReader(body)).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("key-match status=%d want=%d cache-control=%q", w.Code, want, w.Header().Get("Cache-Control"))
	}
	for _, secret := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2", "SYNTHETIC-B1", "SECRET-CANARY", "api.deepseek.com", `"digest"`, `"endpoint"`, `"fingerprint"`} {
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
			t.Fatal("key-match response leaked a credential, digest, endpoint or fingerprint")
		}
	}
	if want != 200 && want != 404 {
		var out map[string]any
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 1 || out["error"] == nil {
			t.Fatal("error response must contain only a safe error code")
		}
	}
	return w.Body.Bytes()
}

func TestProviderKeyMatchPublicStrictJSON(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	valid := mustProviderJSON(t, q)
	cases := map[string][]byte{
		"duplicate-version":  bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"escaped-duplicate":  bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"\u0076ersion":1`), 1),
		"case-shadow":        bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		"scope-duplicate":    bytes.Replace(valid, []byte(`"snapshot_revision":`), []byte(`"snapshot_revision":1,"snapshot_revision":`), 1),
		"target-case-shadow": bytes.Replace(valid, []byte(`"credential_version":`), []byte(`"Credential_version":`), 1),
		"unknown-secret":     bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"secret":"SECRET-CANARY"`), 1),
		"fraction-version":   bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1.0`), 1),
		"trailing-value":     append(append([]byte{}, valid...), []byte(` {}`)...),
		"invalid-utf8":       bytes.Replace(valid, []byte(q["auth_index"].(string)), []byte{0xff}, 1),
		"unpaired-surrogate": bytes.Replace(valid, []byte(q["auth_index"].(string)), []byte(`\ud800`), 1),
		"oversized":          append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), 32<<10)...),
	}
	for _, field := range []string{"version", "scope", "targets", "sourceVersion", "auth_index", "adapter", "nonce", "digest"} {
		missing := map[string]any{}
		for k, v := range q {
			if k != field {
				missing[k] = v
			}
		}
		cases["missing-"+field] = mustProviderJSON(t, missing)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(body, valid) {
				t.Fatal("negative fixture was unchanged")
			}
			providerKeyMatchRaw(t, x.f, body, "test-password", 400)
		})
	}
	for name, value := range map[string]any{"digest": strings.Repeat("A", 64), "nonce": "not-a-uuid", "auth_index": "index\nSECRET-CANARY", "adapter": "unverified-adapter", "version": 2, "sourceVersion": strings.Repeat("g", 64)} {
		t.Run("malformed-"+name, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range q {
				copy[k] = v
			}
			copy[name] = value
			providerKeyMatchRaw(t, x.f, mustProviderJSON(t, copy), "test-password", 400)
		})
	}
}

func providerKeyMatchQuery(t *testing.T, x *providerGateFixture, key string) map[string]any {
	t.Helper()
	e := providerEligibility(t, x.f, x.binding(t, key))
	if !e.Ready || !e.Supported || len(e.Members) != 2 {
		t.Fatal("fixture did not issue a complete actual runtime provider proof")
	}
	index := ""
	for _, a := range x.f.manager.List() {
		if a.Attributes["api_key"] == key {
			index = a.Index
		}
	}
	q := map[string]any{"version": 1, "scope": e.Scope, "targets": e.Targets,
		"sourceVersion": e.SourceVersion, "auth_index": index, "adapter": "deepseek", "nonce": uuid.NewString()}
	signProviderKeyMatch(q, key)
	return q
}

// Construct the frozen wire message independently of the implementation.
func signProviderKeyMatch(q map[string]any, key string) {
	m := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(m, "cpa-provider-key-match-v1\n%s\n%s\n%s", q["nonce"], q["sourceVersion"], q["auth_index"])
	q["digest"] = hex.EncodeToString(m.Sum(nil))
}

func TestProviderKeyMatchPublicRuntimeCredential(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com/v1")
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	raw := providerGatePost(t, x.f, "inference-gates/providers/key-match", q, 200)
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	expected := map[string]any{}
	for k, v := range q {
		if k != "digest" {
			expected[k] = v
		}
	}
	expected["matched"], expected["authority"] = true, "runtime_key_match_only"
	var normalized map[string]any
	if err := json.Unmarshal(mustProviderJSON(t, expected), &normalized); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, normalized) {
		t.Fatal("receipt must echo only the exact frozen context, matched and non-monetary authority")
	}
	// The selected runtime Binding is a credential, not the submitted group.
	if len(q["targets"].([]resource.Target)) != 3 {
		t.Fatal("query did not use the full issued parent-first group")
	}
}
