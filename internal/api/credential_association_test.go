package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCredentialAssociationPublicV8Boundary(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	for _, tc := range []struct {
		name, body string
		authorized bool
		want       int
	}{
		{"malformed-current-admin", `{}`, true, 400},
		{"admin-required", `{}`, false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v8/management/credential-quota/credential-association", strings.NewReader(tc.body))
			req.RemoteAddr = "127.0.0.1:1234"
			if tc.authorized {
				req.Header.Set("Authorization", "Bearer test-password")
			}
			w := httptest.NewRecorder()
			f.server.engine.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("association status=%d want=%d", w.Code, tc.want)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("association response cacheable")
			}
		})
	}
}

// This uses actual host-issued current source and complete provider membership,
// not synthesized resource identifiers or a copied key as an identity claim.
func associationFixtureRequest(t *testing.T, f *inventoryHarness) credentialassociation.Request {
	return associationFixtureForKey(t, f, "synthetic-A")
}
func associationFixtureForKey(t *testing.T, f *inventoryHarness, key string) credentialassociation.Request {
	t.Helper()
	installGateFixtureExecutors(f)
	var sources struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &sources); err != nil {
		t.Fatal(err)
	}
	var selected resource.QuotaSource
	for _, s := range sources.Sources {
		for _, a := range f.manager.List() {
			if a.Index == s.AuthIndex && a.Attributes["api_key"] == key {
				selected = s
			}
		}
	}
	if selected.AuthIndex == "" {
		t.Fatal("selected configured A missing")
	}
	var snapshot resource.Snapshot
	if err := json.Unmarshal(f.request("resources", 200), &snapshot); err != nil {
		t.Fatal(err)
	}
	rows := map[string]resource.Row{}
	for _, r := range snapshot.Resources {
		rows[r.ResourceID] = r
	}
	ids := map[string]bool{}
	for _, target := range selected.Targets {
		ids[target.ResourceID] = true
		if parent := rows[target.ResourceID].ParentID; parent != "" {
			ids[parent] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for id := range ids {
			r := rows[id]
			for _, child := range r.Members {
				if !ids[child] {
					ids[child] = true
					changed = true
				}
			}
			for _, related := range r.SourceBindings {
				if !ids[related.ResourceID] {
					ids[related.ResourceID] = true
					changed = true
				}
			}
		}
	}
	targets := []resource.Target{}
	for id := range ids {
		targets = append(targets, rows[id].Target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ResourceID < targets[j].ResourceID })
	q := credentialassociation.Request{Version: 1, Selected: selected.Binding, AuthIndex: selected.AuthIndex, SourceVersion: selected.SourceVersion, Origin: "https://synthetic.invalid:443", QueryID: "80b421b1-260f-4931-adb4-6861e70d4115", Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Official: credentialassociation.Config{Binding: resource.Binding{Scope: snapshot.Version, Targets: targets}, Version: 1, Adapter: "newapi-token-usage-v1", Endpoint: "https://synthetic.invalid/api/usage/token/", NewAPI: &credentialassociation.NewAPI{ProtocolConfirmed: true, InstanceVersion: "controlled-v1", Auth: "inference-key-readonly-v1", NativeUnit: "tokens"}}}
	signAssociation(t, &q, key)
	return q
}
func signAssociation(t *testing.T, q *credentialassociation.Request, key string) {
	t.Helper()
	b, err := credentialassociation.Envelope(*q)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write(b)
	q.CandidateMAC = base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func TestCredentialAssociationCurrentSourceProof(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	original := associationFixtureRequest(t, f)
	other := associationFixtureForKey(t, f, "synthetic-B")
	for _, tc := range []struct {
		name     string
		mutate   func(*credentialassociation.Request)
		status   int
		reason   string
		positive bool
	}{
		{"exact-selected-key", func(q *credentialassociation.Request) {}, 200, "selected_credential_association", true},
		{"different-selected-key", func(q *credentialassociation.Request) { signAssociation(t, q, "synthetic-B") }, 200, "credential_mismatch", false},
		{"other-current-whole-group", func(q *credentialassociation.Request) {
			q.Official = other.Official
			signAssociation(t, q, "synthetic-A")
		}, 200, "source_group_mismatch", false},
		{"stale-source", func(q *credentialassociation.Request) { q.SourceVersion = strings.Repeat("0", 64) }, 409, "", false},
		{"stale-selected-target", func(q *credentialassociation.Request) { q.Selected.Targets[0].CredentialVersion++ }, 409, "", false},
		{"stale-official-target", func(q *credentialassociation.Request) { q.Official.Targets[0].ConfigVersion++ }, 409, "", false},
		{"current-but-incomplete-group", func(q *credentialassociation.Request) {
			for _, target := range q.Official.Targets {
				if target.MembershipVersion > 0 {
					q.Official.Targets = []resource.Target{target}
					break
				}
			}
			signAssociation(t, q, "synthetic-A")
		}, 200, "source_group_mismatch", false},
		{"different-origin", func(q *credentialassociation.Request) {
			q.Origin = "https://other.invalid:443"
			signAssociation(t, q, "synthetic-A")
		}, 200, "origin_mismatch", false},
		{"wrong-token-path", func(q *credentialassociation.Request) {
			q.Official.Endpoint = "https://synthetic.invalid/tenant/B/api/usage/token/"
			signAssociation(t, q, "synthetic-A")
		}, 200, "association_unsupported", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var q credentialassociation.Request
			json.Unmarshal(raw, &q)
			tc.mutate(&q)
			raw, _ = json.Marshal(q)
			req := httptest.NewRequest("POST", "/v8/management/credential-quota/credential-association", bytes.NewReader(raw))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Authorization", "Bearer test-password")
			w := httptest.NewRecorder()
			f.server.engine.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable association")
			}
			if tc.status != 200 {
				return
			}
			var result struct {
				Associated bool             `json:"associated"`
				Reason     string           `json:"reason"`
				Selected   resource.Binding `json:"selected"`
				Proof      *struct {
					Version       int    `json:"version"`
					Kind          string `json:"kind"`
					ChallengeHash string `json:"challengeHash"`
				} `json:"proof"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Associated != tc.positive || result.Reason != tc.reason || !reflect.DeepEqual(result.Selected, q.Selected) {
				t.Fatalf("wrong selected proof: %s", w.Body.String())
			}
			if (result.Proof != nil) != tc.positive {
				t.Fatal("proof presence disagrees with positive")
			}
			if tc.positive && (result.Proof.Version != 2 || result.Proof.Kind != "selected_credential_hmac_v2" || len(result.Proof.ChallengeHash) != 64) {
				t.Fatal("invalid frozen proof")
			}
			if bytes.Contains(w.Body.Bytes(), []byte("synthetic-A")) || bytes.Contains(w.Body.Bytes(), []byte("synthetic-B")) || bytes.Contains(w.Body.Bytes(), []byte(q.CandidateMAC)) {
				t.Fatal("secret/MAC canary leaked")
			}
		})
	}
}

func TestCredentialAssociationPublicV8MatchesActualConfiguredNative(t *testing.T) {
	for _, family := range []string{"codex", "claude", "openai-compatibility"} {
		t.Run(family, func(t *testing.T) {
			for _, mode := range []string{"standard", "auth-override", "tenant-prefix"} {
				t.Run(mode, func(t *testing.T) {
					var sends atomic.Int32
					observations := make(chan *http.Request, 2)
					upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						io.Copy(io.Discard, r.Body)
						sends.Add(1)
						observations <- r.Clone(context.Background())
						w.WriteHeader(418)
						io.WriteString(w, `{"error":{"message":"controlled terminal"}}`)
					}))
					defer upstream.Close()
					tr := upstream.Client().Transport.(*http.Transport).Clone()
					tr.TLSClientConfig.ServerName = upstream.Certificate().DNSNames[0]
					if tr.TLSClientConfig.InsecureSkipVerify {
						t.Fatal("unverified TLS")
					}
					tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
					}
					defer tr.CloseIdleConnections()
					base := "https://synthetic.invalid/v1"
					path := "/v1/responses"
					format := sdktranslator.FormatOpenAIResponse
					if family == "claude" {
						base = "https://synthetic.invalid"
						path = "/v1/messages"
						format = sdktranslator.FormatClaude
					}
					if family == "openai-compatibility" {
						path = "/v1/chat/completions"
						format = sdktranslator.FormatOpenAI
					}
					if mode == "tenant-prefix" {
						base = strings.Replace(base, "synthetic.invalid", "synthetic.invalid/tenant/B", 1)
						path = "/tenant/B" + path
					}
					extra := ""
					if mode == "auth-override" {
						extra = "      headers: {Authorization: 'Bearer synthetic-B'}\n"
					}
					dir := t.TempDir()
					authDir := filepath.Join(dir, "auth")
					if err := os.MkdirAll(authDir, 0700); err != nil {
						t.Fatal(err)
					}
					text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  %s:\n    - name: actual-native\n      base-url: %q\n%s      keys: [{api-key: synthetic-A}, {api-key: synthetic-B}]\n", filepath.ToSlash(authDir), family, base, extra)
					if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
						t.Fatal(err)
					}
					f := newInventoryHarness(t, dir)
					f.manager.SetConfig(f.server.cfg)
					for _, a := range f.manager.List() {
						switch family {
						case "codex":
							f.manager.RegisterExecutor(executor.NewCodexAutoExecutor(f.server.cfg))
						case "claude":
							f.manager.RegisterExecutor(executor.NewClaudeExecutor(f.server.cfg))
						default:
							f.manager.RegisterExecutor(executor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
						}
					}
					q := associationFixtureRequest(t, f)
					for _, key := range []string{"synthetic-A", "synthetic-B"} {
						signAssociation(t, &q, key)
						raw, _ := json.Marshal(q)
						req := httptest.NewRequest("POST", "/v8/management/credential-quota/credential-association", bytes.NewReader(raw))
						req.RemoteAddr = "127.0.0.1:1234"
						req.Header.Set("Authorization", "Bearer test-password")
						w := httptest.NewRecorder()
						f.server.engine.ServeHTTP(w, req)
						var result credentialassociation.Response
						if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
							t.Fatalf("public association status=%d body=%s", w.Code, w.Body.String())
						}
						expected := mode == "standard" && key == "synthetic-A"
						if result.Associated != expected {
							t.Fatalf("public result disagrees with effective current source: %s", w.Body.String())
						}
						if mode != "standard" && result.Reason != "association_unsupported" {
							t.Fatalf("unproven realm/auth result=%s", result.Reason)
						}
						if result.AuthIndex != q.AuthIndex || result.SourceVersion != q.SourceVersion || result.QueryID != q.QueryID || result.Nonce != q.Nonce || !reflect.DeepEqual(result.OfficialBinding, q.Official.Binding) || result.OfficialVersion != q.Official.Version {
							t.Fatal("frozen capture echo changed")
						}
					}
					// Fence failures are real public RPCs against this SAME isolated
					// upstream. Every branch must return without any egress.
					other := associationFixtureForKey(t, f, "synthetic-B")
					for _, negative := range []struct {
						name   string
						mutate func(*credentialassociation.Request)
						status int
						reason string
					}{
						{"stale-source", func(x *credentialassociation.Request) { x.SourceVersion = strings.Repeat("0", 64) }, 409, ""},
						{"stale-selected", func(x *credentialassociation.Request) { x.Selected.Targets[0].CredentialVersion++ }, 409, ""},
						{"stale-official", func(x *credentialassociation.Request) { x.Official.Targets[0].ConfigVersion++ }, 409, ""},
						{"stale-scope", func(x *credentialassociation.Request) { x.Official.Scope.Revision++ }, 409, ""},
						{"other-current-credential-group", func(x *credentialassociation.Request) { x.Official.Binding = other.Selected }, 200, "source_group_mismatch"},
						{"official-origin", func(x *credentialassociation.Request) { x.Official.Endpoint = "https://other.invalid/api/usage/token/" }, 200, "origin_mismatch"},
					} {
						raw, _ := json.Marshal(q)
						var changed credentialassociation.Request
						if err := json.Unmarshal(raw, &changed); err != nil {
							t.Fatal(err)
						}
						negative.mutate(&changed)
						signAssociation(t, &changed, "synthetic-A")
						raw, _ = json.Marshal(changed)
						req := httptest.NewRequest("POST", "/v8/management/credential-quota/credential-association", bytes.NewReader(raw))
						req.RemoteAddr = "127.0.0.1:1234"
						req.Header.Set("Authorization", "Bearer test-password")
						w := httptest.NewRecorder()
						f.server.engine.ServeHTTP(w, req)
						if w.Code != negative.status {
							t.Fatalf("%s fence status=%d want=%d body=%s", negative.name, w.Code, negative.status, w.Body.String())
						}
						var result credentialassociation.Response
						json.Unmarshal(w.Body.Bytes(), &result)
						if result.Associated || result.Proof != nil || negative.reason != "" && result.Reason != negative.reason {
							t.Fatalf("%s incorrectly associated: %s", negative.name, w.Body.String())
						}
						if w.Header().Get("Cache-Control") != "no-store" {
							t.Fatal("negative response cacheable")
						}
						if sends.Load() != 0 {
							t.Fatalf("%s sent upstream traffic", negative.name)
						}
					}
					if sends.Load() != 0 {
						t.Fatal("association RPC sent business/quota traffic")
					}

					var selectedID string
					for _, a := range f.manager.List() {
						if a.Index == q.AuthIndex {
							selectedID = a.ID
						}
					}
					for _, stream := range []bool{false, true} {
						// Invoke the actual registered executor with the SAME host-issued selected
						// auth used by the public RPC; no fake executor and no external networking.
						a, ok := f.manager.GetByID(selectedID)
						if !ok {
							t.Fatal("selected source disappeared")
						}
						e, ok := f.manager.Executor(a.Provider)
						if !ok {
							t.Fatal("registered executor missing")
						}
						if mode == "auth-override" && a.Attributes["header:Authorization"] != "Bearer synthetic-B" {
							t.Fatal("configured override did not reach actual runtime auth")
						}
						ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", tr)
						req := coreexecutor.Request{Model: "controlled-model", Payload: []byte(`{"model":"controlled-model","input":[],"messages":[{"role":"user","content":"synthetic"}]}`)}
						opts := coreexecutor.Options{SourceFormat: format, Stream: stream}
						var err error
						if stream {
							_, err = e.ExecuteStream(ctx, a, req, opts)
						} else {
							_, err = e.Execute(ctx, a, req, opts)
						}
						if err == nil {
							t.Fatal("controlled terminal error missing")
						}
						var observed *http.Request
						select {
						case observed = <-observations:
						default:
							t.Fatalf("actual inference did not reach controlled upstream: %v", err)
						}
						expectedKey := "Bearer synthetic-A"
						if mode == "auth-override" {
							expectedKey = "Bearer synthetic-B"
						}
						if observed.Header.Get("Authorization") != expectedKey || observed.URL.Path != path {
							t.Fatalf("actual auth/path disagrees: header=%q path=%s", observed.Header.Get("Authorization"), observed.URL.Path)
						}
					}
					if sends.Load() != 2 {
						t.Fatalf("actual inference sends=%d want2", sends.Load())
					}
				})
			}
		})
	}
}

func TestCredentialAssociationPublicStrictSecurityBoundary(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	q := associationFixtureRequest(t, f)
	valid, _ := json.Marshal(q)
	cases := map[string][]byte{
		"duplicate-version": bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"escaped-duplicate": bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"\u0076ersion":1`), 1),
		"case-shadow":       bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		"secret-unknown":    bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"secret":"NEVER-RETURN-THIS-CANARY"`), 1),
		"nested-shadow":     bytes.Replace(valid, []byte(`"snapshot_revision":`), []byte(`"Snapshot_revision":`), 1),
		"string-counter":    bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":"1"`), 1),
		"fraction-counter":  bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1.0`), 1),
		"trailing-json":     append(append([]byte{}, valid...), []byte(` {}`)...),
		"invalid-utf8":      append(append([]byte{}, valid...), 0xff),
		"oversized":         append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), credentialassociation.MaxBytes)...),
	}
	before := f.request("inference-gates", 200)
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(body, valid) {
				t.Fatal("unchanged negative fixture")
			}
			for _, authorized := range []bool{false, true} {
				req := httptest.NewRequest("POST", "/v8/management/credential-quota/credential-association", bytes.NewReader(body))
				req.RemoteAddr = "127.0.0.1:1234"
				if authorized {
					req.Header.Set("Authorization", "Bearer test-password")
				}
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, req)
				expected := 401
				if authorized {
					expected = 400
				}
				if w.Code != expected || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("boundary status=%d want=%d no-store=%s", w.Code, expected, w.Header().Get("Cache-Control"))
				}
				if bytes.Contains(w.Body.Bytes(), []byte("NEVER-RETURN-THIS-CANARY")) || bytes.Contains(w.Body.Bytes(), []byte(q.CandidateMAC)) || bytes.Contains(w.Body.Bytes(), []byte("synthetic-A")) {
					t.Fatal("error leaked request/credential")
				}
			}
		})
	}
	after := f.request("inference-gates", 200)
	if !bytes.Equal(before, after) {
		t.Fatal("association error mutated durable gates")
	}
}
