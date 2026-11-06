package api

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	gjson "github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
)

// Each child uses a private TLS fallback root without changing machine trust,
// process-global roots in other tests, or the actual production WSS dialer.
// The current race-enabled test executable is reused; this is not an OAuth helper.
func TestCredentialAssociationActualConfiguredCodexAutoWebsocket(t *testing.T) {
	mode := os.Getenv("SPEC92_ASSOCIATION_WS_MODE")
	if mode == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"standard", "authorization-override", "x-api-key-override"} {
			t.Run(mode, func(t *testing.T) {
				child := exec.Command(executable, "-test.run=^TestCredentialAssociationActualConfiguredCodexAutoWebsocket$", "-test.v", "-test.timeout=180s")
				child.Env = append(os.Environ(), "SPEC92_ASSOCIATION_WS_MODE="+mode, "GODEBUG="+os.Getenv("GODEBUG")+",x509usefallbackroots=1")
				output, err := child.CombinedOutput()
				t.Log(string(output))
				if err != nil {
					t.Fatalf("isolated actual WSS proof failed: %v", err)
				}
			})
		}
		return
	}
	if mode != "standard" && mode != "authorization-override" && mode != "x-api-key-override" {
		t.Fatal("invalid isolated mode")
	}
	var handshakes, business, fallback atomic.Int32
	type handshake struct {
		path, authorization, apiKey string
		tls                         bool
	}
	observed := make(chan handshake, 4)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			fallback.Add(1)
			w.WriteHeader(418)
			return
		}
		observed <- handshake{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Api-Key"), r.TLS != nil}
		handshakes.Add(1)
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		for {
			_, frame, err := c.ReadMessage()
			if err != nil {
				return
			}
			if gjson.GetBytes(frame, "type").String() != "response.create" {
				t.Errorf("unexpected upstream business frame: %s", frame)
				return
			}
			n := business.Add(1)
			if gjson.GetBytes(frame, "model").String() != "assoc-ws-model" {
				t.Error("actual upstream model missing")
				return
			}
			created := fmt.Sprintf(`{"type":"response.created","response":{"id":"assoc-%d","model":"assoc-ws-model","output":[]}}`, n)
			completed := fmt.Sprintf(`{"type":"response.completed","response":{"id":"assoc-%d","model":"assoc-ws-model","status":"completed","output":[]}}`, n)
			if err := c.WriteMessage(websocket.TextMessage, []byte(created)); err != nil {
				return
			}
			if err := c.WriteMessage(websocket.TextMessage, []byte(completed)); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	x509.SetFallbackRoots(roots)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	header := ""
	if mode == "authorization-override" {
		header = "      headers: {Authorization: 'Bearer synthetic-B'}\n"
	}
	if mode == "x-api-key-override" {
		header = "      headers: {X-Api-Key: synthetic-B}\n"
	}
	config := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex:\n    - name: association-wss\n      base-url: %q\n%s      keys: [{api-key: synthetic-A, websockets: true}]\n", filepath.ToSlash(authDir), upstream.URL+"/v1", header)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(f.server.cfg))
	for _, a := range f.manager.List() {
		if a.Attributes["websockets"] != "true" {
			t.Fatal("actual configured source did not enable upstream WS")
		}
		registered, ok := f.manager.Executor(a.Provider)
		if !ok {
			t.Fatal("missing actual registered executor")
		}
		if _, ok := registered.(*runtimeexecutor.CodexAutoExecutor); !ok {
			t.Fatal("not actual CodexAuto executor")
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "assoc-ws-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	q := associationFixtureRequest(t, f)
	origin, ok := credentialassociation.HTTPSOrigin(upstream.URL)
	if !ok {
		t.Fatal("invalid controlled TLS origin")
	}
	q.Origin = origin
	q.Official.Endpoint = upstream.URL + "/api/usage/token/"
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
			t.Fatalf("association status=%d body=%s", w.Code, w.Body.String())
		}
		positive := mode == "standard" && key == "synthetic-A"
		reason := "association_unsupported"
		if mode == "standard" {
			reason = "credential_mismatch"
			if positive {
				reason = "selected_credential_association"
			}
		}
		if result.Associated != positive || result.Reason != reason || (result.Proof != nil) != positive {
			t.Fatalf("actual WS source association mismatch: %s", w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("association result cacheable")
		}
		if handshakes.Load() != 0 || business.Load() != 0 || fallback.Load() != 0 {
			t.Fatal("pure association RPC performed upstream traffic")
		}
	}
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.GET("/v1/responses", h.ResponsesWebsocket)
	downstream := httptest.NewServer(f.server.engine)
	defer downstream.Close()
	turn := gateWSTurns(t, downstream.URL, "assoc-ws-model")
	turn()
	turn()
	// Completed downstream frames causally follow actual upstream business sends.
	// Two turns MUST reuse one actual TLS handshake, not silently use HTTP fallback.
	if handshakes.Load() != 1 || business.Load() != 2 || fallback.Load() != 0 {
		t.Fatalf("actual WSS reuse/count mismatch handshakes=%d business=%d HTTPfallback=%d", handshakes.Load(), business.Load(), fallback.Load())
	}
	var actual handshake
	select {
	case actual = <-observed:
	default:
		t.Fatal("no actual WSS handshake")
	}
	expectedAuth := "Bearer synthetic-A"
	if mode == "authorization-override" {
		expectedAuth = "Bearer synthetic-B"
	}
	if !actual.tls || actual.path != "/v1/responses" || actual.authorization != expectedAuth {
		t.Fatalf("effective WSS TLS/auth/path mismatch: %+v", actual)
	}
	if mode == "x-api-key-override" && actual.apiKey != "synthetic-B" {
		t.Fatal("configured X-Api-Key override not observed on actual WSS")
	}
	if mode == "standard" && actual.apiKey != "" {
		t.Fatal("unexpected extra native authentication header")
	}
	t.Logf("ASSOCIATION_WS_PROOF mode=%s TLSverified=true path=/v1/responses handshakes=1 business=2 HTTPfallback=0 RPCegress=0", mode)
}
