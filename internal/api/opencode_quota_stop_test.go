package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

// This opt-in contract loads the real built DLL, routes actual HTTP and checks
// the durable gate. It never uses real credentials or the public upstream.
func TestOpenCodeQuotaActualPluginStopsAfterFirst429(t *testing.T) {
	pluginDir := os.Getenv("OPENCODE_QUOTA_PLUGIN_DIR")
	if pluginDir == "" {
		t.Skip("set OPENCODE_QUOTA_PLUGIN_DIR to the built plugin directory")
	}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			var failed, healthy atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/models") {
					fmt.Fprint(w, `{"data":[{"id":"glm-5.3"},{"id":"deepseek-v4.1-flash"}]}`)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("Authorization") == "Bearer synthetic-exhausted" {
					failed.Add(1)
					w.WriteHeader(429)
					fmt.Fprint(w, "OpenCode Go usage limit reached (weekly, resets in 4d 16h). To keep going now, turn on Extra Usage or upgrade to Go Plus.")
					return
				}
				healthy.Add(1)
				var payload struct {
					Stream bool `json:"stream"`
				}
				_ = json.Unmarshal(body, &payload)
				if payload.Stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"id\":\"r1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"r1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
				} else {
					fmt.Fprint(w, `{"id":"r1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			if err := os.MkdirAll(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nrouting:\n  cooldown: {disable-cooling: true}\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    cpa-credential-opencode:\n      enabled: true\n      allow-http: true\n      base-url: %q\n      api-keys: [{name: exhausted, value: synthetic-exhausted}, {name: healthy, value: synthetic-healthy}]\n", filepath.ToSlash(authDir), filepath.ToSlash(pluginDir), upstream.URL+"/v1")
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"synthetic-exhausted", "synthetic-healthy"} {
				body := fmt.Sprintf(`{"type":"opencode-go","api_key":%q,"disabled":false}`, key)
				if err := os.WriteFile(filepath.Join(authDir, key+".json"), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var exhaustedIndex string
			for boot := 0; boot < 2; boot++ {
				raw, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := config.ParseConfigBytes(raw)
				if err != nil {
					t.Fatal(err)
				}
				host := pluginhost.New()
				t.Cleanup(host.ShutdownAll)
				host.ApplyConfig(context.Background(), cfg)
				t.Cleanup(func() { sdkAuth.RegisterPluginAuthParser(nil) })
				sdkAuth.RegisterPluginAuthParser(host)
				f := newInventoryHarness(t, dir, host)
				host.SetAuthManager(f.manager)
				f.handler.SetPluginHost(host)
				f.server.cfg.DisableCooling = true
				f.manager.SetConfig(f.server.cfg)
				f.manager.SetRetryConfig(3, time.Second, 0)
				host.RegisterModels(context.Background(), registry.GetGlobalRegistry())
				host.RegisterExecutors(f.manager, registry.GetGlobalRegistry())
				for _, a := range f.manager.List() {
					registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "glm-5.3"}, {ID: "deepseek-v4.1-flash"}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
					if a.Attributes["api_key"] == "synthetic-exhausted" {
						exhaustedIndex = a.Index
					}
				}
				if exhaustedIndex == "" {
					t.Fatal("compiled plugin did not publish selected credentials")
				}
				f.manager.SetSelector(&gatePreferASelector{key: "synthetic-exhausted"})
				var sources struct {
					Sources []map[string]any `json:"sources"`
				}
				if err := json.Unmarshal(f.request("credential-quota/sources", 200), &sources); err != nil {
					t.Fatal(err)
				}
				if boot == 0 {
					found := false
					for _, source := range sources.Sources {
						if source["auth_index"] == exhaustedIndex {
							quotaStopPost(t, f, source, true, 1, 200)
							found = true
							break
						}
					}
					if !found {
						t.Fatal("no selected plugin source")
					}
				}
				h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
				f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
				for _, model := range []string{"glm-5.3", "deepseek-v4.1-flash", "glm-5.3"} {
					r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"stream":%t}`, model, stream)))
					r.Header.Set("Content-Type", "application/json")
					ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
					w := httptest.NewRecorder()
					f.server.engine.ServeHTTP(w, r.WithContext(ctx))
					cancel()
					if w.Code != 200 || !strings.Contains(w.Body.String(), "ok") {
						t.Fatalf("healthy fallback status=%d body=%s", w.Code, w.Body.String())
					}
				}
				if failed.Load() != 1 || healthy.Load() != int32((boot+1)*3) {
					t.Fatalf("boot=%d exhausted sends=%d healthy sends=%d", boot, failed.Load(), healthy.Load())
				}
				var ledger struct {
					Gates []map[string]any `json:"gates"`
				}
				if err := json.Unmarshal(f.request("inference-gates", 200), &ledger); err != nil || len(ledger.Gates) != 1 {
					t.Fatalf("durable pause missing: %+v err=%v", ledger, err)
				}
				if boot == 0 {
					var credentials struct {
						Files []map[string]any `json:"files"`
					}
					if err := json.Unmarshal(f.request("credentials", 200), &credentials); err != nil {
						t.Fatal(err)
					}
					found := false
					for _, a := range credentials.Files {
						if a["auth_index"] == exhaustedIndex {
							q := a["quota"].(map[string]any)
							signals := q["signals"].(map[string]any)
							found = signals["OpenCode-Go-Remaining"] == "0"
						}
					}
					if !found {
						t.Fatal("management credential response did not expose immediate zero")
					}
				}
				f.close()
				host.ShutdownAll()
				sdkAuth.RegisterPluginAuthParser(nil)
			}
		})
	}
}
