package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gjson "github.com/MoeForge/moego/ojson"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestInferenceGateActualDuplexRejectsNewBusinessAndDrains(t *testing.T) {
	for _, kind := range []string{"response.steer", "response.create", "response.append"} {
		t.Run(kind, func(t *testing.T) {
			finish := make(chan struct{})
			upstreamDone := make(chan struct{})
			var sends atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(8 * time.Second))
				_, first, err := c.ReadMessage()
				if err != nil || gjson.GetBytes(first, "type").String() != "response.create" {
					t.Error("no initial create")
					return
				}
				sends.Add(1)
				c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"r1","output":[]}}`))
				<-finish
				c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"r1","status":"completed","output":[]}}`))
				for {
					_, b, err := c.ReadMessage()
					if err != nil {
						return
					}
					if typ := gjson.GetBytes(b, "type").String(); typ == "response.create" || typ == "response.append" || typ == "response.steer" {
						sends.Add(1)
					}
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "auth"), 0700)
			text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: first, base-url: %q, keys: [{api-key: synthetic-ws}]}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL)
			os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600)
			f := newInventoryHarness(t, dir)
			f.server.cfg.Codex.ResponseSteering = true
			f.server.cfg.CodexResponseSteering = true
			f.manager.SetConfig(f.server.cfg)
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(f.server.cfg))
			for _, a := range f.manager.List() {
				a.Attributes["websockets"] = "true"
				_, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a)
				if err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "gate-ws-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			}
			source := gateSource(t, f)
			h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.GET("/v1/responses", h.ResponsesWebsocket)
			downstream := httptest.NewServer(f.server.engine)
			defer downstream.Close()
			c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/responses", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(6 * time.Second))
			if err = c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gate-ws-model","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			read := func() []byte {
				t.Helper()
				_, b, err := c.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			if b := read(); gjson.GetBytes(b, "type").String() != "response.created" {
				t.Fatalf("first event: %s", b)
			}
			gatePost(t, f, gateOp(source, 0, "38291010-eb72-4b7f-8747-344bfe7dfd51", "owner-a", "pause"), 200)
			b, _ := json.Marshal(map[string]any{"type": kind, "model": "gate-ws-model", "previous_response_id": "r1", "input": []any{}})
			c.WriteMessage(websocket.TextMessage, b)
			// Queued creates may be rejected only after the admitted response drains.
			if kind != "response.steer" {
				close(finish)
			}
			rejected, completed := false, false
			for !rejected || !completed {
				b = read()
				typ := gjson.GetBytes(b, "type").String()
				if typ == "error" {
					rejected = true
					if kind == "response.steer" {
						close(finish)
					}
				}
				if typ == "response.completed" {
					completed = true
				}
			}
			c.Close()
			<-upstreamDone
			if sends.Load() != 1 {
				t.Fatalf("new business bypassed gate sends=%d", sends.Load())
			}
		})
	}
}

// A single downstream connection spans the ACK. Each turn must reach a final
// response event, so upstream-send counts are observed after a causal barrier.
func gateWSTurns(t *testing.T, url, model string) func() {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http")+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return func() {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(6 * time.Second))
		body, _ := json.Marshal(map[string]any{"type": "response.create", "model": model, "input": []any{map[string]any{"role": "user", "content": "synthetic"}}})
		if err := c.WriteMessage(websocket.TextMessage, body); err != nil {
			t.Fatal(err)
		}
		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				t.Fatal(err)
			}
			switch gjson.GetBytes(b, "type").String() {
			case "response.completed":
				return
			case "error", "response.failed":
				t.Fatalf("WS turn failed: %s", b)
			}
		}
	}
}
