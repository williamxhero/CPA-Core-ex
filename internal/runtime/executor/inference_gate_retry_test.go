package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Only the real connection's next write is faulted. Reads, the baseline turn,
// reconnect handshake, durable authority and subsequent network all remain real.
type gateRetryWriteConn struct {
	net.Conn
	fail *atomic.Bool
}

func (c gateRetryWriteConn) Write(p []byte) (int, error) {
	if c.fail.CompareAndSwap(true, false) {
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func TestInferenceGateActualWebsocketInternalResendRechecks(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			retryEntered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var connections, sends atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := connections.Add(1)
				if n == 2 {
					close(retryEntered)
					<-release
				}
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer c.Close()
				for {
					_, _, err := c.ReadMessage()
					if err != nil {
						return
					}
					sends.Add(1)
					c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"r","status":"completed","output":[]}}`))
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			os.MkdirAll(authDir, 0700)
			path := filepath.Join(dir, "config.yaml")
			os.WriteFile(path, []byte(fmt.Sprintf("oauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: gate,base-url: %q,keys: [{api-key: SYNTHETIC}]}]\n", filepath.ToSlash(authDir), upstream.URL)), 0600)
			catalog, err := resourcecatalog.Open(path, authDir, "")
			if err != nil {
				t.Fatal(err)
			}
			defer catalog.Close()
			snapshot, err := catalog.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			var binding resource.Binding
			for _, r := range snapshot.Resources {
				if r.Kind == "credential" {
					binding = resource.Binding{Scope: snapshot.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
				}
			}
			if len(binding.Targets) == 0 {
				t.Fatal("no host-issued binding")
			}
			auth := &coreauth.Auth{ID: "gate-ws", Provider: "codex", ResourceIdentity: &binding, Attributes: map[string]string{"api_key": "SYNTHETIC", "base_url": upstream.URL}}
			e := NewCodexWebsocketsExecutor(&config.Config{})
			e.store = &codexWebsocketSessionStore{sessions: map[string]*codexWebsocketSession{}}
			sessionID := "gate-internal"
			defer e.CloseExecutionSession(sessionID)
			var fail atomic.Bool
			dialer := &websocket.Dialer{NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return gateRetryWriteConn{c, &fail}, nil
			}}
			wsURL := "ws" + strings.TrimPrefix(upstream.URL, "http") + "/responses"
			conn, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			sess := e.getOrCreateSession(sessionID)
			sess.conn = conn
			sess.connCloser = newWebsocketConnectionCloser(conn)
			sess.authID = auth.ID
			sess.wsURL = wsURL
			ctx := coreexecutor.WithInferenceAdmission(context.Background(), func(context.Context) error { return catalog.AdmitInference(&binding, "") })
			req := coreexecutor.Request{Model: "gate-model", Payload: []byte(`{"model":"gate-model","input":[]}`)}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: req.Payload, Metadata: map[string]any{coreexecutor.ExecutionSessionMetadataKey: sessionID}}
			run := func() error {
				if !stream {
					_, err := e.Execute(ctx, auth, req, opts)
					return err
				}
				result, err := e.ExecuteStream(ctx, auth, req, opts)
				if err != nil {
					return err
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						return chunk.Err
					}
				}
				return nil
			}
			if err := run(); err != nil {
				t.Fatal(err)
			}
			if sends.Load() != 1 {
				t.Fatal("baseline real WS turn missing")
			}
			fail.Store(true)
			done := make(chan error, 1)
			go func() { done <- run() }()
			select {
			case <-retryEntered:
			case err := <-done:
				t.Fatalf("internal retry not reached: %v", err)
			case <-time.After(6 * time.Second):
				t.Fatal("internal reconnect barrier missing")
			}
			result, err := catalog.ApplyGate(resource.GateOperation{Version: 1, OpID: "60b2e585-39e5-4559-bdf7-13fdcbb66b21", Binding: binding, Subject: "credential", Owner: "owner-a", Action: "pause", Reason: "quota_exhausted", EvidenceID: "evidence", AuthIndex: "synthetic", SourceVersion: strings.Repeat("a", 64)})
			if err != nil || !result.Durable || !result.Applied {
				t.Fatalf("real durable gate ACK missing: %v", err)
			}
			close(release)
			select {
			case err := <-done:
				if err == nil || (!coreexecutor.IsInferenceAdmissionError(err) && !errors.Is(err, resourcecatalog.ErrGateDenied)) {
					t.Fatalf("resend denial lost classification: %T %v", err, err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("internal resend denial did not settle")
			}
			if sends.Load() != 1 || connections.Load() != 2 {
				t.Fatalf("internal retry sent new business after ACK: frames=%d conns=%d", sends.Load(), connections.Load())
			}
		})
	}
}
