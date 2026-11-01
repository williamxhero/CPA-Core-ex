package executor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func nativeAssociationRequest(t *testing.T, key string) credentialassociation.Request {
	t.Helper()
	raw, err := os.ReadFile("../../credentialassociation/testdata/association-v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Base json.RawMessage `json:"baseRequest"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var q credentialassociation.Request
	if err = json.Unmarshal(fixture.Base, &q); err != nil {
		t.Fatal(err)
	}
	q.Origin = "https://association.test:443"
	signNativeAssociation(t, &q, key)
	return q
}
func signNativeAssociation(t *testing.T, q *credentialassociation.Request, key string) {
	t.Helper()
	b, err := credentialassociation.Envelope(*q)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write(b)
	q.CandidateMAC = base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func TestCredentialAssociationRejectsNativeOAuthAndUnknown(t *testing.T) {
	a := &coreauth.Auth{Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant-oat01-CONTROLLED", "base_url": "https://association.test"}}
	q := nativeAssociationRequest(t, a.Attributes["api_key"])
	if match, reason := executorAssociationForTest(NewClaudeExecutor(&config.Config{}), a, q); match || reason != "association_unsupported" {
		t.Fatalf("OAuth credential certified as API key: associated=%t reason=%s", match, reason)
	}
	for _, a := range []*coreauth.Auth{nil, {Provider: "codex"}, {SourcePluginID: "unverified", Attributes: map[string]string{"api_key": "CONTROLLED-A", "base_url": "https://association.test/v1"}}} {
		if match, reason := executorAssociationForTest(nil, a, q); match || reason != "association_unsupported" {
			t.Fatalf("unproven route associated=%t reason=%s", match, reason)
		}
	}
}

// Observe the ACTUAL native HTTP and SSE execution send, with authenticated TLS
// pinned to a controlled local listener. Association reads themselves send zero.
// A terminal controlled 418 avoids claiming a successful provider response.
func TestCredentialAssociationActualNativeEffectiveAuthAndPath(t *testing.T) {
	for _, family := range []string{"codex", "codex-auto", "claude", "compat"} {
		t.Run(family, func(t *testing.T) {
			for _, mode := range []string{"standard", "authorization-override", "x-api-key-override", "tenant-prefix"} {
				t.Run(mode, func(t *testing.T) {
					var sends atomic.Int32
					observed := make(chan *http.Request, 2)
					upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						io.Copy(io.Discard, r.Body)
						sends.Add(1)
						observed <- r.Clone(context.Background())
						w.WriteHeader(418)
						io.WriteString(w, `{"error":{"message":"controlled terminal response"}}`)
					}))
					defer upstream.Close()
					tr := upstream.Client().Transport.(*http.Transport).Clone()
					tr.TLSClientConfig.ServerName = upstream.Certificate().DNSNames[0]
					if tr.TLSClientConfig.InsecureSkipVerify {
						t.Fatal("unverified TLS fixture")
					}
					tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
					}
					defer tr.CloseIdleConnections()
					cfg := &config.Config{}
					var e coreauth.ProviderExecutor
					base := "https://association.test/v1"
					path := "/v1/responses"
					format := sdktranslator.FormatOpenAIResponse
					switch family {
					case "codex":
						e = NewCodexExecutor(cfg)
					case "codex-auto":
						e = NewCodexAutoExecutor(cfg)
					case "claude":
						e = NewClaudeExecutor(cfg)
						base = "https://association.test"
						path = "/v1/messages"
						format = sdktranslator.FormatClaude
					case "compat":
						e = NewOpenAICompatExecutor("compat", cfg)
						path = "/v1/chat/completions"
						format = sdktranslator.FormatOpenAI
					}
					attrs := map[string]string{"api_key": "CONTROLLED-A", "base_url": base}
					if mode == "tenant-prefix" {
						attrs["base_url"] = "https://association.test/tenant/B"
						if family != "claude" {
							attrs["base_url"] += "/v1"
						}
						path = "/tenant/B" + path
					}
					if mode == "authorization-override" {
						attrs["header:Authorization"] = "Bearer CONTROLLED-B"
					}
					if mode == "x-api-key-override" {
						attrs["header:X-Api-Key"] = "CONTROLLED-B"
					}
					a := &coreauth.Auth{ID: "association-controlled", Provider: family, Attributes: attrs}
					q := nativeAssociationRequest(t, "CONTROLLED-A")
					match, reason := executorAssociationForTest(e, a, q)
					if mode == "standard" {
						if !match || reason != "selected_credential_association" {
							t.Fatalf("native standard unavailable: %t %s", match, reason)
						}
					} else if match || reason != "association_unsupported" {
						t.Fatalf("unsafe routing certified: %t %s", match, reason)
					}
					if sends.Load() != 0 {
						t.Fatal("association performed upstream send")
					}
					for _, stream := range []bool{false, true} {
						payload := []byte(`{"model":"controlled-model","input":[],"messages":[{"role":"user","content":"hello"}]}`)
						ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", tr)
						req := coreexecutor.Request{Model: "controlled-model", Payload: payload}
						opts := coreexecutor.Options{SourceFormat: format, Stream: stream}
						var err error
						if stream {
							_, err = e.ExecuteStream(ctx, a, req, opts)
						} else {
							_, err = e.Execute(ctx, a, req, opts)
						}
						if err == nil {
							t.Fatal("controlled terminal upstream error missing")
						}
						var r *http.Request
						select {
						case r = <-observed:
						default:
							t.Fatalf("business send never reached actual controlled transport: %v", err)
						}
						if r.URL.Path != path {
							t.Fatalf("actual path=%s expected=%s", r.URL.Path, path)
						}
						expected := "Bearer CONTROLLED-A"
						if mode == "authorization-override" {
							expected = "Bearer CONTROLLED-B"
						}
						if r.Header.Get("Authorization") != expected {
							t.Fatalf("actual effective authorization mismatch: %q", r.Header.Get("Authorization"))
						}
						if mode == "x-api-key-override" && r.Header.Get("X-Api-Key") != "CONTROLLED-B" {
							t.Fatal("custom auth header silently ignored in test")
						}
						if family == "claude" && r.URL.RawQuery != "beta=true" {
							t.Fatal("Claude actual native beta query not preserved")
						}
					}
					if sends.Load() != 2 {
						t.Fatalf("actual send count=%d want2", sends.Load())
					}
					signNativeAssociation(t, &q, "CONTROLLED-B")
					if match, _ = executorAssociationForTest(e, a, q); match {
						t.Fatal("other key associated")
					}
					if bytes.Contains([]byte(reason), []byte("CONTROLLED")) {
						t.Fatal("secret-bearing reason")
					}
				})
			}
		})
	}
}

// Tests invoke the additive method without manufacturing effective credentials.
func executorAssociationForTest(e coreauth.ProviderExecutor, a *coreauth.Auth, q credentialassociation.Request) (bool, string) {
	if native, ok := e.(interface {
		CredentialAssociation(*coreauth.Auth, credentialassociation.Request) (bool, string)
	}); ok {
		return native.CredentialAssociation(a, q)
	}
	return false, "association_unsupported"
}
