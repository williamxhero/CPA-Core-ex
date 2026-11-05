package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// Schedule a real runtime update at the request's closing cancellation check.
// The real route, source binder, auth manager and native matcher still execute;
// no sleeps, substitute matchers or production test callbacks are involved.
type providerKeyMatchClosingContext struct {
	context.Context
	once          sync.Once
	beforeClosing func()
}

func (c *providerKeyMatchClosingContext) Err() error {
	c.once.Do(c.beforeClosing)
	return c.Context.Err()
}

func TestProviderKeyMatchPublicRejectsDispatchSelectorDrift(t *testing.T) {
	for _, phase := range []string{"opening", "closing"} {
		for _, member := range []string{"selected", "sibling"} {
			for _, selector := range []string{"provider_key", "compat_name"} {
				for _, destination := range []string{"missing", "wrapper", "native"} {
					t.Run(strings.Join([]string{phase, member, selector, destination}, "/"), func(t *testing.T) {
						x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
						trapProviderKeyMatchDispatchEgress(t, x)
						q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
						body := mustProviderJSON(t, q)
						providerKeyMatchRaw(t, x.f, body, "test-password", 200)
						driftKey := "openai-compatible-redirected-" + destination
						switch destination {
						case "wrapper":
							x.f.manager.RegisterExecutor(providerKeyMatchImpostor{runtimeexecutor.NewOpenAICompatExecutor(driftKey, x.f.server.cfg)})
						case "native":
							x.f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(driftKey, x.f.server.cfg))
						}
						if _, registered := x.f.manager.Executor(driftKey); registered != (destination != "missing") {
							t.Fatal("redirected executor registration does not match fixture")
						}
						changed := false
						drift := func() {
							for _, a := range x.f.manager.List() {
								key := "SYNTHETIC-A1"
								if member == "sibling" {
									key = "SYNTHETIC-A2"
								}
								if a.Attributes["api_key"] != key {
									continue
								}
								if a.Attributes["compat_name"] == "" {
									t.Fatal("fixture requires actual compatibility dispatch attributes")
								}
								if selector == "compat_name" {
									delete(a.Attributes, "provider_key")
								}
								// Preserve Provider, locator, source, actual credentials
								// and issued Binding; only real dispatch changes.
								a.Attributes[selector] = driftKey
								if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
									t.Fatal(err)
								}
								changed = true
								return
							}
							t.Fatal("runtime member missing from fixture")
						}
						ctx := context.Background()
						if phase == "opening" {
							drift()
						} else {
							ctx = &providerKeyMatchClosingContext{Context: ctx, beforeClosing: drift}
						}
						want := 409
						if destination == "missing" {
							want = 503
						} else if destination == "wrapper" {
							want = 422
						}
						providerKeyMatchRawContext(t, ctx, x.f, body, "test-password", want)
						if !changed {
							t.Fatal("closing drift was not scheduled")
						}
						// S1's frozen routing receipt stays unchanged. Key-match
						// must independently reject the actual dispatch mismatch.
						e := providerEligibility(t, x.f, resource.Binding{Scope: q["scope"].(resource.Version), Targets: q["targets"].([]resource.Target)})
						if !e.Ready || !e.Supported || e.SourceVersion != q["sourceVersion"] {
							t.Fatal("selector-only drift unexpectedly changed the frozen S1 proof")
						}
					})
				}
			}
		}
	}
}

func TestProviderKeyMatchPublicCanonicalDispatchSelectors(t *testing.T) {
	for _, member := range []string{"selected", "sibling"} {
		for _, mode := range []string{"normalized-key", "compat-name-fallback", "provider-fallback", "ignored-key-without-compat-name", "key-precedes-compat-name"} {
			t.Run(member+"/"+mode, func(t *testing.T) {
				x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
				trapProviderKeyMatchDispatchEgress(t, x)
				q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
				for _, a := range x.f.manager.List() {
					key := "SYNTHETIC-A1"
					if member == "sibling" {
						key = "SYNTHETIC-A2"
					}
					if a.Attributes["api_key"] != key {
						continue
					}
					switch mode {
					case "normalized-key":
						a.Attributes["provider_key"] = "  " + strings.ToUpper(a.Provider) + "  "
					case "compat-name-fallback":
						delete(a.Attributes, "provider_key")
						a.Attributes["compat_name"] = "  " + strings.ToUpper(a.Attributes["compat_name"]) + "  "
					case "provider-fallback":
						delete(a.Attributes, "provider_key")
						delete(a.Attributes, "compat_name")
					case "ignored-key-without-compat-name":
						delete(a.Attributes, "compat_name")
						a.Attributes["provider_key"] = "unregistered-but-not-selected"
					case "key-precedes-compat-name":
						a.Attributes["compat_name"] = "unregistered-but-not-selected"
					}
					if _, err := x.f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
						t.Fatal(err)
					}
				}
				var got struct{ Matched bool }
				if err := json.Unmarshal(providerKeyMatchRaw(t, x.f, mustProviderJSON(t, q), "test-password", 200), &got); err != nil || !got.Matched {
					t.Fatal("canonical dispatch selecting the same native executor must still match")
				}
			})
		}
	}
}

func TestProviderKeyMatchPublicCancelledClosing(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com")
	trapProviderKeyMatchDispatchEgress(t, x)
	q := providerKeyMatchQuery(t, x, "SYNTHETIC-A1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	providerKeyMatchRawContext(t, ctx, x.f, mustProviderJSON(t, q), "test-password", 503)
}

func trapProviderKeyMatchDispatchEgress(t *testing.T, x *providerGateFixture) {
	t.Helper()
	trap := &gateEgressCounter{}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = trap
	x.f.manager.SetRoundTripperProvider(gateFixedTransport{rt: trap})
	x.f.handler.SetQuotaNetwork(credentialquota.NetworkOptions{
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			trap.calls.Add(1)
			return nil, fmt.Errorf("controlled dispatch quota DNS reached")
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			trap.calls.Add(1)
			return nil, fmt.Errorf("controlled dispatch quota dial reached")
		},
	})
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		if trap.calls.Load() != 0 {
			t.Error("key-match dispatch validation performed network I/O")
		}
	})
}
