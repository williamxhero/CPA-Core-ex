package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestProviderSchedulingHardAffinityDoesNotLoseLowerPriorityBinding(t *testing.T) {
	for _, mode := range []string{coreauth.SessionAffinityRebindOnNever, coreauth.SessionAffinityRebindOnAny} {
		t.Run(mode, func(t *testing.T) {
			f := newSchedulingHTTPFixture(t, nil)
			f.manager.SetSelector(coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
				Fallback: &coreauth.FillFirstSelector{}, RebindOn: mode,
			}))
			makeUnavailable := func(key string, unavailable bool) {
				t.Helper()
				a, ok := f.manager.GetByID(f.auths[key].ID)
				if !ok {
					t.Fatal("missing fixture route")
				}
				a.Unavailable = unavailable
				a.NextRetryAfter = time.Time{}
				if a.ModelStates == nil {
					a.ModelStates = make(map[string]*coreauth.ModelState)
				}
				if unavailable {
					a.NextRetryAfter = time.Now().Add(time.Hour)
					for model := range a.ModelStates {
						a.ModelStates[model] = &coreauth.ModelState{Unavailable: true, NextRetryAfter: a.NextRetryAfter}
					}
				} else {
					for model := range a.ModelStates {
						a.ModelStates[model] = &coreauth.ModelState{}
					}
				}
				if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
					t.Fatal(err)
				}
			}
			send := func(session string, status int, contains string) {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(simpleSchedulingChat))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer open")
				req.Header.Set("X-Session-ID", session)
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, req)
				if w.Code != status || !strings.Contains(w.Body.String(), contains) {
					t.Fatalf("session %s: status %d want %d with %q: %s", session, w.Code, status, contains, w.Body.String())
				}
			}
			makeUnavailable("A", true)
			send("bound-session", 200, `"content":"C"`)
			makeUnavailable("A", false)
			if mode == coreauth.SessionAffinityRebindOnNever {
				send("bound-session", 200, `"content":"C"`)
			} else {
				send("bound-session", 200, `"content":"A"`)
			}
			send("fresh-session", 200, `"content":"A"`)
			if mode == coreauth.SessionAffinityRebindOnNever {
				makeUnavailable("C", true)
				send("bound-session", 503, "no_available_route")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			want := "[C A A]"
			if mode == coreauth.SessionAffinityRebindOnNever {
				want = "[C C A]"
			}
			if got := fmt.Sprint(f.calls); got != want {
				t.Fatalf("sends=%s want %s", got, want)
			}
		})
	}
}

func TestProviderSchedulingHardLCPBindingWaitsForItsOwnRoute(t *testing.T) {
	f := newSchedulingHTTPFixture(t, nil)
	f.manager.SetSelector(coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback: &coreauth.FillFirstSelector{}, RebindOn: coreauth.SessionAffinityRebindOnNever,
	}))
	f.manager.SetRetryConfig(0, time.Second, 3)
	f.manager.SetUpstreamErrorRetryLimit(-1)
	send := func(messages string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"public-scheduling-model","messages":`+messages+`}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer open")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"content":"A"`) {
			t.Fatalf("hard-bound session should route to A; got status %d: %s", w.Code, w.Body.String())
		}
	}

	send(`[{"role":"user","content":"Explain why ocean tides vary."}]`)
	const model = "public-scheduling-model"
	a := f.auths["A"]
	retryAfter := 700 * time.Millisecond
	f.manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: a.ID, Provider: a.Provider, Model: model, RetryAfter: &retryAfter,
		Error: &coreauth.Error{HTTPStatus: 429, Code: coreauth.ErrorCodeTransientRateLimit, Message: "rate limited"},
	})
	a, _ = f.manager.GetByID(a.ID)
	retryAt := a.ModelStates[model].NextRetryAfter
	if retryAt.IsZero() {
		t.Fatal("fixture did not record the trusted upstream retry time")
	}
	clock := newProviderBudgetClock(retryAt.Add(-retryAfter), true)
	f.manager.SetContinuityClockForTest(clock)

	send(`[{"role":"user","content":"Explain why ocean tides vary."},{"role":"assistant","content":"A"},{"role":"user","content":"How does the moon contribute?"}]`)
	select {
	case wait := <-clock.waits:
		if wait != retryAfter {
			t.Fatalf("wait = %s; want %s", wait, retryAfter)
		}
	default:
		t.Fatal("session did not wait for its bound route")
	}
	select {
	case extra := <-clock.waits:
		t.Fatalf("unexpected second wait: %s", extra)
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := fmt.Sprint(f.calls); got != "[A A]" {
		t.Fatalf("sends = %s; want [A A] despite an unrelated healthy route", got)
	}
}
