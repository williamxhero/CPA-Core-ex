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
