package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const pilotResponsesPath = "/v1/responses"
const pilotResponsesBody = `{"model":"gpt-6.2-sol","stream":true,"input":"PAYLOAD"}`

func pilotWaiter(ctx context.Context, f *inventoryHarness, key, text string) (context.Context, <-chan *httptest.ResponseRecorder) {
	ctx = coreauth.WithFreshRequestBudget(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		servePersistentPilot(ctx, f, w, pilotResponsesPath, strings.ReplaceAll(pilotResponsesBody, "PAYLOAD", text), key)
		done <- w
	}()
	return ctx, done
}

func awaitPilotWaitTrace(t *testing.T, guard, request context.Context, f *inventoryHarness, done <-chan *httptest.ResponseRecorder, field string) string {
	t.Helper()
	for {
		select {
		case r := <-done:
			t.Fatalf("request returned before waiting for %s: %d %s", field, r.Code, r.Body)
		case <-guard.Done():
			t.Fatalf("request %q never waited for %s", coreauth.RoutingTraceID(request), field)
		default:
		}
		if id := coreauth.RoutingTraceID(request); id != "" {
			trace := readSchedulingTraceForTest(t, f, id)
			if ojson.Get(trace, "last_recovery_wait."+field).Bool() {
				return trace
			}
		}
		runtime.Gosched()
	}
}

func assertPilotBackpressure(t *testing.T, guard context.Context, f *inventoryHarness, done <-chan *httptest.ResponseRecorder, reason string) {
	t.Helper()
	r := awaitPilotResult(t, guard, done)
	trace := awaitPilotTerminalTrace(t, guard, f, r.Header().Get("X-Request-ID"))
	if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body.String(), `"code":"local_backpressure"`) ||
		ojson.Get(trace, "retry_stop_reason").String() != reason || ojson.Get(trace, "send_count").Int() != 0 {
		t.Fatalf("wrong backpressure: %d %s %s", r.Code, r.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotBoundedWaiters(t *testing.T) {
	guard, stop := context.WithTimeout(t.Context(), 9*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clock := newManualPersistentPilotClock()
	sends := make(chan string, 8)
	var attempts atomic.Int32
	release := make(chan struct{})
	f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, 1,
		"    persistent-retry: {max-waiters: 1, max-waiters-per-caller: 1}\n", func(w http.ResponseWriter, r *http.Request) {
			payload, _ := io.ReadAll(r.Body)
			text := ojson.GetBytes(payload, "input.0.content.0.text").String()
			sends <- text
			if attempts.Add(1) == 1 {
				select {
				case <-release:
				case <-guard.Done():
					return
				}
			}
			persistentPilotStart(w, "resp-"+text)
			persistentPilotSucceed(w, "result-"+text)
		})
	defer close(release)
	awaitSend := func(want string) {
		t.Helper()
		select {
		case got := <-sends:
			if got != want {
				t.Fatalf("wrong send order: %q, want %q", got, want)
			}
		case <-guard.Done():
			t.Fatalf("missing send for %q", want)
		}
	}
	_, active := pilotWaiter(ctx, f, "open", "active-CANARY")
	awaitSend("active-CANARY")
	oldCtx, old := pilotWaiter(ctx, f, "open", "old-CANARY")
	awaitPilotWaitTrace(t, guard, oldCtx, f, old, "capacity_pending")
	_, rejected := pilotWaiter(guard, f, "open", "rejected-CANARY")
	assertPilotBackpressure(t, guard, f, rejected, "caller_waiter_capacity")
	_, totalRejected := pilotWaiter(guard, f, "second-pilot", "total-CANARY")
	assertPilotBackpressure(t, guard, f, totalRejected, "total_waiter_capacity")
	trace := readSchedulingTraceForTest(t, f, coreauth.RoutingTraceID(oldCtx))
	if attempts.Load() != 1 || ojson.Get(trace, "last_recovery_wait.waiters").Int() != 1 ||
		ojson.Get(trace, "retry_policy.waiter_capacity.per_caller").Int() != 1 || strings.Contains(trace, "CANARY") {
		t.Fatalf("waiting consumes execution or protected readback is wrong: %s", trace)
	}
	// An immediately usable alternate is still allowed despite the primary
	// queue and the caller's full waiter quota. Its own receipt is independent.
	addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
		persistentPilotStart(w, "resp-backup")
		persistentPilotSucceed(w, "healthy-alternate")
	})
	_, backup := pilotWaiter(ctx, f, "open", "alternate-CANARY")
	w := awaitPilotResult(t, guard, backup)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "healthy-alternate") {
		t.Fatalf("healthy alternate blocked by primary queue: %d %s", w.Code, w.Body)
	}
	// Active waiters may now use that alternate as well. FIFO for a single
	// route is tested separately, without making this legal bypass illegal.
	select {
	case release <- struct{}{}:
	case <-guard.Done():
		t.Fatal("cannot release the first execution")
	}
	awaitPilotResult(t, guard, active)
	awaitPilotResult(t, guard, old)
}

func TestProviderSchedulingPersistentPilotQueueOrder(t *testing.T) {
	guard, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	clock := newManualPersistentPilotClock()
	admitted := make(chan string, 8)
	release := make(chan struct{})
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		text := ojson.GetBytes(payload, "input.0.content.0.text").String()
		admitted <- text
		select {
		case <-release:
		case <-guard.Done():
			return
		}
		persistentPilotStart(w, "resp-"+text)
		persistentPilotSucceed(w, "result-"+text)
	})
	defer close(release)
	awaitSend := func(expected string) {
		t.Helper()
		select {
		case text := <-admitted:
			if text != expected {
				t.Fatalf("sent %s, wanted %s", text, expected)
			}
		case <-guard.Done():
			t.Fatalf("missing send for %s", expected)
		}
	}
	_, active := pilotWaiter(guard, f, "open", "working")
	awaitSend("working")
	canceledCtx, cancel := context.WithCancel(guard)
	defer cancel()
	canceledCtx, canceled := pilotWaiter(canceledCtx, f, "open", "canceled")
	awaitPilotWaitTrace(t, guard, canceledCtx, f, canceled, "capacity_pending")
	oldCtx, old := pilotWaiter(guard, f, "open", "old")
	awaitPilotWaitTrace(t, guard, oldCtx, f, old, "capacity_pending")
	youngCtx, young := pilotWaiter(guard, f, "second-pilot", "young")
	awaitPilotWaitTrace(t, guard, youngCtx, f, young, "capacity_pending")
	cancel()
	awaitPilotResult(t, guard, canceled)
	select {
	case release <- struct{}{}:
	case <-guard.Done():
		t.Fatal("cannot release the first execution")
	}
	awaitPilotResult(t, guard, active)
	_, newArrival := pilotWaiter(guard, f, "open", "new-arrival")
	for i, expected := range []string{"old", "young", "new-arrival"} {
		awaitSend(expected)
		select {
		case release <- struct{}{}:
		case <-guard.Done():
			t.Fatal("cannot release controlled send")
		}
		w := awaitPilotResult(t, guard, []<-chan *httptest.ResponseRecorder{old, young, newArrival}[i])
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "result-"+expected) {
			t.Fatalf("wrong response for %s: %d %s", expected, w.Code, w.Body)
		}
	}
}
