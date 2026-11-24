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
		servePersistentPilot(ctx, f, w, pilotResponsesPath, setPilotFixtureField(pilotResponsesBody, "input", text), key)
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

func TestProviderSchedulingPersistentPilotAdmittedRequestSurvivesFailedProbeWithFullQueue(t *testing.T) {
	guard, stop := context.WithTimeout(t.Context(), 8*time.Second)
	defer stop()
	live, cancel := context.WithCancel(t.Context())
	defer cancel()
	clock := newManualPersistentPilotClock()
	var sends atomic.Int32
	probeStarted, finishProbe := make(chan struct{}), make(chan struct{})
	f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, 4,
		"    persistent-retry: {jitter-percent: 0, max-waiters: 1, max-waiters-per-caller: 1}\n",
		func(w http.ResponseWriter, r *http.Request) {
			payload, _ := io.ReadAll(r.Body)
			text := ojson.GetBytes(payload, "input.0.content.0.text").String()
			switch n := sends.Add(1); {
			case n == 1 && text == "original-A":
				w.WriteHeader(http.StatusBadGateway)
			case n == 2 && text == "original-A":
				close(probeStarted)
				select {
				case <-finishProbe:
					w.WriteHeader(http.StatusBadGateway)
				case <-r.Context().Done():
				}
			case n == 3 && text == "after-cancel":
				persistentPilotStart(w, "resp-after-cancel")
				persistentPilotSucceedWithID(w, "resp-after-cancel", "result-after-cancel")
			default:
				t.Errorf("unexpected upstream send %d for %q", n, text)
				w.WriteHeader(http.StatusBadGateway)
			}
		})
	aLive, cancelA := context.WithCancel(live)
	defer cancelA()
	aCtx, a := pilotWaiter(aLive, f, "open", "original-A")
	first := awaitPilotTimer(t, guard, clock, a)
	aID := coreauth.RoutingTraceID(aCtx)
	initial := readSchedulingTraceForTest(t, f, aID)
	if first.at.Sub(clock.Now()) != time.Second || ojson.Get(initial, "last_recovery_wait.waiters").Int() != 1 || ojson.Get(initial, "send_count").Int() != 1 {
		t.Fatalf("A was not already admitted and waiting: %s", initial)
	}
	clock.moveTo(first.at)
	close(first.fire)
	select {
	case <-probeStarted:
	case <-guard.Done():
		t.Fatal("A never acquired the half-open probe")
	}
	bCtx, b := pilotWaiter(live, f, "second-pilot", "new-B")
	// Synchronize on B's wait (the old behavior) or its rejection; either
	// way A's second 502 arrives only after B has tried to take the slot.
	var bRejected bool
	for {
		select {
		case w := <-b:
			bRejected = true
			trace := awaitPilotTerminalTrace(t, guard, f, w.Header().Get("X-Request-ID"))
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"code":"local_backpressure"`) ||
				ojson.Get(trace, "retry_stop_reason").String() != "total_waiter_capacity" || ojson.Get(trace, "send_count").Int() != 0 {
				t.Fatalf("wrong backpressure for new B: %d %s %s", w.Code, w.Body, trace)
			}
		case <-guard.Done():
			t.Fatal("B neither waited nor received backpressure")
		default:
		}
		if bRejected {
			break
		}
		if id := coreauth.RoutingTraceID(bCtx); id != "" {
			trace := readSchedulingTraceForTest(t, f, id)
			if ojson.Get(trace, "last_recovery_wait.probe_pending").Bool() {
				if ojson.Get(trace, "last_recovery_wait.waiters").Int() != 1 || ojson.Get(trace, "send_count").Int() != 0 {
					t.Fatalf("B did not fill the only wait slot during A's probe: %s", trace)
				}
				break
			}
		}
		runtime.Gosched()
	}
	if bRejected {
		_, sameCaller := pilotWaiter(live, f, "open", "same-caller")
		assertPilotBackpressure(t, guard, f, sameCaller, "caller_waiter_capacity")
		var backupSends atomic.Int32
		backupID := addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
			backupSends.Add(1)
			persistentPilotStart(w, "resp-backup")
			persistentPilotSucceedWithID(w, "resp-backup", "result-backup")
		})
		_, backup := pilotWaiter(live, f, "open", "use-backup")
		w := awaitPilotResult(t, guard, backup)
		trace := awaitPilotTerminalTrace(t, guard, f, w.Header().Get("X-Request-ID"))
		if w.Code != http.StatusOK || strings.Count(w.Body.String(), "result-backup") != 1 ||
			backupSends.Load() != 1 || sends.Load() != 2 || ojson.Get(trace, "send_count").Int() != 1 || ojson.Get(trace, "last_recovery_wait").Exists() {
			t.Fatalf("active probe or full admission blocked the healthy backup: %d %s %s", w.Code, w.Body, trace)
		}
		updatePilotAuth(t, f, backupID, func(a *coreauth.Auth) { a.Disabled = true })
	}
	close(finishProbe)
	// Keep request time fixed. B's possible dwell timer isn't A's cooldown.
	want := first.at.Add(2 * time.Second)
	for {
		select {
		case w := <-a:
			trace := awaitPilotTerminalTrace(t, guard, f, aID)
			t.Fatalf("already-admitted A lost its original request after a failed probe: status=%d local_backpressure=%t total_sends=%d A_send_count=%d stop=%s",
				w.Code, strings.Contains(w.Body.String(), `"code":"local_backpressure"`), sends.Load(), ojson.Get(trace, "send_count").Int(), ojson.Get(trace, "retry_stop_reason").String())
		case <-guard.Done():
			t.Fatal("A did not re-enter its recovery wait")
		default:
		}
		trace := readSchedulingTraceForTest(t, f, aID)
		if ojson.Get(trace, "last_recovery_wait.not_before").String() == want.UTC().Format(time.RFC3339Nano) {
			if !bRejected || sends.Load() != 2 || ojson.Get(trace, "send_count").Int() != 2 ||
				ojson.Get(trace, "last_recovery_wait.waiters").Int() != 1 || ojson.Get(trace, "terminal").Exists() {
				t.Fatalf("A did not retain its sole admission and original request: %s", trace)
			}
			break
		}
		runtime.Gosched()
	}
	cancelA()
	awaitPilotResult(t, guard, a)
	trace := awaitPilotTerminalTrace(t, guard, f, aID)
	if ojson.Get(trace, "send_count").Int() != 2 || ojson.Get(trace, "retry_stop_reason").String() != "canceled" {
		t.Fatalf("wrong cancellation accounting for A: %s", trace)
	}
	cCtx, c := pilotWaiter(live, f, "open", "after-cancel")
	timer := awaitPilotTimer(t, guard, clock, c)
	cID := coreauth.RoutingTraceID(cCtx)
	trace = readSchedulingTraceForTest(t, f, cID)
	if !timer.at.Equal(want) || sends.Load() != 2 || ojson.Get(trace, "send_count").Int() != 0 || ojson.Get(trace, "last_recovery_wait.waiters").Int() != 1 {
		t.Fatalf("fresh caller did not acquire the released token and wait for its first send: %s", trace)
	}
	clock.moveTo(timer.at)
	close(timer.fire)
	w := awaitPilotResult(t, guard, c)
	trace = awaitPilotTerminalTrace(t, guard, f, cID)
	if w.Code != http.StatusOK || w.Header().Get("X-Request-ID") != cID || strings.Count(w.Body.String(), "result-after-cancel") != 1 ||
		strings.Count(w.Body.String(), `"type":"response.completed"`) != 1 || ojson.Get(trace, "send_count").Int() != 1 ||
		ojson.Get(trace, "terminal.code").String() != "succeeded" || sends.Load() != 3 {
		t.Fatalf("wrong result after cancellation released admission: %d %s %s", w.Code, w.Body, trace)
	}
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
