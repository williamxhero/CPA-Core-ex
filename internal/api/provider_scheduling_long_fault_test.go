package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

func TestProviderSchedulingPersistentPilotTwoHourCadence(t *testing.T) {
	clock := newManualPersistentPilotClock()
	start := clock.Now()
	guard, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sends := make(chan time.Time, 64)
	f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, 1,
		fmt.Sprintf("    persistent-retry: {jitter-percent: 0}\n    caller-funding: {%x: []}\n", sha256.Sum256([]byte(sdkaccess.DefaultAccessProviderName+"\x00second-pilot"))), func(w http.ResponseWriter, _ *http.Request) {
			sends <- clock.Now()
			w.WriteHeader(http.StatusBadGateway)
		})
	rec := httptest.NewRecorder()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		servePersistentPilot(ctx, f, rec, "/v1/chat/completions", persistentPilotChat, "open")
		done <- rec
	}()
	at := []int{0, 1, 3, 7, 15, 75, 135, 195, 255, 555, 855, 1155, 1455, 1755, 2055, 2355, 2655, 2955, 3255, 3555, 3855, 4155, 4455, 4755, 5055, 5355, 5655, 5955, 6255, 6555, 6855, 7155, 7455}
	for i, sec := range at {
		if i > 0 {
			timer := awaitPilotTimer(t, guard, clock, done)
			want := start.Add(time.Duration(sec) * time.Second)
			if !timer.at.Equal(want) {
				t.Fatalf("send %d timer = %v from start, want %ds", i+1, timer.at.Sub(start), sec)
			}
			if i == 1 {
				trace := readSchedulingTraceForTest(t, f, rec.Header().Get("X-Request-ID"))
				if ojson.Get(trace, "retry_policy.cadence.probe_backoff.3").String() != "8s" || ojson.Get(trace, "retry_policy.cadence.jitter_percent").Raw != "0" {
					t.Fatalf("effective cadence missing: %s", trace)
				}
			}
			if sec > 7200 {
				clock.moveTo(start.Add(7200 * time.Second))
				// Churn through more than the completed receipt ring without
				// touching the pilot route or restarting the original request.
				for range 270 {
					ctl := httptest.NewRecorder()
					servePersistentPilot(guard, f, ctl, "/v1/chat/completions", strings.ReplaceAll(persistentPilotChat, persistentPilotModel, "pilot-control-model"), "second-pilot")
					if ctl.Code != http.StatusServiceUnavailable || ctl.Header().Get("X-Request-ID") == "" {
						t.Fatal("control did not create an independent receipt")
					}
				}
				select {
				case got := <-sends:
					t.Fatalf("extra send by two hours: %v", got.Sub(start))
				case r := <-done:
					t.Fatalf("original request stopped at two hours: %s", r.Body)
				default:
				}
			}
			clock.moveTo(want)
			close(timer.fire)
		}
		select {
		case got := <-sends:
			if got.Sub(start) != time.Duration(sec)*time.Second {
				t.Fatalf("send %d at %v, want %ds", i+1, got.Sub(start), sec)
			}
		case <-guard.Done():
			t.Fatalf("missing send %d", i+1)
		}
	}
	_ = awaitPilotTimer(t, guard, clock, done)
	id := rec.Header().Get("X-Request-ID")
	trace := readSchedulingTraceForTest(t, f, id)
	if ojson.Get(trace, "send_count").Int() != 33 || ojson.Get(trace, "last_recovery_wait.cadence_tier").String() != "long" ||
		ojson.Get(trace, "last_recovery_wait.timing_source").String() != "local_backoff" || ojson.Get(trace, "last_recovery_wait.waiters").Int() != 1 {
		t.Fatalf("active receipt unavailable after >2h or missing route state: %s", trace)
	}
	cancel()
	awaitPilotResult(t, guard, done)
	trace = awaitPilotTerminalTrace(t, guard, f, id)
	if ojson.Get(trace, "retry_stop_reason").String() != "canceled" {
		t.Fatalf("missing terminal receipt after long wait: %s", trace)
	}
}

type pilotAlarmLog struct {
	mu     sync.Mutex
	events []string
}

func (l *pilotAlarmLog) Levels() []log.Level { return []log.Level{log.InfoLevel, log.WarnLevel} }
func (l *pilotAlarmLog) Fire(e *log.Entry) error {
	if event, _ := e.Data["event"].(string); event == "pilot_route_fault" || event == "pilot_route_resolved" {
		l.mu.Lock()
		l.events = append(l.events, event)
		l.mu.Unlock()
	}
	return nil
}
func (l *pilotAlarmLog) snapshot() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.events, ",")
}

func capturePilotAlarms(t *testing.T) *pilotAlarmLog {
	t.Helper()
	logger := log.StandardLogger()
	hook := &pilotAlarmLog{}
	prior := logger.ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() { logger.ReplaceHooks(prior) })
	logger.AddHook(hook)
	return hook
}

func TestProviderSchedulingPersistentPilotTwoFaultRecoveries(t *testing.T) {
	hook := capturePilotAlarms(t)

	guard, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clock := newManualPersistentPilotClock()
	start := clock.Now()
	var failing atomic.Bool
	var sends atomic.Int32
	blocks := make(chan chan struct{}, 8)
	f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, 4,
		"    persistent-retry: {jitter-percent: 0}\n", func(w http.ResponseWriter, r *http.Request) {
			sends.Add(1)
			if failing.Load() {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			payload, _ := io.ReadAll(r.Body)
			text := ojson.GetBytes(payload, "input.0.content.0.text").String()
			if strings.HasPrefix(text, "hold-") {
				release := make(chan struct{})
				blocks <- release
				select {
				case <-release:
				case <-guard.Done():
					return
				}
			}
			persistentPilotStart(w, "resp-"+text)
			persistentPilotSucceed(w, "result-"+text)
		})
	const fault = "pilot_route_fault"
	const resolved = "pilot_route_resolved"
	awaitBlock := func() chan struct{} {
		t.Helper()
		select {
		case release := <-blocks:
			return release
		case <-guard.Done():
			t.Fatal("missing real upstream execution")
			return nil
		}
	}
	awaitTrace := func(w *httptest.ResponseRecorder, successes int64) {
		t.Helper()
		trace := awaitPilotTerminalTrace(t, guard, f, w.Header().Get("X-Request-ID"))
		if w.Code != http.StatusOK || ojson.Get(trace, "pilot_recovery.consecutive_successes").Int() != successes {
			t.Fatalf("missing recovery accounting: %d %s", w.Code, trace)
		}
	}
	for cycle := range 2 {
		failing.Store(true)
		clock.moveTo(start.Add(time.Duration(cycle) * 10000 * time.Second))
		before := sends.Load()
		_, original := pilotWaiter(ctx, f, "open", "original")
		var logs string
		if cycle > 0 {
			logs = fault + "," + resolved + ","
		}
		steps := []int{1, 2, 4, 8, 60, 60, 60, 60}
		for range 24 {
			steps = append(steps, 300)
		}
		for i, sec := range steps {
			timer := awaitPilotTimer(t, guard, clock, original)
			if timer.at.Sub(clock.Now()) != time.Duration(sec)*time.Second {
				t.Fatalf("cycle %d probe %d: wait %s, want %ds", cycle, i, timer.at.Sub(clock.Now()), sec)
			}
			wantLogs := strings.TrimSuffix(logs, ",")
			if i >= 4 {
				wantLogs = logs + fault
			}
			if got := hook.snapshot(); got != wantLogs {
				t.Fatalf("cycle %d probe %d: alarm events %q want %q", cycle, i, got, wantLogs)
			}
			if i == 10 {
				late, cancelLate := context.WithCancel(ctx)
				defer cancelLate()
				_, lateDone := pilotWaiter(late, f, "second-pilot", "late-CANARY")
				lateTimer := awaitPilotTimer(t, guard, clock, lateDone)
				if !lateTimer.at.Equal(timer.at) {
					t.Fatalf("late waiter changed cadence: %v vs %v", lateTimer.at, timer.at)
				}
				cancelLate()
				awaitPilotResult(t, guard, lateDone)
				// Removing B wakes and re-evaluates A; synchronize with A's
				// replacement timer before advancing the shared clock.
				replacement := awaitPilotTimer(t, guard, clock, original)
				if !replacement.at.Equal(timer.at) {
					t.Fatalf("cancellation changed cadence: %v vs %v", replacement.at, timer.at)
				}
				timer = replacement
			}
			if i == 31 {
				clock.moveTo(start.Add(time.Duration(cycle*10000+7200) * time.Second))
				if sends.Load()-before != 32 {
					t.Fatalf("cycle %d: sends at t=7155: %d", cycle, sends.Load()-before)
				}
				failing.Store(false)
			}
			clock.moveTo(timer.at)
			close(timer.fire)
		}
		awaitTrace(awaitPilotResult(t, guard, original), 1)
		// A verification failure returns to the previous 300s interval and
		// leaves the same fault alarm active. The original re-failing request
		// recovers, then the serial/two/full ramp starts over.
		failing.Store(true)
		_, retry := pilotWaiter(ctx, f, "open", "verification-failure")
		timer := awaitPilotTimer(t, guard, clock, retry)
		if timer.at.Sub(clock.Now()) != 300*time.Second || hook.snapshot() != logs+fault {
			t.Fatalf("verification failure reset tier or alarm: %v %s", timer.at.Sub(clock.Now()), hook.snapshot())
		}
		failing.Store(false)
		clock.moveTo(timer.at)
		close(timer.fire)
		awaitTrace(awaitPilotResult(t, guard, retry), 1)

		_, second := pilotWaiter(ctx, f, "open", "hold-second")
		secondRelease := awaitBlock()
		thirdCtx, third := pilotWaiter(ctx, f, "second-pilot", "hold-third")
		awaitPilotWaitTrace(t, guard, thirdCtx, f, third, "capacity_pending")
		close(secondRelease)
		awaitTrace(awaitPilotResult(t, guard, second), 2)
		thirdRelease := awaitBlock()
		_, fourth := pilotWaiter(ctx, f, "open", "hold-fourth")
		fourthRelease := awaitBlock() // two validated successes permit two inflight
		fifthCtx, fifth := pilotWaiter(ctx, f, "second-pilot", "hold-fifth")
		awaitPilotWaitTrace(t, guard, fifthCtx, f, fifth, "capacity_pending")
		close(thirdRelease)
		awaitTrace(awaitPilotResult(t, guard, third), 3)
		fifthRelease := awaitBlock()
		if hook.snapshot() != logs+fault {
			t.Fatal("three successes without 60s shouldn't resolve")
		}
		// Two executions remain in flight at the validation cap. The clock
		// alone, after the third success, makes room for the queued request.
		sixthCtx, sixth := pilotWaiter(ctx, f, "second-pilot", "hold-sixth")
		awaitPilotWaitTrace(t, guard, sixthCtx, f, sixth, "capacity_pending")
		stable := awaitPilotTimer(t, guard, clock, sixth)
		if stable.at.Sub(clock.Now()) != 60*time.Second {
			t.Fatalf("wrong stability threshold: %v", stable.at.Sub(clock.Now()))
		}
		clock.moveTo(stable.at)
		close(stable.fire)
		sixthRelease := awaitBlock()
		if got := hook.snapshot(); got != logs+fault+","+resolved {
			t.Fatalf("cycle %d: wrong final alarm events %q", cycle, got)
		}
		// Four, five and six remain in flight. A seventh now fits under
		// the existing cap of four; no old execution had to finish first.
		_, seventh := pilotWaiter(ctx, f, "open", "hold-full")
		seventhRelease := awaitBlock()
		var done = []<-chan *httptest.ResponseRecorder{fourth, fifth, sixth, seventh}
		release := []chan struct{}{fourthRelease, fifthRelease, sixthRelease, seventhRelease}
		for i, r := range release {
			close(r)
			awaitPilotResult(t, guard, done[i])
		}
	}
}

func TestProviderSchedulingPersistentPilotLongHintDwellAndCancel(t *testing.T) {
	hook := capturePilotAlarms(t)
	guard, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clock := newManualPersistentPilotClock()
	start := clock.Now()
	var sends atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if sends.Add(1) == 1 {
			w.Header().Set("Retry-After", "7200")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		persistentPilotStart(w, "resp-from-new-caller")
		persistentPilotSucceed(w, "still-live")
	})
	aCtx, a := pilotWaiter(ctx, f, "open", "abandoned-A")
	dwell := awaitPilotTimer(t, guard, clock, a)
	if dwell.at.Sub(start) != 300*time.Second || hook.snapshot() != "" {
		t.Fatalf("wrong alarm wake: %v at %s", dwell.at.Sub(start), hook.snapshot())
	}
	clock.moveTo(dwell.at)
	close(dwell.fire)
	retry := awaitPilotTimer(t, guard, clock, a)
	trace := readSchedulingTraceForTest(t, f, coreauth.RoutingTraceID(aCtx))
	if sends.Load() != 1 || retry.at.Sub(start) != 7200*time.Second || hook.snapshot() != "pilot_route_fault" ||
		ojson.Get(trace, "last_recovery_wait.timing_source").String() != "retry_after" || !ojson.Get(trace, "pilot_recovery.alarmed").Bool() {
		t.Fatalf("dwell alarm changed the trusted floor: %v %d %s", retry.at.Sub(start), sends.Load(), trace)
	}
	bCtx, b := pilotWaiter(ctx, f, "second-pilot", "abandoned-B")
	bTimer := awaitPilotTimer(t, guard, clock, b)
	if !bTimer.at.Equal(retry.at) {
		t.Fatalf("arrival changed the trusted floor: %v", bTimer.at.Sub(start))
	}
	cancel()
	for _, ch := range []<-chan *httptest.ResponseRecorder{a, b} {
		awaitPilotResult(t, guard, ch)
	}
	trace = awaitPilotTerminalTrace(t, guard, f, coreauth.RoutingTraceID(bCtx))
	if ojson.Get(trace, "retry_stop_reason").String() != "canceled" || ojson.Get(trace, "send_count").Int() != 0 {
		t.Fatalf("bad cancellation accounting: %s", trace)
	}
	clock.moveTo(start.Add(3 * time.Hour))
	close(retry.fire)
	close(bTimer.fire)
	if sends.Load() != 1 {
		t.Fatal("abandoned request sent after cancellation")
	}
	// No synthetic work occurred: the next send belongs to a fresh caller.
	freshCtx, cancelFresh := context.WithCancel(t.Context())
	defer cancelFresh()
	_, fresh := pilotWaiter(freshCtx, f, "open", "fresh")
	w := awaitPilotResult(t, guard, fresh)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "still-live") || sends.Load() != 2 || hook.snapshot() != "pilot_route_fault" {
		t.Fatalf("wrong post-cancel state: %d %d %s", w.Code, sends.Load(), hook.snapshot())
	}
}

func TestProviderSchedulingPersistentPilotRollbackOnYAMLReload(t *testing.T) {
	guard, stop := context.WithTimeout(t.Context(), 8*time.Second)
	defer stop()
	clock := newManualPersistentPilotClock()
	var sends atomic.Int32
	f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, 1,
		"    persistent-retry: {probe-backoff: [3s, 5s, 7s, 9s], jitter-percent: 0}\n", func(w http.ResponseWriter, _ *http.Request) {
			sends.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		})
	call := func(body string) *httptest.ResponseRecorder {
		return awaitPilotResult(t, guard, startPilotRequest(guard, f, "/v1/chat/completions", body))
	}
	w := call(persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != http.StatusBadGateway || ojson.Get(trace, "retry_policy.cadence.probe_backoff.0").String() != "3s" || ojson.Get(trace, "pilot_recovery.failures").Int() != 1 {
		t.Fatalf("pilot did not apply nested YAML: %d %s", w.Code, trace)
	}
	// A registered but nonpilot model remains outside the policy even
	// when the authenticated caller matches enforce mode.
	w = call(strings.ReplaceAll(persistentPilotChat, persistentPilotModel, "pilot-control-model"))
	trace = readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != http.StatusBadGateway || ojson.Get(trace, "retry_policy").Exists() || sends.Load() != 2 {
		t.Fatalf("control model entered pilot: %d %d %s", w.Code, sends.Load(), trace)
	}
	path := f.server.configFilePath
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.ReplaceAll(string(raw), "persistent-retry-models: [gpt-6.2-sol]", "persistent-retry-models: []")
	if updated == string(raw) {
		t.Fatal("rollback fixture did not remove the model")
	}
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Apply the parsed config through the same public Core and server entry
	// points used by the service reload path (no watcher timing dependency).
	if !f.manager.ApplyConfigWithCooldownStateStore(guard, cfg, nil) || !f.server.UpdateClientsContext(guard, cfg) {
		t.Fatal("could not apply rollback YAML")
	}
	w = call(persistentPilotChat)
	trace = readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != http.StatusBadGateway || sends.Load() != 3 || ojson.Get(trace, "retry_policy").Exists() {
		t.Fatalf("removed model still subject to pilot cooldown or policy: %d %d %s", w.Code, sends.Load(), trace)
	}
}

type pilotCloseBarrier struct {
	io.ReadCloser
	entered chan<- struct{}
	release <-chan struct{}
}

func (b pilotCloseBarrier) Close() error {
	err := b.ReadCloser.Close()
	close(b.entered)
	<-b.release
	return err
}

func TestProviderSchedulingPersistentPilotCanceledProbeTeardown(t *testing.T) {
	for _, beforeHeaders := range []bool{false, true} {
		name := "raw-sse-body-close"
		if beforeHeaders {
			name = "provider-not-returned"
		}
		t.Run(name, func(t *testing.T) {
			guard, stop := context.WithTimeout(t.Context(), 8*time.Second)
			defer stop()
			ctxA, cancelA := context.WithCancel(t.Context())
			defer cancelA()
			clock := newManualPersistentPilotClock()
			var sends atomic.Int32
			probe, downstreamRead := make(chan struct{}), make(chan struct{})
			closing, release := make(chan struct{}), make(chan struct{})
			f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, 4,
				"    persistent-retry: {jitter-percent: 0}\n", func(w http.ResponseWriter, r *http.Request) {
					switch sends.Add(1) {
					case 1:
						w.WriteHeader(http.StatusBadGateway)
					case 2:
						if !beforeHeaders {
							persistentPilotStart(w, "resp-probe")
							io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"probe\"}\n\n")
							w.(http.Flusher).Flush()
						}
						close(probe)
						select {
						case <-r.Context().Done():
						case <-guard.Done():
						}
					default:
						if n := sends.Load(); n > 3 {
							t.Errorf("unexpected upstream send %d", n)
						}
						persistentPilotStart(w, "resp-B")
						persistentPilotSucceed(w, "only-B")
					}
				})
			defer close(release)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			var trips atomic.Int32
			f.manager.SetRoundTripperProvider(gateFixedTransport{rt: nativeFundingTestTransport(func(r *http.Request) (*http.Response, error) {
				n := trips.Add(1)
				resp, err := transport.RoundTrip(r)
				if n == 2 {
					if beforeHeaders {
						close(closing)
						<-release
					} else if err == nil {
						resp.Body = pilotCloseBarrier{resp.Body, closing, release}
						close(downstreamRead)
					}
				}
				return resp, err
			})})
			path := "/v1/responses"
			body := `{"model":"gpt-6.2-sol","stream":true,"input":"hello"}`
			a := startPilotRequest(ctxA, f, path, body)
			timer := awaitPilotTimer(t, guard, clock, a)
			clock.moveTo(timer.at)
			close(timer.fire)
			select {
			case <-probe:
			case <-guard.Done():
				t.Fatal("probe didn't reach the real upstream")
			}
			if !beforeHeaders {
				select {
				case <-downstreamRead:
				case <-guard.Done():
					t.Fatal("probe never opened a real SSE body")
				}
			}
			cancelA()
			select {
			case <-closing:
			case <-guard.Done():
				t.Fatal("probe teardown didn't reach its transport barrier")
			}
			awaitPilotResult(t, guard, a) // transport exit is held; downstream cancellation must still finish
			b := waitForPilotEvent(t, guard, f, path, "probe_pending")
			if sends.Load() != 2 {
				t.Fatalf("B dispatched before A's raw attempt exited: %d", sends.Load())
			}
			select {
			case release <- struct{}{}:
			case <-guard.Done():
				t.Fatal("cannot release the transport barrier")
			}
			w := awaitPilotResult(t, guard, b)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "only-B") || sends.Load() != 3 {
				t.Fatalf("B didn't wake and complete its own send: %d %d %s", w.Code, sends.Load(), w.Body)
			}
		})
	}
}
