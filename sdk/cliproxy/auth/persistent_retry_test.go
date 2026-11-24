package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func newPersistentBackoffTest(t *testing.T, start time.Time) (*Manager, *fakeContinuityClock, *routeReservation, context.Context, func() RequestBudgetSnapshot) {
	t.Helper()
	clock := newFakeContinuityClock(start)
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{})
	m.SetContinuityClockForTest(clock)
	ctx := WithFreshRequestBudget(t.Context())
	b := requestBudgetFromContext(ctx)
	b.mu.Lock()
	b.now = clock.Now
	b.mu.Unlock()
	r := &routeReservation{manager: m, persistentRoute: "route:persistent-test", ctx: ctx}
	return m, clock, r, ctx, func() RequestBudgetSnapshot {
		snapshot, _ := RequestBudgetSnapshotFromContext(ctx)
		return snapshot
	}
}

func TestPersistentRetryReservationReleasedBeforeRecheck(t *testing.T) {
	for _, temporary := range []bool{true, false} {
		name := "unchanged_local_failure"
		if temporary {
			name = "reservation_released"
		}
		t.Run(name, func(t *testing.T) {
			m, _, _, ctx, snapshot := newPersistentBackoffTest(t, time.Unix(1_800_000_000, 0))
			const resourceID = "fee222e4-6116-4cd5-9578-23265074d937"
			m.SetConfig(&internalconfig.Config{Routing: internalconfig.RoutingConfig{
				ProviderScheduling: internalconfig.ProviderSchedulingConfig{Resources: map[string]internalconfig.ProviderSchedulingResource{resourceID: {MaxConcurrent: 1}}},
			}})
			m.SetRetryConfig(1, 0, 1)
			m.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
			a := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, ResourceIdentity: &resource.Binding{Targets: []resource.Target{{ResourceID: resourceID}}}}
			if _, errRegister := m.Register(WithSkipPersist(ctx), a); errRegister != nil {
				t.Fatal(errRegister)
			}
			registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: persistentRetryPilotModel}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			b := requestBudgetFromContext(ctx)
			b.persistentRetry, b.persistentLimit, b.Attempts, b.UpstreamCategory = true, -1, 1, string(upstreamCategoryTransient)
			providers := []string{"codex"}
			req := executor.Request{Model: persistentRetryPilotModel}
			opts := executor.Options{Metadata: map[string]any{}}
			calls := 0
			result, err := runScheduledExecution(m, ctx, providers, req, opts, nil, func(ctx context.Context, opts executor.Options, _, _ int, _ *int) (string, error) {
				calls++
				if calls == 1 {
					return "", markUpstreamExecutionAttemptWithProvider(persistentTestFailure(), "codex")
				}
				if !temporary {
					return "", newNoAvailableRouteError(req.Model)
				}
				if calls == 2 {
					otherOpts := executor.Options{Metadata: map[string]any{}}
					if _, _, _, errPick := m.pickScheduledRoute(t.Context(), providers, req.Model, otherOpts, nil); errPick != nil {
						t.Fatal(errPick)
					}
					other := takeRouteReservation(otherOpts)
					if other == nil {
						t.Fatal("other request did not reserve the slot")
					}
					_, _, _, errPick := m.pickScheduledRoute(ctx, providers, req.Model, opts, nil)
					other.release()
					if _, ok := errPick.(scheduledUnavailablePick); !ok {
						t.Fatalf("expected temporary pick miss, got %v", errPick)
					}
					return "", errPick
				}
				return "recovered", nil
			})
			if temporary && (err != nil || result != "recovered" || calls != 3 || snapshot().Round != 1) {
				t.Fatalf("released slot did not recover in the same round: result=%q err=%v calls=%d accounting=%+v", result, err, calls, snapshot())
			}
			if !temporary && (err == nil || calls != 2 || snapshot().RetryStopReason != "local_dispatch_rejected") {
				t.Fatalf("unchanged local rejection must not retry: err=%v calls=%d accounting=%+v", err, calls, snapshot())
			}
		})
	}
}

func persistentTestFailure() error {
	return &Error{HTTPStatus: http.StatusBadGateway, Message: "temporary upstream rejection"}
}

func assertPersistentStepWait(t *testing.T, wait, base time.Duration) {
	t.Helper()
	if wait < base || wait > base+base/5 {
		t.Fatalf("wait = %v, want the %v step with up to 20%% jitter", wait, base)
	}
}

func assertPersistentBaseWait(t *testing.T, wait time.Duration) {
	t.Helper()
	assertPersistentStepWait(t, wait, time.Second)
}

func attachPersistentTestProbe(m *Manager, r *routeReservation) {
	m.providerSchedulingUse.mu.Lock()
	state := m.providerSchedulingUse.backoff[r.persistentRoute]
	state.probe = r
	r.faultGeneration = state.generation
	m.providerSchedulingUse.pilotInUse = map[string]int{r.persistentRoute: 1}
	m.providerSchedulingUse.backoff[r.persistentRoute] = state
	m.providerSchedulingUse.mu.Unlock()
}

func persistentBackoffEntry(m *Manager, routeID string) bool {
	m.providerSchedulingUse.mu.Lock()
	defer m.providerSchedulingUse.mu.Unlock()
	_, ok := m.providerSchedulingUse.backoff[routeID]
	return ok
}

func TestPersistentRouteBackoffEscalatesForLiveRoute(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	m, clock, r, ctx, snapshot := newPersistentBackoffTest(t, start)
	live := map[string]struct{}{r.persistentRoute: {}}

	r.notePersistentFailure(ctx, persistentTestFailure())
	assertPersistentBaseWait(t, snapshot().UpstreamRetryAt.Sub(start))

	clock.Advance(2 * time.Second)
	m.providerSchedulingUse.mu.Lock()
	m.providerSchedulingUse.pruneStalePersistentBackoffLocked(live, clock.Now())
	m.providerSchedulingUse.mu.Unlock()
	r.notePersistentFailure(ctx, persistentTestFailure())
	assertPersistentStepWait(t, snapshot().UpstreamRetryAt.Sub(clock.Now()), 2*time.Second)

	clock.Advance(3 * time.Second)
	m.providerSchedulingUse.mu.Lock()
	m.providerSchedulingUse.pruneStalePersistentBackoffLocked(live, clock.Now())
	m.providerSchedulingUse.mu.Unlock()
	r.notePersistentFailure(ctx, persistentTestFailure())
	assertPersistentStepWait(t, snapshot().UpstreamRetryAt.Sub(clock.Now()), 4*time.Second)
}

func TestPersistentRouteBackoffDropsStaleRouteEntry(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	m, clock, r, ctx, _ := newPersistentBackoffTest(t, start)
	r.notePersistentFailure(ctx, persistentTestFailure())
	clock.Advance(2 * time.Second)
	m.providerSchedulingUse.mu.Lock()
	m.providerSchedulingUse.pruneStalePersistentBackoffLocked(map[string]struct{}{}, clock.Now())
	m.providerSchedulingUse.mu.Unlock()
	if persistentBackoffEntry(m, r.persistentRoute) {
		t.Fatal("elapsed entry for a route outside the candidate pool was kept")
	}
}

func TestPersistentRouteBackoffKeepsLiveElapsedEntry(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	m, clock, r, ctx, _ := newPersistentBackoffTest(t, start)
	r.notePersistentFailure(ctx, persistentTestFailure())
	clock.Advance(2 * time.Second)
	m.providerSchedulingUse.mu.Lock()
	m.providerSchedulingUse.pruneStalePersistentBackoffLocked(map[string]struct{}{r.persistentRoute: {}}, clock.Now())
	m.providerSchedulingUse.mu.Unlock()
	if !persistentBackoffEntry(m, r.persistentRoute) {
		t.Fatal("live route lost its half-open probe window")
	}
}

func TestPersistentRouteBackoffKeepsPendingProbeEntry(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	m, clock, r, ctx, _ := newPersistentBackoffTest(t, start)
	r.notePersistentFailure(ctx, persistentTestFailure())
	attachPersistentTestProbe(m, r)
	clock.Advance(2 * time.Second)
	m.providerSchedulingUse.mu.Lock()
	m.providerSchedulingUse.pruneStalePersistentBackoffLocked(map[string]struct{}{}, clock.Now())
	m.providerSchedulingUse.mu.Unlock()
	if !persistentBackoffEntry(m, r.persistentRoute) {
		t.Fatal("pending probe entry was pruned")
	}
}

func TestPersistentRouteBackoffReleasesProbeIntoVerification(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	m, clock, r, ctx, _ := newPersistentBackoffTest(t, start)
	r.notePersistentFailure(ctx, persistentTestFailure())
	attachPersistentTestProbe(m, r)

	clock.Advance(2 * time.Second)
	r.completePersistentProbe()
	r.release()
	state := m.providerSchedulingUse.backoff[r.persistentRoute]
	if state.probe != nil || state.successes != 1 || state.slotLimit() != 1 {
		t.Fatal("completed probe did not enter serial verification")
	}
}
