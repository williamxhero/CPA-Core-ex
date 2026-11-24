package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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
