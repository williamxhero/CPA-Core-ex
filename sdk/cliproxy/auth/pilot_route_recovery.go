package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

const (
	pilotWaitAlarmAfter = 5 * time.Minute
	pilotStableFor      = time.Minute
)

type persistentRouteBackoff struct {
	failures     int
	step         int
	at           time.Time
	source       string
	tier         string
	started      time.Time
	probe        *routeReservation
	generation   uint64
	firstSuccess time.Time
	successes    int
	alarmed      bool
	cadence      internalconfig.PersistentRetryCadence
}

// The reservation lock owns cadence, recovery capacity and alarm transitions.
func (s persistentRouteBackoff) slotLimit() int {
	switch {
	case s.failures == 0:
		return 0
	case s.successes < 2:
		return 1
	default:
		return 2
	}
}

func (s persistentRouteBackoff) view(slots, waiters int, now time.Time) RoutingPilotRecovery {
	v := RoutingPilotRecovery{CadenceTier: s.tier, TimingSource: s.source, Failures: s.failures, Slots: slots,
		SlotLimit: s.slotLimit(), Waiters: waiters, ConsecutiveSuccesses: s.successes, Alarmed: s.alarmed}
	if s.failures > 0 {
		cadence := s.cadence
		v.Cadence = &cadence
	}
	if s.probe != nil {
		v.Probes = 1
	}
	if !s.at.IsZero() {
		at := s.at.UTC()
		v.NextProbeAt = &at
	}
	if !s.started.IsZero() {
		v.FaultAgeMS = max(0, now.Sub(s.started).Milliseconds())
	}
	if !s.firstSuccess.IsZero() {
		at := s.firstSuccess.UTC()
		v.StableSince = &at
	}
	return v
}

type pilotAlarm struct {
	code, scope string
	view        RoutingPilotRecovery
}

func (s persistentRouteBackoff) alarmEvent(code, route string, now time.Time) pilotAlarm {
	return pilotAlarm{code: code, scope: fmt.Sprintf("%x", sha256.Sum256([]byte(route))), view: s.view(0, 0, now)}
}

func (a pilotAlarm) emit() {
	if a.code == "" {
		return
	}
	entry := log.WithFields(log.Fields{"event": a.code, "route_scope": a.scope, "failures": a.view.Failures,
		"cadence_tier": a.view.CadenceTier, "fault_age_ms": a.view.FaultAgeMS, "next_probe_at": a.view.NextProbeAt})
	if a.code == "pilot_route_resolved" {
		entry.Info("Codex pilot route recovered")
	} else {
		entry.Warn("Codex pilot route remains unavailable")
	}
}

func (r *routeReservation) notePersistentFailure(ctx context.Context, err error) {
	if r.attempt != nil {
		if r.attempt.outcomeRecorded {
			return
		}
		r.attempt.outcomeRecorded = true
	}
	now := RequestBudgetNow(ctx)
	u := &r.manager.providerSchedulingUse
	u.mu.Lock()
	if u.backoff == nil {
		u.backoff = make(map[string]persistentRouteBackoff)
	}
	state := u.backoff[r.persistentRoute]
	if state.failures == 0 {
		state.started = now
	}
	if state.failures == 0 || (state.firstSuccess.IsZero() && r.faultGeneration == state.generation) {
		state.step++
	}
	state.failures++
	// A verification failure returns to the most recent fault tier. Ignore
	// successes from executions admitted before this new health conclusion.
	u.pilotGeneration++
	state.generation = u.pilotGeneration
	r.faultGeneration = state.generation
	state.firstSuccess, state.successes = time.Time{}, 0
	state.cadence = r.manager.runtimeConfigSnapshot().Routing.ProviderScheduling.PersistentRetry.Cadence()
	base, tier := state.cadence.Delay(state.step)
	state.tier = tier
	wait := pilotJitter(base, state.cadence.JitterPercent)
	source := "local_backoff"
	if hint := trustedRetryAfterHint(err); hint != nil && *hint > wait {
		wait, source = *hint, "retry_after"
	}
	r.pacingDelay, r.pacingSource = wait, source
	state.pace(now, wait, source)
	var alarm pilotAlarm
	if !state.alarmed && state.step >= 5 {
		state.alarmed = true
		alarm = state.alarmEvent("pilot_route_fault", r.persistentRoute, now)
	}
	u.backoff[r.persistentRoute] = state
	view := state.view(u.pilotInUse[r.persistentRoute], u.waiterCount(r.persistentRoute), now)
	u.mu.Unlock()
	alarm.emit()
	r.manager.providerSchedulingWake.signal()

	b := requestBudgetFromContext(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	category := upstreamCategoryTransient
	if statusCodeFromError(err) == http.StatusTooManyRequests {
		category = upstreamCategoryTransientRateLimit
	}
	b.UpstreamCategory = string(category)
	b.pacedStatus = statusCodeFromError(err)
	b.UpstreamRetryAt = state.at
	b.UpstreamRetrySource = state.source
	updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
	recordPilotRecovery(b.trace.Load(), view)
}

// Called after the provider and raw producer have exited, while holding the
// reservation lock. Report the outcome before waking or allowing another pick.
func (r *routeReservation) finishPersistentRecovery(u *providerSchedulingUse) pilotAlarm {
	state, ok := u.backoff[r.persistentRoute]
	if !ok {
		return pilotAlarm{}
	}
	if state.probe == r {
		state.probe = nil
	}
	now := RequestBudgetNow(r.ctx)
	if r.pacingDelay > 0 {
		// An SSE failure can be visible to the conductor before Body.Close
		// returns. The delay starts at actual exit, not at the error frame.
		state.pace(now, r.pacingDelay, r.pacingSource)
	}
	if r.faultGeneration == state.generation {
		switch {
		case r.completed:
			if state.firstSuccess.IsZero() {
				state.firstSuccess = now
				state.at, state.source = time.Time{}, ""
			}
			state.successes++
		case r.validationFailed && !state.firstSuccess.IsZero():
			// A non-recoverable upstream outcome is still not evidence of
			// health. Preserve the normal rejection/replay policy separately.
			u.pilotGeneration++
			state.generation = u.pilotGeneration
			state.firstSuccess, state.successes = time.Time{}, 0
			base, _ := state.cadence.Delay(state.step)
			state.pace(now, pilotJitter(base, state.cadence.JitterPercent), "local_backoff")
		}
	}
	resolved := state.stable(now)
	view := state.view(u.pilotInUse[r.persistentRoute], u.waiterCount(r.persistentRoute), now)
	var alarm pilotAlarm
	if resolved {
		view.Alarmed, view.SlotLimit, view.Resolved = false, 0, true
	}
	u.backoff[r.persistentRoute] = state
	if resolved {
		alarm = u.evaluatePersistentRecovery(r.persistentRoute, now)
	}
	if b := requestBudgetFromContext(r.ctx); b != nil && r.pacingDelay > 0 {
		b.mu.Lock()
		b.UpstreamRetryAt, b.UpstreamRetrySource = state.at, state.source
		updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
		b.mu.Unlock()
	}
	recordPilotRecovery(routingTraceFromContext(r.ctx), view)
	return alarm
}

func pilotJitter(base time.Duration, percent int) time.Duration {
	return base + rand.N(base*time.Duration(percent)/100+1)
}

func (s *persistentRouteBackoff) pace(now time.Time, delay time.Duration, source string) {
	if next := now.Add(delay); next.After(s.at) {
		s.at, s.source = next, source
	}
}

func (s persistentRouteBackoff) stable(now time.Time) bool {
	return s.successes >= 3 && !s.firstSuccess.IsZero() && now.Sub(s.firstSuccess) >= pilotStableFor
}

// Evaluation can observe the 60s threshold after the third success. No timer
// runs for idle routes and no new request is sent just to clear the alarm.
func (u *providerSchedulingUse) evaluatePersistentRecovery(route string, now time.Time) pilotAlarm {
	state := u.backoff[route]
	if !state.stable(now) {
		return pilotAlarm{}
	}
	delete(u.backoff, route)
	if state.alarmed {
		return state.alarmEvent("pilot_route_resolved", route, now)
	}
	return pilotAlarm{}
}
