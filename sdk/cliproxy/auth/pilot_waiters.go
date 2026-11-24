package auth

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"
)

type pilotBackpressure struct{ limit retryStopReason }

func (e pilotBackpressure) StatusCode() int { return http.StatusServiceUnavailable }
func (e pilotBackpressure) Error() string   { return "Local recovery capacity is full." }

const (
	pilotCallerCapacity  retryStopReason = "caller_waiter_capacity"
	pilotWaiterCapacity  retryStopReason = "total_waiter_capacity"
	pilotTraceCapacity   retryStopReason = "active_trace_capacity"
	pilotWaitBuffer      retryStopReason = "waiter_buffer_capacity"
	pilotWaitBufferBytes                 = 128 << 20
)

type pilotWaiter struct {
	budget *requestBudget
	ctx    context.Context
	caller string
	bytes  int
	// Only routes this request is eligible to wait for. An older caller
	// never owns a global turn or blocks an unrelated healthy alternate.
	routes map[string]struct{}
	since  map[string]time.Time
}

// All queue operations hold providerSchedulingUse.mu, the same lock as
// route reservation and recovery state. Queue order is admission order.
func (u *providerSchedulingUse) waiterIndex(b *requestBudget) int {
	return slices.IndexFunc(u.waiters, func(w pilotWaiter) bool { return w.budget == b })
}

func (u *providerSchedulingUse) removeWaiter(b *requestBudget) bool {
	i := u.waiterIndex(b)
	if i == -1 {
		return false
	}
	u.waiterBytes -= u.waiters[i].bytes
	u.waiters = slices.Delete(u.waiters, i, i+1)
	return true
}

func (u *providerSchedulingUse) olderWaiter(b *requestBudget, route string) bool {
	for _, w := range u.waiters {
		if w.budget == b {
			return false
		}
		if _, ok := w.routes[route]; ok && w.ctx.Err() == nil {
			return true
		}
	}
	return false
}

func (u *providerSchedulingUse) waiterCount(route string) int {
	n := 0
	for _, w := range u.waiters {
		if _, ok := w.routes[route]; ok && w.ctx.Err() == nil {
			n++
		}
	}
	return n
}

func (m *Manager) joinPilotWait(ctx context.Context, opportunity *scheduledRetryOpportunity, now time.Time) error {
	u := &m.providerSchedulingUse
	b := requestBudgetFromContext(ctx)
	caller := providerSchedulingCaller(ctx)
	u.mu.Lock()
	var alarms []pilotAlarm
	defer func() {
		u.mu.Unlock()
		for _, alarm := range alarms {
			alarm.emit()
		}
	}()
	i := u.waiterIndex(b)
	if i < 0 {
		capacity := m.runtimeConfigSnapshot().Routing.ProviderScheduling.PersistentRetry.WaiterCapacity()
		n := 0
		for _, w := range u.waiters {
			if w.caller == caller {
				n++
			}
		}
		if n >= capacity.PerCaller {
			return pilotBackpressure{pilotCallerCapacity}
		}
		if len(u.waiters) >= capacity.Total {
			return pilotBackpressure{pilotWaiterCapacity}
		}
		if opportunity.bufferBytes > pilotWaitBufferBytes-u.waiterBytes {
			return pilotBackpressure{pilotWaitBuffer}
		}
		i = len(u.waiters)
		u.waiterBytes += opportunity.bufferBytes
		u.waiters = append(u.waiters, pilotWaiter{budget: b, ctx: ctx, caller: caller, bytes: opportunity.bufferBytes})
	}
	w := &u.waiters[i]
	if !maps.Equal(w.routes, opportunity.routes) {
		since := make(map[string]time.Time, len(opportunity.routes))
		for route := range opportunity.routes {
			since[route] = w.since[route]
			if since[route].IsZero() {
				since[route] = now
			}
		}
		changed := w.routes != nil
		w.routes, w.since = opportunity.routes, since
		if changed {
			m.providerSchedulingWake.signal()
		}
	}
	for route, since := range w.since {
		state, ok := u.backoff[route]
		if !ok || state.alarmed || !state.firstSuccess.IsZero() {
			continue
		}
		if state.started.After(since) {
			since = state.started
		}
		alarmAt := since.Add(pilotWaitAlarmAfter)
		if !alarmAt.After(now) {
			state.alarmed = true
			u.backoff[route] = state
			alarms = append(alarms, state.alarmEvent("pilot_route_fault", route, now))
		} else if opportunity.alarmAt.IsZero() || alarmAt.Before(opportunity.alarmAt) {
			opportunity.alarmAt = alarmAt
		}
	}
	opportunity.waiters = u.waiterCount(opportunity.route)
	if opportunity.route != "" {
		state := u.backoff[opportunity.route]
		opportunity.cadenceTier = state.tier
		recordPilotRecovery(b.trace.Load(), state.view(u.pilotInUse[opportunity.route], opportunity.waiters, now))
	}
	return nil
}

func (m *Manager) leavePilotWait(b *requestBudget) {
	u := &m.providerSchedulingUse
	u.mu.Lock()
	removed := u.removeWaiter(b)
	u.mu.Unlock()
	if removed {
		m.providerSchedulingWake.signal()
	}
}
