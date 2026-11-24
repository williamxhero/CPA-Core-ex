package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type schedulingLimit struct {
	id  string
	max int
}

type providerSchedulingUse struct {
	mu              sync.Mutex
	counts          map[string]int
	pilotInUse      map[string]int
	pilotGeneration uint64
	backoff         map[string]persistentRouteBackoff
	waiters         []pilotWaiter
	waiterBytes     int
}

type providerSchedulingWake struct {
	mu      sync.Mutex
	changed chan struct{}
}

func (w *providerSchedulingWake) watch() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed == nil {
		w.changed = make(chan struct{})
	}
	return w.changed
}

func (w *providerSchedulingWake) signal() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed != nil {
		close(w.changed)
		w.changed = nil
	}
}

func schedulingLimits(cfg internalconfig.ProviderSchedulingConfig, auth *Auth) []schedulingLimit {
	id, parent := schedulingResource(auth)
	var limits []schedulingLimit
	for _, ref := range []string{id, parent} {
		if ref == "" || len(limits) > 0 && limits[0].id == ref {
			continue
		}
		if max := cfg.Resources[ref].MaxConcurrent; max >= 0 {
			limits = append(limits, schedulingLimit{ref, max})
		}
	}
	return limits
}

// Callers hold providerSchedulingUse.mu across this test and acquisition.
func (u *providerSchedulingUse) available(limits []schedulingLimit) bool {
	for _, limit := range limits {
		if limit.max > 0 && u.counts[limit.id] >= limit.max {
			return false
		}
	}
	return true
}

// pruneStalePersistentBackoffLocked drops elapsed idle entries whose route is
// no longer part of the candidate pool, so credentials or models that
// disappeared cannot accumulate state. Callers hold u.mu.
func (u *providerSchedulingUse) pruneStalePersistentBackoffLocked(live map[string]struct{}, now time.Time) {
	for routeID, state := range u.backoff {
		if state.probe != nil || u.pilotInUse[routeID] != 0 || state.at.After(now) {
			continue
		}
		if _, ok := live[routeID]; ok {
			continue
		}
		delete(u.backoff, routeID)
	}
}

type routeReservation struct {
	once             sync.Once
	manager          *Manager
	limits           []schedulingLimit
	persistentRoute  string
	faultGeneration  uint64
	pacingDelay      time.Duration
	pacingSource     string
	completed        bool
	validationFailed bool
	ctx              context.Context
	attempt          *pilotStreamAttempt
}

func (r *routeReservation) completePersistentProbe() {
	if r != nil {
		r.completed = true
	}
}

const routeReservationMetadata = "_cpa_route_reservation"

func takeRouteReservation(opts cliproxyexecutor.Options) *routeReservation {
	r, _ := opts.Metadata[routeReservationMetadata].(*routeReservation)
	delete(opts.Metadata, routeReservationMetadata)
	return r
}

func (r *routeReservation) release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if attempt := r.attempt; attempt != nil {
			select {
			case <-attempt.exit():
			default:
				go func() {
					<-attempt.exit()
					r.free()
				}()
				return
			}
		}
		r.free()
	})
}

func (r *routeReservation) free() {
	if a := r.attempt; a != nil && a.canceledBootstrap {
		err := markUpstreamExecutionAttemptFromContext(a.ctx, a.err)
		if persistentTransient(err) {
			r.notePersistentFailure(a.ctx, err)
		}
	}
	u := &r.manager.providerSchedulingUse
	u.mu.Lock()
	for _, limit := range r.limits {
		u.counts[limit.id]--
		if u.counts[limit.id] == 0 {
			delete(u.counts, limit.id)
		}
	}
	var alarm pilotAlarm
	if r.persistentRoute != "" {
		if u.pilotInUse[r.persistentRoute] > 1 {
			u.pilotInUse[r.persistentRoute]--
		} else {
			delete(u.pilotInUse, r.persistentRoute)
		}
		alarm = r.finishPersistentRecovery(u)
	}
	u.mu.Unlock()
	alarm.emit()
	r.manager.providerSchedulingWake.signal()
}

func wrapRouteReservationStream(ctx context.Context, result *cliproxyexecutor.StreamResult, reservation *routeReservation) *cliproxyexecutor.StreamResult {
	if reservation == nil {
		return result
	}
	if result == nil || result.Chunks == nil {
		reservation.release()
		return result
	}
	chunks := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(chunks)
		defer reservation.release()
		for {
			select {
			case <-ctx.Done():
				return
			case chunk, ok := <-result.Chunks:
				if !ok {
					return
				}
				// Free before forwarding terminal errors so any eligible replay
				// observes the released slot.
				if chunk.Err != nil {
					reservation.release()
				}
				select {
				case chunks <- chunk:
				case <-ctx.Done():
					return
				}
				if chunk.Err != nil {
					return
				}
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: chunks}
}

func schedulingOpaqueResource(auth *Auth) string {
	if id, _ := schedulingResource(auth); id != "" {
		return id
	}
	if auth == nil {
		return ""
	}
	return fmt.Sprintf("runtime-%x", sha256.Sum256([]byte(auth.ID)))
}

func (m *Manager) scheduledRouteIdentity(auth *Auth, routeModel string) string {
	if auth == nil {
		return ""
	}
	models, _, _, _ := m.executionModelCandidatesWithAliasOrdered(auth, routeModel, false)
	for i := range models {
		models[i] = canonicalModelLookupKey(models[i])
	}
	slices.Sort(models)
	models = slices.Compact(models)
	return "route:" + schedulingOpaqueResource(auth) + ":" + strings.Join(models, "\x00")
}

// scheduledNextAvailability never picks, reserves, or updates selector state.
func (m *Manager) scheduledNextAvailability(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, now time.Time, allowPilotLegacyCooldown bool) scheduledRetryOpportunity {
	// Subscribe before reading either candidate or reservation state. A change
	// between the snapshot and the actual wait closes this generation too.
	opportunity := scheduledRetryOpportunity{changed: m.providerSchedulingWake.watch()}
	candidates, selector := m.scheduledCandidates(ctx, providers, model, opts, tried, now, allowPilotLegacyCooldown)
	hardBinding := scheduledHardAffinity(selector, model, opts)
	persistent := PersistentRetryPilot(ctx)
	u := &m.providerSchedulingUse
	u.mu.Lock()
	var alarms []pilotAlarm
	defer func() {
		u.mu.Unlock()
		for _, alarm := range alarms {
			alarm.emit()
		}
		if len(alarms) > 0 {
			m.providerSchedulingWake.signal()
		}
	}()
	if persistent {
		m.providerSchedulingUse.pruneStalePersistentBackoffLocked(scheduledLiveRoutes(candidates), now)
	}
	b := requestBudgetFromContext(ctx)
	if persistent {
		opportunity.routes = make(map[string]struct{})
	}
	var blockedBy retryStopReason
	for _, c := range candidates {
		if hardBinding != "" && c.auth.ID != hardBinding {
			continue
		}
		if persistent && !slices.ContainsFunc(c.reasons, schedulingIneligible) && !slices.Contains(c.reasons, "request_excluded") {
			reason := candidateStopReason(c)
			switch {
			case blockedBy == "":
				blockedBy = reason
			case blockedBy != reason:
				blockedBy = retryStopNoAvailableRoute
			}
		}
		pilot := persistent && c.owner == "codex"
		if pilot && len(c.reasons) == 1 && c.reasons[0] == "refresh_in_progress" {
			opportunity.noteRoute(c.routeID, time.Time{}, "")
			opportunity.refreshPending = true
			continue
		}
		if len(c.reasons) == 0 {
			if pilot {
				if alarm := u.evaluatePersistentRecovery(c.routeID, now); alarm.code != "" {
					alarms = append(alarms, alarm)
				}
				state := u.backoff[c.routeID]
				if state.probe != nil {
					opportunity.noteRoute(c.routeID, time.Time{}, "")
					opportunity.probePending = true
					continue
				}
				if state.at.After(now) {
					opportunity.noteRoute(c.routeID, state.at, state.source)
					continue
				}
				if state.slotLimit() > 0 && u.pilotInUse[c.routeID] >= state.slotLimit() {
					if state.successes >= 3 && u.available(c.limits) {
						opportunity.noteRoute(c.routeID, state.firstSuccess.Add(pilotStableFor), "recovery_validation")
					} else {
						opportunity.noteRoute(c.routeID, time.Time{}, "")
					}
					opportunity.capacityPending = true
					continue
				}
			}
			if !u.available(c.limits) {
				if pilot {
					opportunity.noteRoute(c.routeID, time.Time{}, "")
					opportunity.capacityPending = true
				}
				continue
			}
			if pilot && u.olderWaiter(b, c.routeID) {
				opportunity.noteRoute(c.routeID, time.Time{}, "")
				opportunity.queuePending = true
				continue
			}
			return scheduledRetryOpportunity{ready: true, changed: opportunity.changed}
		}
		if len(c.reasons) == 1 && c.reasons[0] == "cooldown" && c.retryAt.After(now) && (pilot || u.available(c.limits)) {
			// A quota reset estimate schedules rechecks, not inference.
			if (allowPilotLegacyCooldown && c.owner != "codex") || (pilot && c.quotaBlocked) {
				continue
			}
			if pilot {
				state := u.backoff[c.routeID]
				if state.probe != nil {
					opportunity.noteRoute(c.routeID, time.Time{}, "")
					opportunity.probePending = true
					continue
				}
				if state.at.After(c.retryAt) {
					opportunity.noteRoute(c.routeID, state.at, state.source)
					continue
				}
			}
			opportunity.noteRoute(c.routeID, c.retryAt, "credential_cooldown")
		}
	}
	opportunity.stop = blockedBy
	return opportunity
}

func candidateStopReason(c scheduledCandidate) retryStopReason {
	switch {
	case slices.Contains(c.reasons, "tos_violation"):
		return "tos_violation"
	case slices.Contains(c.reasons, "manual_disabled"):
		return "manual_disabled"
	case slices.Contains(c.reasons, "disabled"):
		return "disabled"
	case c.quotaBlocked:
		return "quota_exhausted"
	case slices.Contains(c.reasons, "inference_admission_blocked"):
		return "inference_admission_blocked"
	}
	for _, reason := range c.reasons {
		switch reason {
		case "reauthentication_required", "credential_recovery_required", "authentication_unavailable":
			return retryStopReason(reason)
		}
	}
	return retryStopNoAvailableRoute
}

func scheduledLiveRoutes(candidates []scheduledCandidate) map[string]struct{} {
	live := make(map[string]struct{}, len(candidates))
	for i := range candidates {
		live[candidates[i].routeID] = struct{}{}
	}
	return live
}

func scheduledHardAffinity(selector Selector, model string, opts cliproxyexecutor.Options) string {
	affinity, ok := selector.(*SessionAffinitySelector)
	if !ok || !affinity.rebindOnNever {
		return ""
	}
	// The enforcing selector picks in the mixed namespace, not the individual
	// upstream provider namespaces used by legacy paths.
	authID, _ := affinity.resolveBoundAuth(nil, selectionArgForSelector(selector, model), opts, true)
	return authID
}
