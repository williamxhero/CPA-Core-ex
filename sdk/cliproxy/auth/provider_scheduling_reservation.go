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
	mu      sync.Mutex
	counts  map[string]int
	backoff map[string]persistentRouteBackoff
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

type routeReservation struct {
	once            sync.Once
	manager         *Manager
	limits          []schedulingLimit
	persistentRoute string
	probeAt         time.Time
}

func (r *routeReservation) completePersistentProbe() {
	if r == nil || r.probeAt.IsZero() {
		return
	}
	u := &r.manager.providerSchedulingUse
	u.mu.Lock()
	defer u.mu.Unlock()
	if state := u.backoff[r.persistentRoute]; state.probe == r && state.at.Equal(r.probeAt) {
		delete(u.backoff, r.persistentRoute)
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
		u := &r.manager.providerSchedulingUse
		u.mu.Lock()
		for _, limit := range r.limits {
			u.counts[limit.id]--
			if u.counts[limit.id] == 0 {
				delete(u.counts, limit.id)
			}
		}
		if state := u.backoff[r.persistentRoute]; state.probe == r {
			state.probe = nil
			u.backoff[r.persistentRoute] = state
		}
		u.mu.Unlock()
		r.manager.providerSchedulingWake.signal()
	})
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
func (m *Manager) scheduledNextAvailability(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, now time.Time) (bool, time.Time, <-chan struct{}, bool) {
	changed := m.providerSchedulingWake.watch()
	candidates, selector := m.scheduledCandidates(ctx, providers, model, opts, tried, now)
	hardBinding := scheduledHardAffinity(selector, model, opts)
	persistent := PersistentRetryPilot(ctx)
	m.providerSchedulingUse.mu.Lock()
	defer m.providerSchedulingUse.mu.Unlock()
	var next time.Time
	var probePending bool
	for _, c := range candidates {
		if hardBinding != "" && c.auth.ID != hardBinding {
			continue
		}
		if persistent && c.owner == "codex" && len(c.reasons) == 0 {
			state := m.providerSchedulingUse.backoff[c.routeID]
			if state.probe != nil {
				probePending = true
				continue
			}
			if state.at.After(now) {
				if next.IsZero() || state.at.Before(next) {
					next = state.at
				}
				continue
			}
		}
		if !m.providerSchedulingUse.available(c.limits) {
			continue
		}
		if len(c.reasons) == 0 {
			return true, time.Time{}, changed, false
		}
		if len(c.reasons) == 1 && c.reasons[0] == "cooldown" && c.retryAt.After(now) && (next.IsZero() || c.retryAt.Before(next)) {
			next = c.retryAt
		}
	}
	return false, next, changed, probePending
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
