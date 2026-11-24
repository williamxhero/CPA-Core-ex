package auth

import (
	"context"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A pilot reservation outlives both a canceled bootstrap call and the
// conductor's stream wrappers. Only the provider return and the raw channel
// closing (after the Codex response body closes) can acknowledge its exit.
// The conductor owns the consumer until it hands the reservation back.
type pilotStreamAttempt struct {
	returned          chan struct{}
	exited            chan struct{}
	drain             sync.Once
	raw               <-chan executor.StreamChunk
	stream            *executor.StreamResult
	err               error
	outcomeRecorded   bool // only the conductor writes this
	canceledBootstrap bool
	ctx               context.Context
}

func (m *Manager) pilotStreamGate(ctx context.Context, r *routeReservation, call func() (*executor.StreamResult, error)) (*executor.StreamResult, error) {
	if prior := r.attempt; prior != nil {
		// Don't start another model or refreshed credential attempt under this
		// same reservation until the previous producer exits, either.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-prior.exit():
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.pacingDelay, r.pacingSource, r.validationFailed = 0, "", false
	a := &pilotStreamAttempt{returned: make(chan struct{}), exited: make(chan struct{}), ctx: ctx}
	r.attempt = a
	go func() {
		a.stream, a.err = call()
		if a.stream != nil {
			a.raw = a.stream.Chunks
		}
		close(a.returned)
	}()
	// The provider may already be connected while waiting to return its stream.
	// Only the request context can cancel a live pilot attempt based on time.
	select {
	case <-a.returned:
		return a.stream, a.err
	case <-ctx.Done():
		select {
		case <-a.returned:
			return a.stream, a.err
		default:
			// Preserve a real failure that races cancellation, once the
			// original provider actually returns. It cannot authorize a
			// replay for the canceled request.
			a.canceledBootstrap = true
			return nil, ctx.Err()
		}
	}
}

func (a *pilotStreamAttempt) tryExit() bool {
	select {
	case <-a.returned:
	default:
		return false
	}
	if a.raw == nil {
		return true
	}
	select {
	case _, ok := <-a.raw:
		return !ok
	default:
		return false
	}
}

func (a *pilotStreamAttempt) exit() <-chan struct{} {
	a.drain.Do(func() {
		if a.tryExit() {
			close(a.exited)
			return
		}
		go func() {
			defer close(a.exited)
			<-a.returned
			if a.raw != nil {
				for range a.raw {
				}
			}
		}()
	})
	return a.exited
}
