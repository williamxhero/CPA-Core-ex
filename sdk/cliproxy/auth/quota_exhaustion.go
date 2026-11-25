package auth

import (
	"context"
	"time"
)

type pluginRejectionObserver struct {
	publish func(context.Context, *Auth) bool
}

func (m *Manager) SetPluginQuotaRejectionObserver(f func(context.Context, *Auth) bool) {
	if f == nil {
		m.pluginQuotaRejection.Store(nil)
		return
	}
	m.pluginQuotaRejection.Store(&pluginRejectionObserver{f})
}

type quotaExhaustionHolder struct {
	observe func(context.Context, *Auth, Result)
}

// SetQuotaExhaustionObserver installs the independent automatic-stop authority.
// It runs synchronously before a failed execution can enter another retry.
func (m *Manager) SetQuotaExhaustionObserver(observe func(context.Context, *Auth, Result)) {
	if observe == nil {
		m.quotaExhaustion.Store(nil)
		return
	}
	m.quotaExhaustion.Store(&quotaExhaustionHolder{observe: observe})
}

func (m *Manager) observeQuotaExhaustion(ctx context.Context, a *Auth, result Result) {
	if a == nil || result.Success || !result.CredentialScope || result.Error == nil || result.Error.HTTPStatus != 429 {
		return
	}
	if observer := m.quotaExhaustion.Load(); observer != nil {
		observer.observe(ctx, a, result)
	}
}

type upstreamBalanceExhaustionHolder struct {
	observe func(context.Context, *Auth, Result, time.Time)
}

// SetUpstreamBalanceExhaustionObserver installs the synchronous, policy-free
// authority for explicit upstream balance denials.
func (m *Manager) SetUpstreamBalanceExhaustionObserver(observe func(context.Context, *Auth, Result, time.Time)) {
	if observe == nil {
		m.upstreamBalanceExhaustion.Store(nil)
		return
	}
	m.upstreamBalanceExhaustion.Store(&upstreamBalanceExhaustionHolder{observe: observe})
}

func (m *Manager) observeUpstreamBalanceExhaustion(ctx context.Context, a *Auth, result Result, observedAt time.Time) {
	if observer := m.upstreamBalanceExhaustion.Load(); a != nil && observer != nil {
		observer.observe(ctx, a, result, observedAt)
	}
}
