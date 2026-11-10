package auth

import "context"

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
