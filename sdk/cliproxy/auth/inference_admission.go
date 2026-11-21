package auth

import (
	"context"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type InferenceAdmission func(context.Context, *Auth, string) error
type inferenceAdmissionHolder struct{ check InferenceAdmission }

// SetInferenceAdmission installs an instance-owned authority, not a result hook.
func (m *Manager) SetInferenceAdmission(check InferenceAdmission) {
	if check == nil {
		m.inferenceAdmission.Store(nil)
		return
	}
	m.inferenceAdmission.Store(&inferenceAdmissionHolder{check: check})
}

// ErrorCodePersistentQuotaGate marks a published pause. MarkResult must not
// create a second cooldown with the same event's quota reset deadline.
const ErrorCodePersistentQuotaGate = "persistent_quota_gate"

type codexQuotaRejectionHolder struct {
	observe func(context.Context, *Auth, time.Time, resource.CodexQuotaRejection) bool
}

func (m *Manager) SetCodexQuotaRejectionObserver(observe func(context.Context, *Auth, time.Time, resource.CodexQuotaRejection) bool) {
	if observe == nil {
		m.codexQuotaRejection.Store(nil)
		return
	}
	m.codexQuotaRejection.Store(&codexQuotaRejectionHolder{observe: observe})
}

func (m *Manager) withInferenceAdmission(ctx context.Context, a *Auth, model string) context.Context {
	if m.inferenceAdmission.Load() == nil {
		return ctx
	}
	if p := m.codexQuotaRejection.Load(); p != nil && a != nil && a.Provider == "codex" && a.SourcePluginID == "" && a.ResourceIdentity != nil {
		start := time.Now()
		ctx = cliproxyexecutor.WithCodexQuotaObserver(ctx, func(e resource.CodexQuotaRejection) bool {
			return p.observe(ctx, a, start, e)
		})
	}
	// Read the currently installed authority on EVERY transport attempt. Retaining
	// a selected credential does not retain an earlier permission.
	return cliproxyexecutor.WithInferenceAdmission(ctx, func(ctx context.Context) error {
		p := m.inferenceAdmission.Load()
		if p == nil {
			return nil
		}
		return p.check(ctx, a, model)
	})
}

func (m *Manager) executeGateAttempt(ctx context.Context, e ProviderExecutor, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	ctx = m.withInferenceAdmission(ctx, a, req.Model)
	if err := cliproxyexecutor.AdmitInference(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return e.Execute(ctx, a, req, opts)
}
func (m *Manager) streamGateAttempt(ctx context.Context, e ProviderExecutor, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	ctx = m.withInferenceAdmission(ctx, a, req.Model)
	if err := cliproxyexecutor.AdmitInference(ctx); err != nil {
		return nil, err
	}
	return e.ExecuteStream(ctx, a, req, opts)
}
func (m *Manager) countGateAttempt(ctx context.Context, e ProviderExecutor, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	ctx = m.withInferenceAdmission(ctx, a, req.Model)
	if err := cliproxyexecutor.AdmitInference(ctx); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return e.CountTokens(ctx, a, req, opts)
}
