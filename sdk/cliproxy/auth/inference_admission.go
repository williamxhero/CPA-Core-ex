package auth

import (
	"context"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type InferenceAdmission func(context.Context, *Auth, string) error
type inferenceAdmissionHolder struct {
	check   InferenceAdmission
	inspect func(context.Context, *Auth, string) (*resource.QuotaGateEvidence, error)
}

// SetInferenceAdmission installs an instance-owned authority, not a result hook.
func (m *Manager) SetInferenceAdmission(check InferenceAdmission) {
	if check == nil {
		m.inferenceAdmission.Store(nil)
		return
	}
	m.inferenceAdmission.Store(&inferenceAdmissionHolder{check: check})
}

// SetInferenceAdmissionInspector attaches the read-only native gate projection
// alongside the normal authority. The inspector must make the same decision.
func (m *Manager) SetInferenceAdmissionInspector(check InferenceAdmission, inspect func(context.Context, *Auth, string) (*resource.QuotaGateEvidence, error)) {
	if check == nil {
		m.inferenceAdmission.Store(nil)
		return
	}
	m.inferenceAdmission.Store(&inferenceAdmissionHolder{check: check, inspect: inspect})
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
	if m.inferenceAdmission.Load() == nil && a == nil {
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
		// A retained selection cannot authorize a resend after manual disable.
		if a != nil {
			m.mu.RLock()
			latest := m.auths[a.ID]
			disabled := a.Disabled || a.Status == StatusDisabled || latest != nil && (latest.Disabled || latest.Status == StatusDisabled)
			m.mu.RUnlock()
			if disabled {
				return &cliproxyexecutor.InferenceAdmissionError{}
			}
		}
		p := m.inferenceAdmission.Load()
		if p == nil {
			return nil
		}
		return p.check(ctx, a, model)
	})
}

// Check native funding admission before consuming a credential attempt. The
// final transport still rechecks admission to close the selection/send race.
func (m *Manager) pickNextMixedForInference(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	if !m.HomeEnabled() && m.ProviderSchedulingEnforced(ctx, model) {
		opts.EnsureMetadata()
		return m.pickScheduledRoute(ctx, providers, model, opts, tried)
	}
	report := func(*Auth) {}
	if m.providerSchedulingMode(ctx, model) == internalconfig.ProviderSchedulingShadow && wantsSchedulingDecision(ctx) {
		view := SchedulingDecision{Mode: internalconfig.ProviderSchedulingShadow, Model: model, Proposal: "unobservable"}
		if !m.HomeEnabled() {
			view = m.schedulingSnapshot(ctx, providers, model, m.scheduleRequestOptions(cliproxyexecutor.Request{Model: model}, opts), tried)
		}
		report = func(a *Auth) {
			id, _ := schedulingResource(a)
			view.ActualResourceID = catalogRoutingID(id)
			switch {
			case a != nil && view.ActualResourceID == "", view.Proposal == "unobservable", view.Proposal == "equally_ranked", view.Proposal == "available" && view.ProposedResourceID == "":
				view.Comparison = "unobservable"
			case a == nil && view.Proposal == "no_available_route", a != nil && view.ActualResourceID == view.ProposedResourceID:
				view.Comparison = "same"
			default:
				view.Comparison = "different"
			}
			publishSchedulingDecision(ctx, view)
		}
	}
	if tried == nil {
		tried = make(map[string]struct{})
	}
	var held bool
	for {
		a, executor, provider, err := m.pickNextMixed(ctx, providers, model, opts, tried)
		if err != nil {
			report(nil)
			if held && isCredentialSelectionFailure(err) {
				return nil, nil, "", &Error{Code: "auth_unavailable", Message: "no auth available: inference admission restricted", HTTPStatus: 503}
			}
			return a, executor, provider, err
		}
		if a == nil {
			report(nil)
			return a, executor, provider, nil
		}
		historical := a.Attributes[AttributeLegacyFundingHold] == "true"
		boundNative := a.ResourceIdentity != nil && a.Attributes[AttributeNativeFunding] == "true"
		boundSubscription := a.ResourceIdentity != nil && (a.Provider == "codex" || a.SourcePluginID == "cpa-credential-opencode" || a.SourcePluginID == "cpa-credential-qwen")
		if !historical && !boundNative && !boundSubscription {
			report(a)
			return a, executor, provider, nil
		}
		authority := m.inferenceAdmission.Load()
		if authority == nil {
			if !historical {
				report(a)
				return a, executor, provider, nil
			}
		} else if authority.check(ctx, a, model) == nil {
			report(a)
			return a, executor, provider, nil
		}
		tried[a.ID] = struct{}{}
		held = true
	}
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
