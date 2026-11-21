package auth

// Regression coverage for williamxhero/CPA#50: a credential-wide quota
// cooldown must not hold a request until the client's own timeout.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// expiredAccessTokenJWT has an exp claim of 2001-09-09, so any credential that
// carries it is unavailable without a refresh.
const expiredAccessTokenJWT = "eyJhbGciOiJub25lIn0.eyJleHAiOjEwMDAwMDAwMDB9."

func registerQuotaSelectionModel(t *testing.T, provider, model string, authIDs ...string) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	for _, authID := range authIDs {
		reg.RegisterClient(authID, provider, []*registry.ModelInfo{{ID: model}})
	}
	t.Cleanup(func() {
		for _, authID := range authIDs {
			reg.UnregisterClient(authID)
		}
	})
}

func registerQuotaSelectionAuths(t *testing.T, m *Manager, auths ...*Auth) {
	t.Helper()
	for _, auth := range auths {
		if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", auth.ID, errRegister)
		}
	}
}

func credentialQuotaCoolingAuth(id string, until time.Time) *Auth {
	return &Auth{
		ID:       id,
		Provider: "codex",
		Status:   StatusActive,
		Quota: QuotaState{
			Exceeded:      true,
			Reason:        "credential_quota",
			NextRecoverAt: until,
		},
	}
}

// A credential-wide quota cooldown on one credential must not hide a peer that
// can still serve the model.
func TestCredentialQuotaCooldownKeepsSelectablePeerAvailable(t *testing.T) {
	const (
		provider = "codex"
		model    = "gpt-6.2-sol"
	)
	ctx := context.Background()
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(&mockCustomErrorExecutor{identifier: provider})

	now := time.Now()
	cooling := credentialQuotaCoolingAuth("codex-cooling", now.Add(135*time.Hour))
	peer := &Auth{ID: "codex-peer", Provider: provider, Status: StatusActive}
	registerQuotaSelectionModel(t, provider, model, cooling.ID, peer.ID)
	registerQuotaSelectionAuths(t, m, cooling, peer)

	selected, errSelect := m.SelectAuth(ctx, provider, model, cliproxyexecutor.Options{})
	if errSelect != nil {
		t.Fatalf("SelectAuth() error = %v, want peer selection", errSelect)
	}
	if selected == nil || selected.ID != peer.ID {
		t.Fatalf("SelectAuth() = %v, want peer %q", selected, peer.ID)
	}
}

// When no credential can serve the model, the selection failure must stop
// immediately instead of consuming the client's whole request deadline one
// second at a time under an unlimited upstream retry policy. The diagnostic must
// also name the reason the peer is blocked, not only the cooldown.
func TestCredentialQuotaCooldownWithoutSelectablePeerStopsRetrying(t *testing.T) {
	const (
		provider = "codex"
		model    = "gpt-6.2-sol"
	)
	ctx := context.Background()
	hook := setupTestLoggerHook(t)
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(&mockCustomErrorExecutor{identifier: provider})
	m.SetRetryConfig(10, time.Second, 0)
	m.SetUpstreamErrorRetryLimit(-1)

	now := time.Now()
	cooling := credentialQuotaCoolingAuth("codex-cooling", now.Add(135*time.Hour))
	expired := &Auth{
		ID:       "codex-expired",
		Provider: provider,
		Status:   StatusActive,
		Metadata: map[string]any{"access_token": expiredAccessTokenJWT},
	}
	registerQuotaSelectionModel(t, provider, model, cooling.ID, expired.ID)
	registerQuotaSelectionAuths(t, m, cooling, expired)

	_, errSelect := m.SelectAuth(ctx, provider, model, cliproxyexecutor.Options{})
	if errSelect == nil {
		t.Fatal("SelectAuth() error = nil, want unavailable error")
	}
	if !strings.Contains(errSelect.Error(), "credential_quota") || !strings.Contains(errSelect.Error(), "access_token_expired") {
		t.Fatalf("SelectAuth() error = %v, want both blocking reasons in the client-visible message", errSelect)
	}

	wait, shouldRetry := m.shouldRetryAfterErrorWithAttempted(
		ctx,
		cliproxyexecutor.Options{},
		errSelect,
		0,
		[]string{provider},
		model,
		time.Second,
		-1,
		10,
		nil,
	)
	if shouldRetry {
		t.Fatalf("shouldRetryAfterErrorWithAttempted() = (wait=%v, true) for a selection failure that cannot clear within the retry interval; error=%v", wait, errSelect)
	}

	warnCount := 0
	for _, entry := range hook.AllEntries() {
		if entry.Level != log.WarnLevel || !strings.Contains(entry.Message, "auth unavailable") {
			continue
		}
		warnCount++
		if !strings.Contains(entry.Message, "reason=credential_quota") {
			t.Fatalf("Warn log lost the cooling credential reason: %s", entry.Message)
		}
		if !strings.Contains(entry.Message, "reason=access_token_expired") {
			t.Fatalf("Warn log did not explain the blocked peer: %s", entry.Message)
		}
	}
	if warnCount != 1 {
		t.Fatalf("auth unavailable Warn logs = %d, want 1; logs=%#v", warnCount, hook.AllEntries())
	}
}

// A cooldown that fits the configured retry interval must still be waited out.
func TestCredentialQuotaCooldownWithinRetryIntervalStillRetries(t *testing.T) {
	const (
		provider = "codex"
		model    = "gpt-6.2-sol"
	)
	ctx := context.Background()
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(&mockCustomErrorExecutor{identifier: provider})
	m.SetRetryConfig(10, 30*time.Second, 0)
	m.SetUpstreamErrorRetryLimit(-1)

	now := time.Now()
	cooling := credentialQuotaCoolingAuth("codex-short-cooling", now.Add(2*time.Second))
	expired := &Auth{
		ID:       "codex-expired",
		Provider: provider,
		Status:   StatusActive,
		Metadata: map[string]any{"access_token": expiredAccessTokenJWT},
	}
	registerQuotaSelectionModel(t, provider, model, cooling.ID, expired.ID)
	registerQuotaSelectionAuths(t, m, cooling, expired)

	_, errSelect := m.SelectAuth(ctx, provider, model, cliproxyexecutor.Options{})
	if errSelect == nil {
		t.Fatal("SelectAuth() error = nil, want unavailable error")
	}
	wait, shouldRetry := m.shouldRetryAfterErrorWithAttempted(
		ctx,
		cliproxyexecutor.Options{},
		errSelect,
		0,
		[]string{provider},
		model,
		30*time.Second,
		-1,
		10,
		nil,
	)
	if !shouldRetry {
		t.Fatalf("shouldRetryAfterErrorWithAttempted() = (wait=%v, false), want a retry inside the configured interval; error=%v", wait, errSelect)
	}
	if wait <= 0 || wait > 30*time.Second {
		t.Fatalf("retry wait = %v, want a positive wait within 30s", wait)
	}
}

// Even when every credential is cooling down, an unlimited upstream policy must
// not reinterpret the model-level cooldown as a transient upstream failure.
func TestAllCredentialQuotaCooldownsStopRetryingUnderUnlimitedUpstreamPolicy(t *testing.T) {
	const (
		provider = "codex"
		model    = "gpt-6.2-sol"
	)
	ctx := context.Background()
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(&mockCustomErrorExecutor{identifier: provider})
	m.SetRetryConfig(10, time.Second, 0)
	m.SetUpstreamErrorRetryLimit(-1)

	now := time.Now()
	first := credentialQuotaCoolingAuth("codex-cooling-1", now.Add(135*time.Hour))
	second := credentialQuotaCoolingAuth("codex-cooling-2", now.Add(136*time.Hour))
	registerQuotaSelectionModel(t, provider, model, first.ID, second.ID)
	registerQuotaSelectionAuths(t, m, first, second)

	_, errSelect := m.SelectAuth(ctx, provider, model, cliproxyexecutor.Options{})
	if errSelect == nil {
		t.Fatal("SelectAuth() error = nil, want model cooldown error")
	}
	wait, shouldRetry := m.shouldRetryAfterErrorWithAttempted(
		ctx,
		cliproxyexecutor.Options{},
		errSelect,
		0,
		[]string{provider},
		model,
		time.Second,
		-1,
		10,
		nil,
	)
	if shouldRetry {
		t.Fatalf("shouldRetryAfterErrorWithAttempted() = (wait=%v, true) for an all-cooling model under a 1s retry interval; error=%v", wait, errSelect)
	}
}
