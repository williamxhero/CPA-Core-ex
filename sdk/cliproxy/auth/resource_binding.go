package auth

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// SourceIdentityBinder is instance-local and validates original persisted bytes.
// Plugin-returned markers are not authority. Unknown/multi-auth sources stay unbound.
type SourceIdentityBinder interface {
	BindAuths(path string, data []byte, auths []*Auth) error
}

// SourceIdentityWriter enrolls host saves before runtime publication.
type SourceIdentityWriter interface {
	SourceIdentityBinder
	SaveAuthFile(path string, data []byte) ([]byte, error)
}

// SourceIdentityOwnedSave publishes an already completed native file save before
// runtime publication. A refresh proof is issued only by the native refresh path.
type SourceIdentityOwnedSave interface {
	BeginOwnedAuthSave(path string, auth *Auth) (func(*Auth, *resource.Binding, bool) error, error)
}

type nativeRefreshBindingKey struct{}

func withNativeRefreshBinding(ctx context.Context, a *Auth) context.Context {
	if a == nil || a.ResourceIdentity == nil || a.SourcePluginID != "" {
		return ctx
	}
	if a.Provider != "codex" && a.Provider != "claude" {
		return ctx
	}
	b := *a.ResourceIdentity
	b.Targets = append([]resource.Target(nil), b.Targets...)
	return context.WithValue(ctx, nativeRefreshBindingKey{}, &b)
}

// NativeRefreshBinding is a host-issued invocation proof, never plugin metadata.
func NativeRefreshBinding(ctx context.Context) *resource.Binding {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(nativeRefreshBindingKey{}).(*resource.Binding)
	return b
}

type ownedAuthSaveHolder struct{ owner SourceIdentityOwnedSave }
type ownedAuthSaveKey struct{}

func (m *Manager) SetSourceIdentityOwnedSave(owner SourceIdentityOwnedSave) {
	if owner == nil {
		m.ownedAuthSave.Store(nil)
		return
	}
	m.ownedAuthSave.Store(&ownedAuthSaveHolder{owner: owner})
}
func (m *Manager) withOwnedAuthSave(ctx context.Context) context.Context {
	if owner := m.ownedAuthSave.Load(); owner != nil {
		return context.WithValue(ctx, ownedAuthSaveKey{}, owner.owner)
	}
	return ctx
}

// CommitNativeRefreshFile binds the executor's local atomic rotation to the
// current source authority. The callback performs local file I/O only.
func CommitNativeRefreshFile(ctx context.Context, a *Auth, path string, write func() error) error {
	owner, _ := ctx.Value(ownedAuthSaveKey{}).(SourceIdentityOwnedSave)
	if owner == nil || a == nil || a.ResourceIdentity == nil {
		return write()
	}
	before := *a.ResourceIdentity
	before.Targets = append([]resource.Target(nil), before.Targets...)
	finish, err := owner.BeginOwnedAuthSave(path, a)
	if err != nil {
		return err
	}
	errWrite := write()
	var proof *resource.Binding
	if a.SourcePluginID == "" && a.CodexRefreshPatch != nil && a.CodexRefreshPatch.UpstreamRefreshed() {
		proof = &before
	}
	errFinish := finish(a, proof, errWrite == nil)
	if errWrite != nil {
		return errWrite
	}
	return errFinish
}

// WithSourceIdentityOwnedSave is an in-process storage binding, never a public bypass.
func WithSourceIdentityOwnedSave(ctx context.Context, owner SourceIdentityOwnedSave) context.Context {
	return context.WithValue(ctx, ownedAuthSaveKey{}, owner)
}
