package pluginhost

import coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"

// SetSourceIdentityBinder installs the instance's host-owned source authority.
func (h *Host) SetSourceIdentityBinder(b coreauth.SourceIdentityBinder) {
	h.mu.Lock()
	h.identityBinder = b
	h.mu.Unlock()
}

// BindAuths is shared by startup, watcher synthesis and host callback parsing.
func (h *Host) BindAuths(path string, data []byte, auths []*coreauth.Auth) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	binder := h.identityBinder
	h.mu.Unlock()
	if binder == nil {
		return nil
	}
	return binder.BindAuths(path, data, auths)
}
