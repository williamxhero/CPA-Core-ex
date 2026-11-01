package pluginhost

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// IdentityCallbackFixture exposes only the external plugin ABI boundary to the
// external HTTP test package; it does not replace any catalog/manager collaborator.
func IdentityCallbackFixture(h *Host, cfg *config.Config) func(context.Context, string, []byte) ([]byte, error) {
	h.mu.Lock()
	h.runtimeConfig = cfg
	h.mu.Unlock()
	return h.callFromPlugin
}
