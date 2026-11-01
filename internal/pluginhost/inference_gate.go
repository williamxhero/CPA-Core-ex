package pluginhost

import (
	"context"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// InferenceExecutorScopedHTTP verifies the selected live adapter and its actual
// binary's additive callback capability. Provider labels are not this proof.
func (h *Host) InferenceExecutorScopedHTTP(ctx context.Context, e coreauth.ProviderExecutor, pluginID string) bool {
	a, ok := e.(*executorAdapter)
	if !ok || a == nil || a.host != h || a.pluginID != pluginID || h.isPluginFused(pluginID) || !h.pluginIdentityCurrent(pluginID, a.path, a.version) {
		return false
	}
	desc, handled, err := h.DescribeQuota(ctx, pluginID)
	return err == nil && handled && desc.ScopedInferenceHTTP && h.pluginIdentityCurrent(pluginID, a.path, a.version)
}
