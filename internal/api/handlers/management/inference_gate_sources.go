package management

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Handler) gateSourceCoverage(ctx context.Context, a *coreauth.Auth) (bool, string, []gin.H) {
	unavailable := func(reason string) (bool, string, []gin.H) {
		return false, reason, []gin.H{{"route": "all-current-source", "supported": false, "reason": reason}}
	}
	e, ok := h.authManager.Executor(a.Provider)
	if !ok {
		return unavailable("executor_unavailable")
	}
	if a.SourcePluginID != "" {
		if a.SourcePluginID == "opencode-go-cliproxyapi" || a.SourcePluginID == "qwen-cliproxyapi" {
			h.mu.Lock()
			host := h.pluginHost
			h.mu.Unlock()
			if host == nil || !host.InferenceExecutorScopedHTTP(ctx, e, a.SourcePluginID) {
				if a.SourcePluginID == "qwen-cliproxyapi" {
					if inner, ok := pluginhost.UnwrapPluginRefreshCompatExecutor(e); ok {
						if _, native := inner.(*runtimeexecutor.OpenAICompatExecutor); native {
							return true, "verified_qwen_native_wrapper", []gin.H{{"route": "native-http", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "native-sse", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "downstream-ws-turn", "supported": true, "reason": "verified_reused_downstream_per_turn"}}
						}
					}
				}
				return unavailable("plugin_operation_context_unavailable")
			}
			return true, "verified_selected_plugin_http", []gin.H{{"route": "selected-plugin-http", "supported": true, "reason": "verified_host_callback_context"}, {"route": "selected-plugin-sse", "supported": true, "reason": "verified_host_callback_context"}, {"route": "downstream-ws-turn", "supported": true, "reason": "verified_reused_downstream_per_turn"}}
		}
		return unavailable("plugin_source_unverified")
	}
	switch e.(type) {
	case *runtimeexecutor.ClaudeExecutor, *runtimeexecutor.OpenAICompatExecutor:
		return true, "verified_native_http_translation", []gin.H{{"route": "native-http", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "native-sse", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "downstream-ws-turn", "supported": true, "reason": "verified_reused_downstream_per_turn"}}
	case *runtimeexecutor.CodexExecutor:
		return true, "verified_native_http", []gin.H{{"route": "native-http", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "native-sse", "supported": true, "reason": "verified_final_transport_admission"}}
	case *runtimeexecutor.CodexAutoExecutor:
		return true, "verified_native_codex", []gin.H{{"route": "native-http", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "native-sse", "supported": true, "reason": "verified_final_transport_admission"}, {"route": "codex-websocket-business", "supported": true, "reason": "verified_per_frame_admission"}}
	default:
		return unavailable("native_route_verification_pending")
	}
}
