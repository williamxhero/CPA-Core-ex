package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/net/context"
)

func (h *BaseAPIHandler) startRoutingTrace(ctx context.Context, requested, normalized, selection string, internal bool) {
	if internal || h.AuthManager == nil {
		return
	}
	c, _ := ctx.Value("gin").(*gin.Context)
	if c == nil || c.Request == nil {
		return
	}
	if selection == "" {
		selection = normalized
	}
	if id := h.AuthManager.StartRoutingTrace(ctx, requested, selection); id != "" && !websocket.IsWebSocketUpgrade(c.Request) && !c.Writer.Written() {
		c.Header("X-Request-ID", id)
	}
}

func routingExecutionError(ctx context.Context, err error) error {
	return coreauth.RoutingErrorForResponse(ctx, err)
}

func externalExecutorSetupError(ctx context.Context, internal bool, err error) *interfaces.ErrorMessage {
	msg := executionErrorMessage(coreauth.ExternalExecutorRoutingError(ctx, err))
	if !internal {
		coreauth.FinishRoutingTrace(ctx, msg.StatusCode, msg.Error)
	}
	return msg
}
