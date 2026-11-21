package handlers

import (
	"strings"

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
		c.Set(ginRoutingIDKey, id)
		c.Header("X-Request-ID", id)
	}
}

const ginRoutingIDKey = "trusted-scheduler-routing-request-id"

func IsRoutingCorrelationHeader(c *gin.Context, key string) bool {
	return strings.EqualFold(key, "X-Request-ID") && c.GetString(ginRoutingIDKey) != ""
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
