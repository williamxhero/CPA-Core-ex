package executor

import (
	"context"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func (e *CodexExecutor) codexHTTPBusinessError(ctx context.Context, a *cliproxyauth.Auth, res *http.Response, body, sent []byte, model string) statusErr {
	result := newCodexStatusErrWithHeadersAndCooling(res.StatusCode, res.Header, body, e.modelLevelCooling())
	evidence, ok := helps.ExtractCodexQuotaRejection(a, res, body, sent, model, time.Now())
	if !ok {
		return result
	}
	installed, handled := cliproxyexecutor.ObserveCodexQuotaRejection(ctx, evidence)
	if installed {
		result.persistentQuotaGate = handled
		result.credentialScoped = false
		if !handled {
			// The rejection is real but account-wide exhaustion is not proven.
			// The reset hint is a quota window, not a transient retry delay.
			result.transientRateLimit = true
			result.retryAfter = nil
		}
	}
	return result
}
