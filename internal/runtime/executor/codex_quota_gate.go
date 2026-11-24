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
		if handled {
			// The durable gate owns the stop; a second cooldown for the same
			// event would only duplicate the restriction.
			result.credentialScoped = false
		} else if cliproxyauth.PersistentRetryPilot(ctx) {
			// The OAuth inference response proves a window rejection. Without
			// current WHAM confirmation it does not prove every legal funding
			// source is exhausted. Do not turn this into a whole-account pause.
			result.credentialScoped = false
		} else {
			// The upstream rejection is still real even when the account-wide
			// confirmation could not be published. Keep the credential scope
			// and the body's reset deadline so the first 429 stops this
			// credential instead of becoming a transient retry loop that keeps
			// selecting the exhausted account.
			result.credentialScoped = true
		}
	}
	return result
}
