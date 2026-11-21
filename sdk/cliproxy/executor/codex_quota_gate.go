package executor

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type codexQuotaObserverKey struct{}

// WithCodexQuotaObserver associates a native adapter's typed evidence with its
// already selected auth. Management and client HTTP cannot install a callback.
func WithCodexQuotaObserver(ctx context.Context, observe func(resource.CodexQuotaRejection) bool) context.Context {
	return context.WithValue(ctx, codexQuotaObserverKey{}, observe)
}

func ObserveCodexQuotaRejection(ctx context.Context, rejection resource.CodexQuotaRejection) (installed, handled bool) {
	observe, _ := ctx.Value(codexQuotaObserverKey{}).(func(resource.CodexQuotaRejection) bool)
	if observe == nil {
		return false, false
	}
	return true, observe(rejection)
}
