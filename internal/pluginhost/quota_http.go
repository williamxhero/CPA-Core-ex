package pluginhost

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type quotaHTTPKey struct{}

// WithQuotaHTTPClient is invocation-local, including compiled plugin callbacks.
// Never install it on the host or on an inference request context.
func WithQuotaHTTPClient(ctx context.Context, client pluginapi.HostHTTPClient) context.Context {
	return context.WithValue(ctx, quotaHTTPKey{}, client)
}
