package auth

import (
	"context"
	"net/url"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func cloneStreamReplayQuery(src url.Values) url.Values {
	if len(src) == 0 {
		return nil
	}
	dst := make(url.Values, len(src))
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
	return dst
}

type streamReplayCoordinator func(context.Context, error) (*cliproxyexecutor.StreamResult, error)

type streamReplayCoordinatorKey struct{}
type streamReplayDisabledKey struct{}
type streamReplayAttemptKey struct{}
type streamReplayExcludedAuthIDsKey struct{}

func withStreamReplayCoordinator(ctx context.Context, coordinator streamReplayCoordinator) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, streamReplayCoordinatorKey{}, coordinator)
}

func streamReplayCoordinatorFromContext(ctx context.Context) streamReplayCoordinator {
	if ctx == nil {
		return nil
	}
	coordinator, _ := ctx.Value(streamReplayCoordinatorKey{}).(streamReplayCoordinator)
	return coordinator
}

func withStreamReplayDisabled(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, streamReplayDisabledKey{}, true)
}

func streamReplayDisabled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	disabled, _ := ctx.Value(streamReplayDisabledKey{}).(bool)
	return disabled
}

func withStreamReplayAttempt(ctx context.Context, attempt int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, streamReplayAttemptKey{}, attempt)
}

func streamReplayAttemptFromContext(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	attempt, _ := ctx.Value(streamReplayAttemptKey{}).(int)
	if attempt < 0 {
		return 0
	}
	return attempt
}

func withStreamReplayExcludedAuthIDs(ctx context.Context, authIDs []string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	cloned := append([]string(nil), authIDs...)
	return context.WithValue(ctx, streamReplayExcludedAuthIDsKey{}, cloned)
}

func streamReplayExcludedAuthIDsFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	ids, _ := ctx.Value(streamReplayExcludedAuthIDsKey{}).([]string)
	return append([]string(nil), ids...)
}
