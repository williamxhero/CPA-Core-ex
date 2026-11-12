package auth

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Default bound for hold-until-complete stream recovery buffers. Exceeding it
// advances recovery from buffered to unbuffered mode for the next attempt.
const defaultStreamRecoveryBufferLimit = 1 << 20

type streamRecoveryMode int32

const (
	streamRecoveryBufferedSame streamRecoveryMode = iota
	streamRecoveryUnbufferedSame
	streamRecoveryBufferedCross
	streamRecoveryUnbufferedCross
)

func (mode streamRecoveryMode) String() string {
	switch mode {
	case streamRecoveryBufferedSame:
		return "buffered_same_provider"
	case streamRecoveryUnbufferedSame:
		return "unbuffered_same_provider"
	case streamRecoveryBufferedCross:
		return "buffered_cross_provider"
	case streamRecoveryUnbufferedCross:
		return "unbuffered_cross_provider"
	default:
		return "unknown"
	}
}

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
type streamReplayStateKey struct{}

// streamReplayState is shared by nested stream executions so the request-wide
// upstream retry budget cannot be reset by a replayed ExecuteStream call.
type streamReplayState struct {
	attempts          atomic.Int64
	mode              atomic.Int32
	preferredProvider atomic.Value
}

func (s *streamReplayState) recoveryMode() streamRecoveryMode {
	if s == nil {
		return streamRecoveryBufferedSame
	}
	return streamRecoveryMode(s.mode.Load())
}

func (s *streamReplayState) setRecoveryMode(mode streamRecoveryMode) {
	if s == nil {
		return
	}
	s.mode.Store(int32(mode))
}

func (s *streamReplayState) holdUntilComplete() bool {
	switch s.recoveryMode() {
	case streamRecoveryBufferedSame, streamRecoveryBufferedCross:
		return true
	default:
		return false
	}
}

func (s *streamReplayState) advancePastBufferLimit() streamRecoveryMode {
	if s == nil {
		return streamRecoveryUnbufferedSame
	}
	switch s.recoveryMode() {
	case streamRecoveryBufferedSame:
		s.setRecoveryMode(streamRecoveryUnbufferedSame)
		return streamRecoveryUnbufferedSame
	case streamRecoveryBufferedCross:
		s.setRecoveryMode(streamRecoveryUnbufferedCross)
		return streamRecoveryUnbufferedCross
	default:
		return s.recoveryMode()
	}
}

func (s *streamReplayState) sameProviderPreferred() bool {
	switch s.recoveryMode() {
	case streamRecoveryBufferedSame, streamRecoveryUnbufferedSame:
		return true
	default:
		return false
	}
}

func (s *streamReplayState) noteProvider(provider string) {
	if s == nil {
		return
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return
	}
	preferred, _ := s.preferredProvider.Load().(string)
	if preferred == "" {
		s.preferredProvider.Store(provider)
		return
	}
	if strings.EqualFold(preferred, provider) {
		return
	}
	switch s.recoveryMode() {
	case streamRecoveryBufferedSame:
		s.setRecoveryMode(streamRecoveryBufferedCross)
	case streamRecoveryUnbufferedSame:
		s.setRecoveryMode(streamRecoveryUnbufferedCross)
	}
}

func streamReplayForbidden(opts cliproxyexecutor.Options) bool {
	if len(opts.Metadata) == 0 {
		return false
	}
	if disabled, ok := opts.Metadata["disable_stream_replay"].(bool); ok && disabled {
		return true
	}
	if raw, ok := opts.Metadata["disable_stream_replay"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

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

func withStreamReplayState(ctx context.Context, state *streamReplayState) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, streamReplayStateKey{}, state)
}

func streamReplayStateFromContext(ctx context.Context) *streamReplayState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(streamReplayStateKey{}).(*streamReplayState)
	return state
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
