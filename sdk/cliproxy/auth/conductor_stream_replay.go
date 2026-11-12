package auth

import (
	"bytes"
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
	excludedAuthStore atomic.Value
	replayProviders   atomic.Value
	replayModel       atomic.Value
}

func (s *streamReplayState) setReplayScope(providers []string, model string) {
	if s == nil {
		return
	}
	s.replayProviders.Store(append([]string(nil), providers...))
	s.replayModel.Store(strings.TrimSpace(model))
}

func (s *streamReplayState) replayProvidersSnapshot() []string {
	if s == nil {
		return nil
	}
	providers, _ := s.replayProviders.Load().([]string)
	if len(providers) == 0 {
		return nil
	}
	return append([]string(nil), providers...)
}

func (s *streamReplayState) replayModelSnapshot() string {
	if s == nil {
		return ""
	}
	model, _ := s.replayModel.Load().(string)
	return strings.TrimSpace(model)
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
	}
}

func (s *streamReplayState) exhaustionProviders(providers []string) []string {
	if s == nil {
		return providers
	}
	if s.sameProviderPreferred() {
		return s.filterProviders(providers)
	}
	// Cross-provider stages are exhausted only when every non-preferred
	// provider has no remaining credentials. Checking the preferred provider
	// here would skip buffered_cross as soon as same-provider auths were
	// excluded for the earlier ladder stages.
	preferred, _ := s.preferredProvider.Load().(string)
	if preferred == "" {
		return providers
	}
	filtered := make([]string, 0, len(providers))
	for _, provider := range providers {
		if !strings.EqualFold(strings.TrimSpace(provider), preferred) {
			filtered = append(filtered, provider)
		}
	}
	if len(filtered) == 0 {
		return providers
	}
	return filtered
}

func (s *streamReplayState) filterProviders(providers []string) []string {
	if s == nil || !s.sameProviderPreferred() {
		return providers
	}
	preferred, _ := s.preferredProvider.Load().(string)
	if preferred == "" {
		return providers
	}
	filtered := make([]string, 0, len(providers))
	for _, provider := range providers {
		if strings.EqualFold(strings.TrimSpace(provider), preferred) {
			filtered = append(filtered, provider)
		}
	}
	if len(filtered) == 0 {
		return providers
	}
	return filtered
}

func (s *streamReplayState) excludedAuthIDs() []string {
	if s == nil {
		return nil
	}
	ids, _ := s.excludedAuthStore.Load().([]string)
	if len(ids) == 0 {
		return nil
	}
	return append([]string(nil), ids...)
}

func (s *streamReplayState) syncExcludedFromContext(ctx context.Context) {
	if s == nil {
		return
	}
	ids := streamReplayExcludedAuthIDsFromContext(ctx)
	if len(ids) == 0 {
		return
	}
	merged := s.excludedAuthIDs()
	for _, authID := range ids {
		authID = strings.TrimSpace(authID)
		if authID == "" {
			continue
		}
		seen := false
		for _, existing := range merged {
			if existing == authID {
				seen = true
				break
			}
		}
		if !seen {
			merged = append(merged, authID)
		}
	}
	s.excludedAuthStore.Store(append([]string(nil), merged...))
}

func (s *streamReplayState) noteExcluded(authID string) {
	if s == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	merged := s.excludedAuthIDs()
	for _, existing := range merged {
		if existing == authID {
			return
		}
	}
	merged = append(merged, authID)
	s.excludedAuthStore.Store(append([]string(nil), merged...))
}

func (s *streamReplayState) clearExcludedAuthIDs() {
	if s == nil {
		return
	}
	s.excludedAuthStore.Store([]string(nil))
}

// advanceOnAuthExhaustion moves to the next recovery stage when every eligible
// credential in the current stage has been excluded.
func (s *streamReplayState) advanceOnAuthExhaustion() bool {
	if s == nil {
		return false
	}
	switch s.recoveryMode() {
	case streamRecoveryBufferedSame:
		s.setRecoveryMode(streamRecoveryUnbufferedSame)
		s.clearExcludedAuthIDs()
		return true
	case streamRecoveryUnbufferedSame:
		s.setRecoveryMode(streamRecoveryBufferedCross)
		return true
	case streamRecoveryBufferedCross:
		s.setRecoveryMode(streamRecoveryUnbufferedCross)
		return true
	default:
		return false
	}
}

func streamReplayForbidden(opts cliproxyexecutor.Options) bool {
	if len(opts.Metadata) == 0 {
		return streamReplayForbiddenPayload(opts)
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
	if committed, ok := opts.Metadata["stream_replay_side_effects_committed"].(bool); ok && committed {
		return true
	}
	if raw, ok := opts.Metadata["stream_replay_side_effects_committed"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return streamReplayForbiddenPayload(opts)
}

func streamReplayForbiddenPayload(opts cliproxyexecutor.Options) bool {
	payload := opts.OriginalRequest
	if len(payload) == 0 {
		return false
	}
	lower := bytes.ToLower(payload)
	if !bytes.Contains(lower, []byte(`"tool_use"`)) {
		return false
	}
	return bytes.Contains(lower, []byte(`"tool_result"`)) || bytes.Contains(lower, []byte(`"function_result"`))
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
