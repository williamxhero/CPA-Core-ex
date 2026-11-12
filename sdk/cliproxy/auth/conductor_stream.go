package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func discardStreamChunks(ch <-chan cliproxyexecutor.StreamChunk) {
	if ch == nil {
		return
	}
	go func() {
		for range ch {
		}
	}()
}

type streamBootstrapError struct {
	cause   error
	headers http.Header
}

func cloneHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func newStreamBootstrapError(err error, headers http.Header) error {
	if err == nil {
		return nil
	}
	upstreamAttempt := hasUpstreamExecutionAttempt(err)
	err = unwrapUpstreamExecutionAttempt(err)
	bootstrapErr := &streamBootstrapError{
		cause:   err,
		headers: cloneHTTPHeader(headers),
	}
	if upstreamAttempt {
		return markUpstreamExecutionAttempt(bootstrapErr)
	}
	return bootstrapErr
}

func (e *streamBootstrapError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *streamBootstrapError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// StatusCode preserves the upstream HTTP status when a stream rejects before
// its first payload. Callers use this to distinguish a real capacity response
// from a locally synthesized stream error.
func (e *streamBootstrapError) StatusCode() int {
	if e == nil {
		return 0
	}
	return statusCodeFromError(e.cause)
}

func (e *streamBootstrapError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return cloneHTTPHeader(e.headers)
}

func streamErrorResult(headers http.Header, err error) *cliproxyexecutor.StreamResult {
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: err}
	close(ch)
	return &cliproxyexecutor.StreamResult{
		Headers: cloneHTTPHeader(headers),
		Chunks:  ch,
	}
}

func validateStreamResult(result *cliproxyexecutor.StreamResult, err error) (*cliproxyexecutor.StreamResult, error) {
	if err != nil {
		return result, err
	}
	if result == nil || result.Chunks == nil {
		return result, &Error{Code: "empty_stream", Message: "upstream stream has no source", Retryable: true}
	}
	return result, nil
}

func readStreamBootstrap(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, bool, error) {
	return readStreamBootstrapWithTimeout(ctx, ch, 0)
}

func readStreamBootstrapWithTimeout(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk, timeout time.Duration) ([]cliproxyexecutor.StreamChunk, bool, error) {
	if ch == nil {
		return nil, true, nil
	}
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}
	for {
		var (
			chunk cliproxyexecutor.StreamChunk
			ok    bool
		)
		if ctx != nil {
			// Prefer a chunk that is already available so an upstream error delivered together
			// with a context cancellation is not discarded.
			select {
			case chunk, ok = <-ch:
			default:
				select {
				case <-ctx.Done():
					return nil, false, ctx.Err()
				case <-timeoutCh:
					return nil, false, &Error{Code: "stream_bootstrap_timeout", Message: "upstream stream produced no payload before bootstrap timeout", Retryable: true, HTTPStatus: http.StatusGatewayTimeout}
				case chunk, ok = <-ch:
				}
			}
		} else {
			if timeoutCh == nil {
				chunk, ok = <-ch
			} else {
				select {
				case <-timeoutCh:
					return nil, false, &Error{Code: "stream_bootstrap_timeout", Message: "upstream stream produced no payload before bootstrap timeout", Retryable: true, HTTPStatus: http.StatusGatewayTimeout}
				case chunk, ok = <-ch:
				}
			}
		}
		if !ok {
			return buffered, true, nil
		}
		if chunk.Err != nil {
			return nil, false, chunk.Err
		}
		buffered = append(buffered, chunk)
		if len(chunk.Payload) > 0 {
			return buffered, false, nil
		}
	}
}

// recordCanceledUpstreamCooldown keeps an upstream-confirmed cooldown (an error carrying
// RetryAfter) when the request context was canceled while the executor was returning, for
// example because the downstream connection was closed in response to the same upstream error.
// Errors without RetryAfter, such as plain client cancellations, are not recorded.
func (m *Manager) recordCanceledUpstreamCooldown(ctx context.Context, auth *Auth, provider, resultModel, routeModel string, opts cliproxyexecutor.Options, err error, ephemeral bool, executionSeq uint64) {
	retryAfter := retryAfterFromError(err)
	if m == nil || auth == nil || retryAfter == nil {
		return
	}
	action, okAction := matchRequestScopedErrorAction(auth, err, m.requestScopedErrorConfig(ctx))
	result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: resultErrorFromError(err), Options: opts, RetryAfter: retryAfter, AccessToken: authAccessTokenForRequest(ctx, auth, opts.Headers), CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
	result.CredentialScope = isCredentialScopedError(err)
	applyRequestScopedActionToResult(action, okAction, &result)
	m.recordExecutionResult(context.WithoutCancel(ctx), result, auth, ephemeral)
}

func (m *Manager) streamBootstrapTimeout() time.Duration {
	if m == nil {
		return 0
	}
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil {
		return 0
	}
	return cfg.Codex.StreamBootstrapTimeoutDuration()
}

// streamGateAttemptWithTimeout bounds the provider call that creates the
// stream itself. A provider can stall before returning headers or a channel;
// readStreamBootstrapWithTimeout cannot protect that phase because it has not
// received a stream to read yet.
func (m *Manager) streamGateAttemptWithTimeout(ctx context.Context, executor ProviderExecutor, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	timeout := m.streamBootstrapTimeout()
	if timeout <= 0 {
		return m.streamGateAttempt(ctx, executor, auth, req, opts)
	}
	type gateResult struct {
		stream *cliproxyexecutor.StreamResult
		err    error
	}
	resultCh := make(chan gateResult, 1)
	go func() {
		stream, err := m.streamGateAttempt(ctx, executor, auth, req, opts)
		resultCh <- gateResult{stream: stream, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		return result.stream, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, &Error{Code: "stream_bootstrap_timeout", Message: "provider did not create a stream before bootstrap timeout", Retryable: true, HTTPStatus: http.StatusGatewayTimeout}
	}
}

func (m *Manager) wrapStreamResult(ctx context.Context, auth *Auth, provider, resultModel, routeModel string, headers http.Header, buffered []cliproxyexecutor.StreamChunk, remaining <-chan cliproxyexecutor.StreamChunk, aliasResult OAuthModelAliasResult, ephemeralResult bool, opts cliproxyexecutor.Options, executionSeq uint64, cancelUpstream context.CancelFunc) *cliproxyexecutor.StreamResult {
	ctx = WithCodexClientRequest(ctx, isOpenAIImageExecutionOptions(opts) || IsCodexClientRequest(ctx, opts.Headers))
	accessToken := authAccessTokenForRequest(ctx, auth, opts.Headers)
	out := make(chan cliproxyexecutor.StreamChunk)
	streamStart := time.Now()
	replay := streamReplayCoordinatorFromContext(ctx)
	replayState := streamReplayStateFromContext(ctx)
	// Unlimited upstream retries prefer hold-until-complete buffering so a
	// mid-stream transient failure can discard partial output and replay
	// without duplicating content already shown to the client.
	holdUntilComplete := replay != nil && m.configuredUpstreamErrorRetryLimit() == -1 && replayState.holdUntilComplete()
	if replayState != nil {
		replayState.noteProvider(provider)
	}
	go func() {
		defer close(out)
		var failed bool
		var sawCompleted bool
		var sawIncomplete bool
		var committed bool
		var deliveredAny bool
		replayed := false
		pending := make([]cliproxyexecutor.StreamChunk, 0, len(buffered))
		pendingBytes := 0
		for _, chunk := range buffered {
			pendingBytes += len(chunk.Payload)
		}
		bootstrapTimeout := m.streamBootstrapTimeout()
		var bootstrapTimer *time.Timer
		var bootstrapTimeoutCh <-chan time.Time
		startBootstrapTimer := func() {
			if bootstrapTimeout > 0 && bootstrapTimer == nil {
				bootstrapTimer = time.NewTimer(bootstrapTimeout)
				bootstrapTimeoutCh = bootstrapTimer.C
			}
		}
		stopBootstrapTimer := func() {
			if bootstrapTimer != nil {
				bootstrapTimer.Stop()
				bootstrapTimer = nil
				bootstrapTimeoutCh = nil
			}
		}
		resetBootstrapTimer := func() {
			stopBootstrapTimer()
			startBootstrapTimer()
		}
		startBootstrapTimer()
		defer func() {
			stopBootstrapTimer()
			if cancelUpstream != nil {
				cancelUpstream()
			}
		}()
		var rewriter *StreamRewriter
		if aliasResult.ForceMapping && strings.TrimSpace(aliasResult.OriginalAlias) != "" {
			rewriter = NewStreamRewriter(StreamRewriteOptions{RewriteModel: aliasResult.OriginalAlias})
		}
		logRecovery := func(event, stopReason string, err error) {
			entry := logEntryWithRequestID(ctx)
			if entry == nil {
				return
			}
			fields := map[string]any{
				"event":            event,
				"attempt":          streamReplayAttemptFromContext(ctx) + 1,
				"provider":         provider,
				"auth_id":          "",
				"buffer_mode":      holdUntilComplete,
				"committed_output": deliveredAny,
				"pending_bytes":    pendingBytes,
				"stop_reason":      stopReason,
			}
			if auth != nil {
				fields["auth_id"] = auth.ID
			}
			if err != nil {
				fields["error"] = err.Error()
			}
			entry.WithFields(fields).Info("stream recovery")
		}
		send := func(chunk cliproxyexecutor.StreamChunk) bool {
			if ctx == nil {
				out <- chunk
				return true
			}
			select {
			case <-ctx.Done():
				return false
			case out <- chunk:
				return true
			}
		}
		flushPending := func() bool {
			for _, chunk := range pending {
				if !send(chunk) {
					return false
				}
				deliveredAny = true
			}
			pending = pending[:0]
			pendingBytes = 0
			return true
		}
		discardPending := func() {
			pending = pending[:0]
			pendingBytes = 0
		}
		recordFailure := func(err error) {
			entry := logEntryWithRequestID(ctx)
			warnLogUpstreamFailure(ctx, entry, provider, resultModel, auth, time.Since(streamStart), err)
			rerr := resultErrorFromError(err)
			action, okAction := matchRequestScopedErrorAction(auth, err, m.requestScopedErrorConfig(ctx))
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: opts, AccessToken: accessToken, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
			result.RetryAfter = retryAfterFromError(err)
			result.CredentialScope = isCredentialScopedError(err)
			applyRequestScopedActionToResult(action, okAction, &result)
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
		}
		retryable := func(err error) bool {
			if err == nil || replay == nil || deliveredAny || (ctx != nil && ctx.Err() != nil) {
				return false
			}
			if statusCodeFromError(err) == http.StatusInsufficientStorage {
				var authErr *Error
				if errors.As(err, &authErr) && authErr != nil && authErr.Code == "stream_recovery_buffer_limit" {
					return true
				}
			}
			return isRetryableUpstreamFailure(err, clienterror.Classify(statusCodeFromError(err), err.Error()))
		}
		var bufferLimitErr error
		processPayload := func(chunk cliproxyexecutor.StreamChunk, applyRewrite bool) bool {
			bufferLimitErr = nil
			if chunk.Incomplete {
				sawIncomplete = true
			}
			if len(chunk.Payload) == 0 {
				return true
			}
			completedChunk, incompleteChunk := streamPayloadCompletionFlags(chunk.Payload)
			if completedChunk {
				sawCompleted = true
			}
			if incompleteChunk {
				sawIncomplete = true
			}
			payload := chunk.Payload
			if applyRewrite {
				payload = rewriteForceMappedStreamChunk(rewriter, payload)
			}
			if len(payload) == 0 {
				return true
			}
			chunk.Payload = payload
			if holdUntilComplete {
				if pendingBytes+len(payload) > defaultStreamRecoveryBufferLimit {
					nextMode := replayState.advancePastBufferLimit()
					logRecovery("stream_recovery_buffer_limit", nextMode.String(), nil)
					discardPending()
					stopBootstrapTimer()
					bufferLimitErr = &Error{
						Code:       "stream_recovery_buffer_limit",
						Message:    "stream recovery buffer exceeded memory limit",
						Retryable:  true,
						HTTPStatus: http.StatusInsufficientStorage,
					}
					return false
				}
				pending = append(pending, chunk)
				pendingBytes += len(payload)
				if streamPayloadCommitsOutput(payload) {
					committed = true
					stopBootstrapTimer()
				}
				if sawCompleted && !sawIncomplete {
					logRecovery("stream_recovery_release", "completed", nil)
					return flushPending()
				}
				return true
			}
			if !committed && !streamPayloadCommitsOutput(payload) {
				pending = append(pending, chunk)
				pendingBytes += len(payload)
				return true
			}
			if !committed {
				committed = true
				stopBootstrapTimer()
				if !flushPending() {
					return false
				}
			}
			deliveredAny = true
			return send(chunk)
		}
		processError := func(err error, source <-chan cliproxyexecutor.StreamChunk) (<-chan cliproxyexecutor.StreamChunk, bool) {
			if err == nil {
				return nil, false
			}
			recordFailure(err)
			if retryable(err) {
				// Stop the failed provider before selecting a replacement. This is
				// essential for silent providers whose stream would otherwise remain
				// alive while the client is waiting for recovery.
				if cancelUpstream != nil {
					cancelUpstream()
				}
				discardStreamChunks(source)
				discardPending()
				excludedAuthIDs := streamReplayExcludedAuthIDsFromContext(ctx)
				if auth != nil && strings.TrimSpace(auth.ID) != "" {
					seen := false
					for _, authID := range excludedAuthIDs {
						if authID == auth.ID {
							seen = true
							break
						}
					}
					if !seen {
						excludedAuthIDs = append(excludedAuthIDs, auth.ID)
					}
				}
				retryCtx := withStreamReplayExcludedAuthIDs(ctx, excludedAuthIDs)
				logRecovery("stream_recovery_retry", "replay", err)
				retryResult, retryErr := replay(retryCtx, err)
				if retryErr == nil && retryResult != nil && retryResult.Chunks != nil {
					pending = pending[:0]
					pendingBytes = 0
					failed = false
					sawCompleted = false
					sawIncomplete = false
					committed = false
					replayed = true
					holdUntilComplete = replay != nil && m.configuredUpstreamErrorRetryLimit() == -1 && replayState.holdUntilComplete()
					resetBootstrapTimer()
					return retryResult.Chunks, true
				}
				if retryErr != nil && !isCredentialSelectionFailure(retryErr) {
					err = retryErr
				}
			}
			failed = true
			logRecovery("stream_recovery_stop", "terminal_error", err)
			if holdUntilComplete {
				discardPending()
			} else if len(pending) > 0 && !flushPending() {
				return nil, false
			}
			_ = send(cliproxyexecutor.StreamChunk{Err: err})
			// Home owns the selection until the original producer terminates.
			// Drain after the terminal error without releasing its accounting early.
			if m.HomeEnabled() {
				for {
					select {
					case <-ctx.Done():
						return nil, false
					case _, open := <-source:
						if !open {
							return nil, false
						}
					}
				}
			}
			return nil, false
		}
		processNext := func(next cliproxyexecutor.StreamChunk, ok bool, source <-chan cliproxyexecutor.StreamChunk, rewrite bool) (<-chan cliproxyexecutor.StreamChunk, bool, bool) {
			if !ok {
				if holdUntilComplete && !sawCompleted && !failed {
					retry, okRetry := processError(&Error{Code: "incomplete_stream", Message: "upstream stream closed before response.completed", Retryable: true}, source)
					if okRetry {
						return retry, true, false
					}
					return nil, false, true
				}
				if !holdUntilComplete && !flushPending() {
					return nil, false, true
				}
				closed := make(chan cliproxyexecutor.StreamChunk)
				close(closed)
				return closed, false, false
			}
			if next.Err != nil {
				retry, okRetry := processError(next.Err, source)
				if okRetry {
					return retry, true, false
				}
				return nil, false, true
			}
			if !processPayload(next, rewrite) {
				if bufferLimitErr != nil {
					retry, okRetry := processError(bufferLimitErr, source)
					if okRetry {
						return retry, true, false
					}
				}
				discardStreamChunks(source)
				return nil, false, true
			}
			return source, false, false
		}

		current := remaining
		applyRewrite := true
		for {
			switched := false
			for _, chunk := range buffered {
				if chunk.Err != nil {
					var retry <-chan cliproxyexecutor.StreamChunk
					retry, okRetry := processError(chunk.Err, current)
					if okRetry {
						current = retry
						applyRewrite = false
						buffered = nil
						switched = true
						break
					}
					return
				}
				if !processPayload(chunk, applyRewrite) {
					if bufferLimitErr != nil {
						retry, okRetry := processError(bufferLimitErr, current)
						if okRetry {
							current = retry
							applyRewrite = false
							buffered = nil
							switched = true
							break
						}
					}
					discardStreamChunks(current)
					return
				}
			}
			if buffered != nil {
				buffered = nil
			}
			if !switched && !committed && len(pending) > 0 {
				if bootstrapTimeoutCh == nil {
					select {
					case next, ok := <-current:
						retry, didSwitch, stop := processNext(next, ok, current, applyRewrite)
						if stop {
							return
						}
						if didSwitch {
							current = retry
							applyRewrite = false
							switched = true
						} else {
							current = retry
						}
					default:
						if !holdUntilComplete {
							if !flushPending() {
								return
							}
						}
					}
				} else {
					select {
					case next, ok := <-current:
						retry, didSwitch, stop := processNext(next, ok, current, applyRewrite)
						if stop {
							return
						}
						if didSwitch {
							current = retry
							applyRewrite = false
							switched = true
						} else {
							current = retry
						}
					case <-bootstrapTimeoutCh:
						retry, didSwitch := processError(&Error{Code: "stream_bootstrap_timeout", Message: "upstream stream produced no payload before bootstrap timeout", Retryable: true, HTTPStatus: http.StatusGatewayTimeout}, current)
						if didSwitch {
							current = retry
							applyRewrite = false
							switched = true
						} else {
							return
						}
					}
				}
			}
			if switched {
				continue
			}
			for {
				var (
					chunk cliproxyexecutor.StreamChunk
					ok    bool
				)
				if !committed && bootstrapTimeoutCh != nil {
					select {
					case <-ctx.Done():
						discardPending()
						logRecovery("stream_recovery_stop", "client_canceled", ctx.Err())
						return
					case <-bootstrapTimeoutCh:
						retry, okRetry := processError(&Error{Code: "stream_bootstrap_timeout", Message: "upstream stream produced no payload before bootstrap timeout", Retryable: true, HTTPStatus: http.StatusGatewayTimeout}, current)
						if okRetry {
							current = retry
							applyRewrite = false
							switched = true
							break
						}
						return
					case chunk, ok = <-current:
					}
				} else if holdUntilComplete {
					select {
					case <-ctx.Done():
						discardPending()
						logRecovery("stream_recovery_stop", "client_canceled", ctx.Err())
						return
					case chunk, ok = <-current:
					}
				} else {
					// Deliver handshake metadata before waiting for more upstream data.
					// Interactive clients need the response ID to interrupt an HTTP turn.
					select {
					case chunk, ok = <-current:
					default:
						if !flushPending() {
							return
						}
						chunk, ok = <-current
					}
				}
				if !ok {
					if holdUntilComplete && !sawCompleted && !failed {
						retry, okRetry := processError(&Error{Code: "incomplete_stream", Message: "upstream stream closed before response.completed", Retryable: true}, current)
						if okRetry {
							current = retry
							applyRewrite = false
							switched = true
							break
						}
						return
					}
					break
				}
				if chunk.Err != nil {
					retry, okRetry := processError(chunk.Err, current)
					if okRetry {
						current = retry
						applyRewrite = false
						switched = true
						break
					}
					return
				}
				if !processPayload(chunk, applyRewrite) {
					if bufferLimitErr != nil {
						retry, okRetry := processError(bufferLimitErr, current)
						if okRetry {
							current = retry
							applyRewrite = false
							switched = true
							break
						}
					}
					discardStreamChunks(current)
					return
				}
			}
			if switched {
				continue
			}
			if failed {
				return
			}
			break
		}
		if !replayed {
			if tail := finishForceMappedStreamChunks(rewriter); len(tail) > 0 {
				if !processPayload(cliproxyexecutor.StreamChunk{Payload: tail}, true) {
					return
				}
			}
		}
		if holdUntilComplete {
			if !failed && sawCompleted && len(pending) > 0 && !flushPending() {
				return
			}
		} else if !committed && len(pending) > 0 && !flushPending() {
			return
		}
		if !failed && !replayed && (ephemeralResult || claudeOAuthRequestCancellation(ctx, auth, nil) == nil) {
			m.recordExecutionResult(ctx, Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: true, CompletedResponse: sawCompleted && !sawIncomplete, Options: opts, AccessToken: accessToken, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}, auth, ephemeralResult)
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}
}

func streamPayloadCommitsOutput(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	for _, rawLine := range bytes.Split(payload, []byte("\n")) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 || bytes.HasPrefix(line, []byte(":")) || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) {
			continue
		}
		data := line
		if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		if bytes.Equal(data, []byte("[DONE]")) || len(data) == 0 {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil || len(obj) == 0 {
			return true
		}
		eventType, _ := obj["type"].(string)
		switch strings.ToLower(strings.TrimSpace(eventType)) {
		case "response.created", "response.in_progress", "response.metadata", "codex.response.metadata", "codex.rate_limits", "rate_limits.updated", "keepalive", "ping":
			continue
		case "response.output_item.added", "response.output_item.done", "response.content_part.added", "response.reasoning_summary_part.added":
			if util.IsResponsesBootstrapEvent(eventType, data) {
				continue
			}
			return true
		case "message_start":
			// Codex-to-Claude translation emits this envelope before any model
			// output. Keep it pending so an incomplete upstream can be replayed
			// without exposing a failed message ID to the Claude client.
			message, _ := obj["message"].(map[string]any)
			content, _ := message["content"].([]any)
			if len(content) == 0 {
				continue
			}
			return true
		case "content_block_start":
			block, _ := obj["content_block"].(map[string]any)
			blockType, _ := block["type"].(string)
			if (blockType == "text" && block["text"] == "") ||
				(blockType == "thinking" && block["thinking"] == "") {
				continue
			}
			return true
		case "content_block_delta":
			delta, _ := obj["delta"].(map[string]any)
			deltaType, _ := delta["type"].(string)
			// Encrypted reasoning signatures carry replay state, not visible
			// output. Do not let a signature-only thinking block disable retry.
			if deltaType == "signature_delta" ||
				(deltaType == "text_delta" && delta["text"] == "") ||
				(deltaType == "thinking_delta" && delta["thinking"] == "") {
				continue
			}
			return true
		case "content_block_stop":
			// A visible block already committed at its content event. Closing
			// an empty or signature-only block does not commit new output.
			continue
		case "response.completed", "response.done":
			return true
		case "response.output_text.delta", "response.reasoning_text.delta", "response.reasoning_summary_text.delta", "response.function_call_arguments.delta", "response.custom_tool_call_input.delta", "response.refusal.delta":
			if delta, ok := obj["delta"].(string); ok && delta == "" {
				continue
			}
			return true
		default:
			return true
		}
	}
	return false
}

func streamPayloadCompletionFlags(payload []byte) (completed, incomplete bool) {
	if len(payload) == 0 {
		return false, false
	}
	for _, rawLine := range bytes.Split(payload, []byte("\n")) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 || bytes.HasPrefix(line, []byte(":")) || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) {
			continue
		}
		data := line
		if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		if bytes.Equal(data, []byte("[DONE]")) {
			continue
		}
		if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
			continue
		}
		comp, incomp := jsonObjectCompletionFlags(data)
		if comp {
			completed = true
		}
		if incomp {
			incomplete = true
		}
	}
	return completed, incomplete
}

func jsonObjectCompletionFlags(rawJSON []byte) (completed, incomplete bool) {
	var obj map[string]any
	if err := json.Unmarshal(rawJSON, &obj); err != nil || len(obj) == 0 {
		return false, false
	}
	if obj["error"] != nil {
		return false, true
	}
	eventType, _ := obj["type"].(string)
	eventType = strings.TrimSpace(eventType)
	status, _ := obj["status"].(string)
	status = strings.ToLower(strings.TrimSpace(status))
	if respObj, ok := obj["response"].(map[string]any); ok {
		if respObj["error"] != nil || respObj["incomplete_details"] != nil {
			incomplete = true
		}
		if respStatus, _ := respObj["status"].(string); strings.TrimSpace(respStatus) != "" {
			status = strings.ToLower(strings.TrimSpace(respStatus))
		}
	}
	switch status {
	case "incomplete", "failed", "cancelled", "canceled":
		return false, true
	}
	switch eventType {
	case "response.incomplete", "response.failed", "response.cancelled", "response.canceled", "error":
		return false, true
	case "response.completed", "response.done", "message_stop":
		if status == "" || status == "completed" {
			return true, incomplete
		}
		return false, true
	case "message_delta":
		if deltaObj, ok := obj["delta"].(map[string]any); ok {
			if sr, okSR := deltaObj["stop_reason"].(string); okSR {
				switch strings.ToLower(strings.TrimSpace(sr)) {
				case "max_tokens", "StopSequenceMaxTokens":
					incomplete = true
				case "end_turn", "stop_sequence", "tool_use":
					completed = true
				}
			}
		}
	}
	if choices, ok := obj["choices"].([]any); ok {
		for _, item := range choices {
			choice, okChoice := item.(map[string]any)
			if !okChoice {
				continue
			}
			fr, okFR := choice["finish_reason"].(string)
			if !okFR {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(fr)) {
			case "length", "content_filter":
				incomplete = true
			case "stop", "tool_calls", "function_call", "end_turn":
				completed = true
			}
		}
	}
	if candidates, ok := obj["candidates"].([]any); ok {
		for _, item := range candidates {
			cand, okCand := item.(map[string]any)
			if !okCand {
				continue
			}
			fr, okFR := cand["finishReason"].(string)
			if !okFR {
				continue
			}
			switch strings.ToUpper(strings.TrimSpace(fr)) {
			case "MAX_TOKENS", "SAFETY", "RECITATION", "OTHER":
				incomplete = true
			case "STOP":
				completed = true
			}
		}
	}
	return completed, incomplete
}

func isCompletedExecutionPayload(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(trimmed, &obj); err != nil || len(obj) == 0 {
		return false
	}
	if obj["error"] != nil || obj["incomplete_details"] != nil {
		return false
	}
	comp, incomp := jsonObjectCompletionFlags(trimmed)
	if incomp {
		return false
	}
	if comp {
		return true
	}
	status, _ := obj["status"].(string)
	status = strings.ToLower(strings.TrimSpace(status))
	if respObj, ok := obj["response"].(map[string]any); ok {
		if respObj["error"] != nil || respObj["incomplete_details"] != nil {
			return false
		}
		if respStatus, _ := respObj["status"].(string); strings.TrimSpace(respStatus) != "" {
			status = strings.ToLower(strings.TrimSpace(respStatus))
		}
	}
	switch status {
	case "incomplete", "failed", "cancelled", "canceled", "in_progress", "queued":
		return false
	case "completed":
		return true
	}
	if objType, _ := obj["type"].(string); strings.TrimSpace(objType) == "message" {
		if stopReason, ok := obj["stop_reason"].(string); ok && strings.TrimSpace(stopReason) != "" {
			return true
		}
	}
	if output, ok := obj["output"].([]any); ok && len(output) > 0 && status == "" {
		return true
	}
	return false
}

func (m *Manager) executeStreamWithModelPool(ctx context.Context, executor ProviderExecutor, auth *Auth, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, routeModel, executionModel string, execModels []string, pooled bool, aliasResult OAuthModelAliasResult, routing *apiKeyModelRoutingSnapshot, allowRetry bool, ephemeralResult bool) (*cliproxyexecutor.StreamResult, error) {
	if executor == nil {
		return nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	executor = executorForAuth(executor, auth)
	ctx = contextWithRequestedModelAlias(ctx, opts, routeModel)
	var lastErr error
	var upstreamErr error
	didRefreshOnUnauthorized := false
	readBootstrap := func(attemptCtx context.Context, cancelAttempt context.CancelFunc, ch <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, bool, error) {
		timeout := m.streamBootstrapTimeout()
		buffered, closed, errBootstrap := readStreamBootstrapWithTimeout(attemptCtx, ch, timeout)
		var timeoutErr *Error
		if errors.As(errBootstrap, &timeoutErr) && timeoutErr != nil && timeoutErr.Code == "stream_bootstrap_timeout" {
			cancelAttempt()
		}
		return buffered, closed, errBootstrap
	}
	for idx, execModel := range execModels {
		ctx = m.newUpstreamAttemptContext(ctx)
		resultModel := m.stateModelForExecution(auth, routeModel, execModel, pooled)
		execReq := req
		execReq.Model = execModel
		if executionModel != "" {
			execReq.Model = executionModel
		}
		execOpts := opts
		var errIntercept error
		execReq, execOpts, errIntercept = applyRequestAfterAuthInterceptor(ctx, executor, provider, execReq, execOpts, requestedModelAliasFromOptions(execOpts, routeModel))
		if errIntercept != nil {
			return nil, errIntercept
		}
		execReq = attachResolvedExecutionModelInfo(routing, execReq, auth, routeModel, execModel, executionModel != "")
		if errCtx := ctx.Err(); errCtx != nil {
			return nil, errCtx
		}
		entry := logEntryWithRequestID(ctx)
		payload := execOpts.OriginalRequest
		if len(payload) == 0 {
			payload = execReq.Payload
		}
		execOpts.Metadata = ensureCanonicalSessionMetadata(execOpts.Metadata, execOpts.Headers, payload)
		ctx = syncMetadataSessionToContext(ctx, execOpts.Metadata)
		executionSeq := m.nextExecutionSeq()
		startStream := time.Now()
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		streamResult, errStream := m.streamGateAttemptWithTimeout(attemptCtx, executor, auth, execReq, execOpts)
		errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
		if hasUpstreamExecutionAttempt(errStream) {
			upstreamErr = errStream
		}
		durationStream := time.Since(startStream)
		if errStream != nil {
			cancelAttempt()
			if errCtx := ctx.Err(); errCtx != nil {
				m.recordCanceledUpstreamCooldown(ctx, auth, provider, resultModel, routeModel, execOpts, errStream, ephemeralResult, executionSeq)
				return nil, errCtx
			}
			if allowRetry && !ephemeralResult {
				alreadyTried := didRefreshOnUnauthorized
				refreshed, okRefresh := m.tryRefreshAfterUnauthorized(newUpstreamAttemptContext(ctx), auth, errStream, alreadyTried, execOpts.Headers)
				if okRefresh {
					auth = refreshed
					publishSelectedAuthMetadata(execOpts.Metadata, auth)
					didRefreshOnUnauthorized = true
					ctx = m.newUpstreamAttemptContext(ctx)
					ctx = syncMetadataSessionToContext(ctx, execOpts.Metadata)
					executionSeq = m.nextExecutionSeq()
					startRetry := time.Now()
					attemptCtx, cancelAttempt = context.WithCancel(ctx)
					streamResult, errStream = m.streamGateAttemptWithTimeout(attemptCtx, executor, auth, execReq, execOpts)
					errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
					if hasUpstreamExecutionAttempt(errStream) {
						upstreamErr = errStream
					}
					durationRetry := time.Since(startRetry)
					if errStream != nil {
						cancelAttempt()
						warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationRetry, errStream)
						if errCtx := ctx.Err(); errCtx != nil {
							m.recordCanceledUpstreamCooldown(ctx, auth, provider, resultModel, routeModel, execOpts, errStream, ephemeralResult, executionSeq)
							return nil, errCtx
						}
					}
				} else {
					warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationStream, errStream)
				}
			} else {
				warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationStream, errStream)
			}
		}
		if !ephemeralResult {
			if errCancel := claudeOAuthRequestCancellation(ctx, auth, errStream); errCancel != nil {
				return nil, errCancel
			}
		}
		streamResult, errStream = validateStreamResult(streamResult, errStream)
		errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
		if errStream != nil {
			rerr := resultErrorFromError(errStream)
			action, okAction := matchRequestScopedErrorAction(auth, errStream, m.requestScopedErrorConfig(ctx))
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
			result.RetryAfter = retryAfterFromError(errStream)
			if isCredentialScopedError(errStream) {
				result.CredentialScope = true
			}
			applyRequestScopedActionToResult(action, okAction, &result)
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			errStream = annotateTrustedRetryAfterByHint(errStream)
			syncPreferredUpstreamError(&upstreamErr, errStream)
			if okAction {
				if isRequestScopedStop(action, okAction) {
					return nil, wrapRequestStopError(errStream)
				}
				lastErr = errStream
				if result.CredentialScope {
					return nil, preferredExecutionAttemptError(errStream, upstreamErr)
				}
				continue
			}
			if isRequestInvalidError(errStream) || cliproxyexecutor.IsUpstreamWebsocketTurnError(errStream) {
				return nil, errStream
			}
			lastErr = errStream
			if result.CredentialScope {
				return nil, preferredExecutionAttemptError(errStream, upstreamErr)
			}
			continue
		}

		buffered, closed, bootstrapErr := readBootstrap(attemptCtx, cancelAttempt, streamResult.Chunks)
		if bootstrapErr != nil {
			cancelAttempt()
		}
		bootstrapErr = markUpstreamExecutionAttemptFromContext(ctx, bootstrapErr)
		if hasUpstreamExecutionAttempt(bootstrapErr) {
			upstreamErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
		}
		if bootstrapErr != nil {
			if errCtx := ctx.Err(); errCtx != nil {
				m.recordCanceledUpstreamCooldown(ctx, auth, provider, resultModel, routeModel, execOpts, bootstrapErr, ephemeralResult, executionSeq)
				discardStreamChunks(streamResult.Chunks)
				return nil, errCtx
			}
			if allowRetry && !ephemeralResult {
				alreadyTried := didRefreshOnUnauthorized
				refreshed, okRefresh := m.tryRefreshAfterUnauthorized(newUpstreamAttemptContext(ctx), auth, bootstrapErr, alreadyTried, execOpts.Headers)
				if okRefresh {
					discardStreamChunks(streamResult.Chunks)
					auth = refreshed
					publishSelectedAuthMetadata(execOpts.Metadata, auth)
					didRefreshOnUnauthorized = true
					ctx = m.newUpstreamAttemptContext(ctx)
					executionSeq = m.nextExecutionSeq()
					startRetry := time.Now()
					attemptCtx, cancelAttempt = context.WithCancel(ctx)
					retryStream, retryErr := m.streamGateAttemptWithTimeout(attemptCtx, executor, auth, execReq, execOpts)
					retryErr = markUpstreamExecutionAttemptFromContext(ctx, retryErr)
					retryStream, retryErr = validateStreamResult(retryStream, retryErr)
					retryErr = markUpstreamExecutionAttemptFromContext(ctx, retryErr)
					if retryErr != nil {
						cancelAttempt()
						if errCtx := ctx.Err(); errCtx != nil {
							m.recordCanceledUpstreamCooldown(ctx, auth, provider, resultModel, routeModel, execOpts, retryErr, ephemeralResult, executionSeq)
							return nil, errCtx
						}
						bootstrapErr = retryErr
						warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startRetry), bootstrapErr)
						streamResult = &cliproxyexecutor.StreamResult{}
					} else {
						streamResult = retryStream
						buffered, closed, bootstrapErr = readBootstrap(attemptCtx, cancelAttempt, streamResult.Chunks)
						if bootstrapErr != nil {
							cancelAttempt()
						}
						bootstrapErr = markUpstreamExecutionAttemptFromContext(ctx, bootstrapErr)
						if bootstrapErr != nil {
							warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startRetry), bootstrapErr)
						}
					}
				} else {
					warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), bootstrapErr)
				}
			} else {
				warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), bootstrapErr)
			}
			if hasUpstreamExecutionAttempt(bootstrapErr) {
				upstreamErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
			}
		}
		if !ephemeralResult {
			if errCancel := claudeOAuthRequestCancellation(ctx, auth, bootstrapErr); errCancel != nil {
				discardStreamChunks(streamResult.Chunks)
				return nil, errCancel
			}
		}
		if bootstrapErr != nil {
			action, okAction := matchRequestScopedErrorAction(auth, bootstrapErr, m.requestScopedErrorConfig(ctx))
			if okAction {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				applyRequestScopedActionToResult(action, okAction, &result)
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				bootstrapErr = annotateTrustedRetryAfterByHint(bootstrapErr)
				bootstrapErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
				syncPreferredUpstreamError(&upstreamErr, bootstrapErr)
				discardStreamChunks(streamResult.Chunks)
				if isRequestScopedStop(action, okAction) {
					return nil, wrapRequestStopError(bootstrapErr)
				}
				lastErr = bootstrapErr
				if result.CredentialScope {
					currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
					return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
				}
				continue
			}
			if isRequestInvalidError(bootstrapErr) || cliproxyexecutor.IsUpstreamWebsocketTurnError(bootstrapErr) {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				bootstrapErr = annotateTrustedRetryAfterByHint(bootstrapErr)
				syncPreferredUpstreamError(&upstreamErr, bootstrapErr)
				discardStreamChunks(streamResult.Chunks)
				return nil, bootstrapErr
			}
			if idx < len(execModels)-1 {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				bootstrapErr = annotateTrustedRetryAfterByHint(bootstrapErr)
				bootstrapErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
				syncPreferredUpstreamError(&upstreamErr, bootstrapErr)
				discardStreamChunks(streamResult.Chunks)
				lastErr = bootstrapErr
				if result.CredentialScope {
					currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
					return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
				}
				continue
			}
			rerr := resultErrorFromError(bootstrapErr)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
			result.RetryAfter = retryAfterFromError(bootstrapErr)
			if isCredentialScopedError(bootstrapErr) {
				result.CredentialScope = true
			}
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			bootstrapErr = annotateTrustedRetryAfterByHint(bootstrapErr)
			bootstrapErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
			syncPreferredUpstreamError(&upstreamErr, bootstrapErr)
			discardStreamChunks(streamResult.Chunks)
			currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
			return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
		}

		if closed && len(buffered) == 0 {
			emptyErr := markUpstreamExecutionAttemptFromContext(ctx, &Error{Code: "empty_stream", Message: "upstream stream closed before first payload", Retryable: true})
			currentErr := newStreamBootstrapError(emptyErr, streamResult.Headers)
			if hasUpstreamExecutionAttempt(emptyErr) {
				upstreamErr = currentErr
			}
			warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), emptyErr)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: resultErrorFromError(emptyErr), Options: execOpts, CredentialVersion: auth.CredentialVersion, RegistrationEpoch: auth.RegistrationEpoch, ExecutionSeq: executionSeq}
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			if idx < len(execModels)-1 {
				lastErr = emptyErr
				continue
			}
			return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
		}

		remaining := streamResult.Chunks
		if closed {
			closedCh := make(chan cliproxyexecutor.StreamChunk)
			close(closedCh)
			remaining = closedCh
		}
		attemptAliasResult := resolveAttemptAliasResult(routing, auth, routeModel, execModel, aliasResult)
		// Keep the replay coordinator on the request context while isolating the
		// old upstream attempt in attemptCtx. The replay must survive the
		// cancellation that tears down the failed provider connection.
		return m.wrapStreamResult(ctx, auth.Clone(), provider, resultModel, routeModel, streamResult.Headers, buffered, remaining, attemptAliasResult, ephemeralResult, execOpts, executionSeq, cancelAttempt), nil
	}
	if lastErr == nil {
		lastErr = &Error{Code: "auth_not_found", Message: "no upstream model available"}
	}
	return nil, preferredExecutionAttemptError(lastErr, upstreamErr)
}
