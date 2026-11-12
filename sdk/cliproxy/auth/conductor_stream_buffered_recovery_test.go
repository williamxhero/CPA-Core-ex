package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func codexAlwaysFailStreamMock(mu *sync.Mutex, attempts *[]string) func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
		mu.Lock()
		*attempts = append(*attempts, auth.ID)
		mu.Unlock()
		chunks := make(chan cliproxyexecutor.StreamChunk, 2)
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"codex-hold\"}}\n\n")}
		chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "server_is_overloaded", Retryable: true}}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}
}

func TestExecuteStreamBufferedRecoveryAfterPartialOutputSameProvider(t *testing.T) {
	const (
		model = "stream-buffered-recovery-model"
		authA = "stream-buffered-recovery-a"
		authB = "stream-buffered-recovery-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	for _, id := range []string{authA, authB} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}

	var mu sync.Mutex
	var attempts []string
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 4)
			if auth.ID == authA {
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"partial-attempt\"}}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial-should-discard\"}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: `{"error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded."}}`, Retryable: true}}
			} else {
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"recovered\"}}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"final-answer\"}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")}
			}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var payload strings.Builder
	var streamErr error
	for chunk := range stream.Chunks {
		payload.Write(chunk.Payload)
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
	}
	if streamErr != nil {
		t.Fatalf("buffered recovery leaked terminal error: %v", streamErr)
	}
	got := payload.String()
	if strings.Contains(got, "partial-should-discard") || strings.Contains(got, "partial-attempt") {
		t.Fatalf("partial buffered attempt leaked to client: %q", got)
	}
	if !strings.Contains(got, "final-answer") || !strings.Contains(got, "recovered") {
		t.Fatalf("recovered payload missing: %q", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 2 || gotAttempts[0] != authA || gotAttempts[1] != authB {
		t.Fatalf("attempts = %v, want [%s %s]", gotAttempts, authA, authB)
	}
}

func TestExecuteStreamBufferedRecoveryCrossProviderFallback(t *testing.T) {
	const (
		model     = "stream-cross-provider-model"
		codexAuth = "stream-cross-codex"
		openAuth  = "stream-cross-openai"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.runtimeConfig.Store(&internalconfig.Config{Codex: internalconfig.CodexConfig{StreamBootstrapTimeout: "0"}})
	for _, item := range []struct {
		id       string
		provider string
	}{{codexAuth, "codex"}, {openAuth, "openai"}} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: item.id, Provider: item.provider, Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", item.id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(item.id, item.provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(item.id) })
	}

	var mu sync.Mutex
	var attempts []string
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "server_is_overloaded", Retryable: true}}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "openai",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"openai-final\"}]}]}}\n\n")}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex", "openai"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var payload strings.Builder
	var streamErr error
	for chunk := range stream.Chunks {
		payload.Write(chunk.Payload)
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
	}
	if streamErr != nil {
		t.Fatalf("cross-provider recovery leaked error: %v", streamErr)
	}
	got := payload.String()
	if strings.Contains(got, "codex-partial") || !strings.Contains(got, "openai-final") {
		t.Fatalf("payload = %q", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) < 2 || gotAttempts[len(gotAttempts)-1] != openAuth {
		t.Fatalf("attempts = %v", gotAttempts)
	}
}

func TestExecuteStreamBufferLimitStaysUnbufferedAcrossFailover(t *testing.T) {
	const (
		model = "stream-buffer-limit-sticky-model"
		authA = "stream-buffer-limit-sticky-a"
		authB = "stream-buffer-limit-sticky-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	for _, id := range []string{authA, authB} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}

	var mu sync.Mutex
	var attempts []string
	oversized := strings.Repeat("x", (1<<20)/3)
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			n := len(attempts)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 8)
			switch {
			case n == 1 && auth.ID == authA:
				// Hold-until-complete accumulates past 1MiB → buffer_limit.
				for i := 0; i < 4; i++ {
					chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.output_text.delta","delta":"` + oversized + `"}\n\n`)}
				}
				go func() {
					<-ctx.Done()
					close(chunks)
				}()
			default:
				// Failover auth recovers. Sticky forceUnbuffered keeps this
				// attempt from holding again (covered with ladder unit test).
				_ = n
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"after-limit\"}}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"sticky-unbuffered\"}\n\n")}
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")}
				close(chunks)
			}
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var payload strings.Builder
	var streamErr error
	for chunk := range stream.Chunks {
		payload.Write(chunk.Payload)
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
	}
	if streamErr != nil {
		t.Fatalf("sticky unbuffered recovery leaked terminal error: %v", streamErr)
	}
	got := payload.String()
	if !strings.Contains(got, "sticky-unbuffered") {
		t.Fatalf("expected recovered unbuffered payload, got %q", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) < 2 {
		t.Fatalf("attempts = %v, want failover after buffer limit", gotAttempts)
	}
	if gotAttempts[0] != authA {
		t.Fatalf("first attempt = %s, want %s", gotAttempts[0], authA)
	}
}

func TestExecuteStreamBufferLimitThenGatedAdmissionFailsClosed(t *testing.T) {
	const (
		model = "stream-buffer-limit-gated-model"
		authA = "stream-buffer-limit-gated-a"
		authB = "stream-buffer-limit-gated-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	for _, id := range []string{authA, authB} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}

	var mu sync.Mutex
	var attempts []string
	oversized := strings.Repeat("x", (1<<20)/3)
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			n := len(attempts)
			mu.Unlock()
			if opts.Metadata == nil {
				opts.Metadata = map[string]any{}
			}
			opts.Metadata[cliproxyexecutor.SelectedAuthMetadataKey] = auth.ID
			if auth.ID == authB {
				return nil, &cliproxyexecutor.InferenceAdmissionError{}
			}
			chunks := make(chan cliproxyexecutor.StreamChunk, 8)
			if n == 1 && auth.ID == authA {
				for i := 0; i < 4; i++ {
					chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.output_text.delta","delta":"` + oversized + `"}\n\n`)}
				}
				go func() {
					<-ctx.Done()
					close(chunks)
				}()
				return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
			}
			// A second buffered hold on authA would hang the test; fail loudly.
			t.Errorf("unexpected retry on %s (attempt %d); recovery must fail closed", auth.ID, n)
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{
		Stream:   true,
		Metadata: map[string]any{},
	})
	if errExecute != nil {
		// Fail-closed may surface before a stream handle is returned.
		if !cliproxyexecutor.IsInferenceAdmissionError(errExecute) &&
			!strings.Contains(strings.ToLower(errExecute.Error()), "admission") &&
			!strings.Contains(strings.ToLower(errExecute.Error()), "auth") {
			t.Fatalf("ExecuteStream(): %v", errExecute)
		}
	} else {
		var streamErr error
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				streamErr = chunk.Err
			}
		}
		if streamErr == nil {
			t.Fatal("expected terminal failure after buffer limit + gated admission")
		}
		if !strings.Contains(strings.ToLower(streamErr.Error()), "admission") &&
			!strings.Contains(strings.ToLower(streamErr.Error()), "auth") &&
			!strings.Contains(strings.ToLower(streamErr.Error()), "stream_recovery_buffer_limit") {
			t.Fatalf("terminal error = %v, want admission/auth/buffer-limit failure", streamErr)
		}
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	authACount := 0
	for _, id := range gotAttempts {
		if id == authA {
			authACount++
		}
	}
	if authACount != 1 {
		t.Fatalf("authA attempts = %d in %v, want exactly 1 (no re-buffered loop)", authACount, gotAttempts)
	}
	if len(gotAttempts) < 2 || gotAttempts[0] != authA {
		t.Fatalf("attempts = %v, want authA then gated failover", gotAttempts)
	}
}

func TestExecuteStreamBufferedRecoveryCancelsAndReleases(t *testing.T) {
	const (
		model = "stream-cancel-recovery-model"
		authA = "stream-cancel-recovery-a"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: authA, Provider: "codex", Status: StatusActive}); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(authA, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authA) })

	started := make(chan struct{})
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"hold-me\"}\n\n")}
			close(started)
			go func() {
				<-ctx.Done()
				close(chunks)
			}()
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	stream, errExecute := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	<-started
	cancel()
	var sawPayload bool
	for chunk := range stream.Chunks {
		if len(chunk.Payload) > 0 {
			sawPayload = true
		}
	}
	if sawPayload {
		t.Fatalf("canceled buffered stream released payload to client")
	}
}

func TestExecuteStreamDisableStreamReplaySkipsRecovery(t *testing.T) {
	const (
		model = "stream-disable-replay-model"
		authA = "stream-disable-replay-a"
		authB = "stream-disable-replay-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	for _, id := range []string{authA, authB} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	var mu sync.Mutex
	var attempts []string
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 2)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"tool-side-effect\"}\n\n")}
			chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "server_is_overloaded", Retryable: true}}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{
		Stream:   true,
		Metadata: map[string]any{"disable_stream_replay": true},
	})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var streamErr error
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
	}
	if streamErr == nil {
		t.Fatal("expected terminal overload when stream replay is disabled")
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 1 || gotAttempts[0] != authA {
		t.Fatalf("attempts = %v, want only %s", gotAttempts, authA)
	}
}

func TestExecuteStreamAllExcludedReturnsCredentialSelectionFailure(t *testing.T) {
	const (
		model = "all-excluded-model"
		authA = "all-excluded-a"
		authB = "all-excluded-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetUpstreamErrorRetryLimit(-1)
	for _, id := range []string{authA, authB} {
		_, _ = manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive})
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			t.Fatal("stream should not start when all auths are excluded")
			return nil, nil
		},
	})
	ctx := withStreamReplayDisabled(withStreamReplayExcludedAuthIDs(context.Background(), []string{authA, authB}))
	_, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err == nil {
		t.Fatal("expected error")
	}
	if !isCredentialSelectionFailure(err) {
		t.Fatalf("err=%v credSelection=%v", err, isCredentialSelectionFailure(err))
	}
	var authErr *Error
	if errors.As(err, &authErr) {
		t.Logf("code=%q", authErr.Code)
	}
}
