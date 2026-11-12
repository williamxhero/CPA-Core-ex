package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

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
			chunks := make(chan cliproxyexecutor.StreamChunk, 2)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"codex-partial\"}\n\n")}
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
			chunks := make(chan cliproxyexecutor.StreamChunk, 2)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"openai-final\"}\n\n")}
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")}
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
	if len(gotAttempts) < 2 || gotAttempts[0] != codexAuth || gotAttempts[len(gotAttempts)-1] != openAuth {
		t.Fatalf("attempts = %v", gotAttempts)
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
