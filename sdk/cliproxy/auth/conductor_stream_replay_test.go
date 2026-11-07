package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestExecuteStreamReplaysPreOutputAdmissionFailureWithoutLeakingIt(t *testing.T) {
	const (
		model = "stream-replay-model"
		authA = "stream-replay-a"
		authB = "stream-replay-b"
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
			if auth.ID == authA {
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.created","response":{"id":"discarded"}}

`)}
				chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "inference admission unavailable or restricted", Retryable: true}}
			} else {
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"recovered"}]}]}}

`)}
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
		t.Fatalf("replayed stream leaked terminal error: %v", streamErr)
	}
	if got := payload.String(); !strings.Contains(got, "recovered") || strings.Contains(got, "discarded") || strings.Contains(got, "inference admission unavailable") {
		t.Fatalf("replayed payload = %q", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 2 || gotAttempts[0] != authA || gotAttempts[1] != authB {
		t.Fatalf("attempts = %v, want [%s %s]", gotAttempts, authA, authB)
	}
}

func TestExecuteStreamAbortsSilentProviderAtBootstrapTimeout(t *testing.T) {
	const (
		model = "stream-bootstrap-timeout-model"
		authA = "stream-bootstrap-timeout-a"
		authB = "stream-bootstrap-timeout-b"
	)

	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.runtimeConfig.Store(&internalconfig.Config{Codex: internalconfig.CodexConfig{StreamBootstrapTimeout: "20ms"}})
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
		streamFn: func(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			if auth.ID == authA {
				go func() {
					<-ctx.Done()
					close(chunks)
				}()
				return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
			}
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"recovered\"}]}]}}\n\n")}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var payload strings.Builder
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("silent provider timeout leaked terminal error: %v", chunk.Err)
		}
		payload.Write(chunk.Payload)
	}
	if got := payload.String(); !strings.Contains(got, "recovered") {
		t.Fatalf("replayed payload = %q, want recovered response", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 2 || gotAttempts[0] != authA || gotAttempts[1] != authB {
		t.Fatalf("attempts = %v, want [%s %s]", gotAttempts, authA, authB)
	}
}

func TestExecuteStreamAbortsPostMetadataProviderAtBootstrapTimeout(t *testing.T) {
	const (
		model = "stream-post-metadata-timeout-model"
		authA = "stream-post-metadata-timeout-a"
		authB = "stream-post-metadata-timeout-b"
	)

	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.runtimeConfig.Store(&internalconfig.Config{Codex: internalconfig.CodexConfig{StreamBootstrapTimeout: "20ms"}})
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
		streamFn: func(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			attempts = append(attempts, auth.ID)
			mu.Unlock()
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			if auth.ID == authA {
				chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"discarded-metadata\"}}\n\n")}
				go func() {
					<-ctx.Done()
					close(chunks)
				}()
				return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
			}
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"recovered\"}]}]}}\n\n")}
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
		if chunk.Err != nil {
			streamErr = chunk.Err
			continue
		}
		payload.Write(chunk.Payload)
	}
	if streamErr != nil {
		mu.Lock()
		gotAttempts := append([]string(nil), attempts...)
		mu.Unlock()
		t.Fatalf("post-metadata timeout leaked terminal error: %v; attempts=%v", streamErr, gotAttempts)
	}
	if got := payload.String(); !strings.Contains(got, "recovered") || strings.Contains(got, "discarded-metadata") {
		t.Fatalf("replayed payload = %q", got)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 2 || gotAttempts[0] != authA || gotAttempts[1] != authB {
		t.Fatalf("attempts = %v, want [%s %s]", gotAttempts, authA, authB)
	}
}

func TestExecuteStreamReplayHonorsFiniteReplayLimit(t *testing.T) {
	const (
		model = "stream-replay-limit-model"
		authA = "stream-replay-limit-a"
		authB = "stream-replay-limit-b"
	)

	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(1)
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
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"discarded\"}}\n\n")}
			chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "inference admission unavailable or restricted", Retryable: true}}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})

	stream, errExecute := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errExecute != nil {
		t.Fatalf("ExecuteStream(): %v", errExecute)
	}
	var streamErr error
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
	}
	if streamErr == nil || !strings.Contains(streamErr.Error(), "inference admission unavailable") {
		t.Fatalf("stream error = %v, want bounded replay failure", streamErr)
	}
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	if len(gotAttempts) != 2 {
		t.Fatalf("attempt count = %d, want one initial attempt plus one replay: %v", len(gotAttempts), gotAttempts)
	}
}
