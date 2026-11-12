package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestStreamReplayStateAdvanceOnAuthExhaustion(t *testing.T) {
	t.Parallel()
	var state streamReplayState

	if !state.advanceOnAuthExhaustion() {
		t.Fatal("buffered_same should advance")
	}
	if state.recoveryMode() != streamRecoveryUnbufferedSame {
		t.Fatalf("mode = %v, want unbuffered_same", state.recoveryMode())
	}
	if state.excludedAuthIDs() != nil {
		t.Fatalf("excluded after unbuffered_same advance = %v, want cleared", state.excludedAuthIDs())
	}

	state.noteExcluded("auth-a")
	state.noteExcluded("auth-b")
	if !state.advanceOnAuthExhaustion() {
		t.Fatal("unbuffered_same should advance")
	}
	if state.recoveryMode() != streamRecoveryBufferedCross {
		t.Fatalf("mode = %v, want buffered_cross", state.recoveryMode())
	}
	if got := state.excludedAuthIDs(); len(got) != 2 {
		t.Fatalf("excluded after cross advance = %v, want preserved", got)
	}

	if !state.advanceOnAuthExhaustion() {
		t.Fatal("buffered_cross should advance")
	}
	if state.recoveryMode() != streamRecoveryUnbufferedCross {
		t.Fatalf("mode = %v, want unbuffered_cross", state.recoveryMode())
	}
	if state.advanceOnAuthExhaustion() {
		t.Fatal("unbuffered_cross must not advance further")
	}
}

func TestStreamReplayStateFilterProvidersSameMode(t *testing.T) {
	t.Parallel()
	var state streamReplayState
	state.noteProvider("codex")
	got := state.filterProviders([]string{"codex", "openai", "Codex"})
	if len(got) != 2 || got[0] != "codex" || got[1] != "Codex" {
		t.Fatalf("filtered = %v", got)
	}
	state.setRecoveryMode(streamRecoveryBufferedCross)
	got = state.filterProviders([]string{"codex", "openai"})
	if len(got) != 2 {
		t.Fatalf("cross mode filtered = %v, want both providers", got)
	}
}

func TestStreamReplayStateExhaustionProvidersCrossMode(t *testing.T) {
	t.Parallel()
	var state streamReplayState
	state.noteProvider("codex")
	state.setRecoveryMode(streamRecoveryBufferedCross)
	got := state.exhaustionProviders([]string{"codex", "openai", "gemini"})
	if len(got) != 2 || got[0] != "openai" || got[1] != "gemini" {
		t.Fatalf("cross exhaustion providers = %v, want non-preferred only", got)
	}
	state.setRecoveryMode(streamRecoveryBufferedSame)
	got = state.exhaustionProviders([]string{"codex", "openai"})
	if len(got) != 1 || got[0] != "codex" {
		t.Fatalf("same-stage exhaustion providers = %v, want preferred only", got)
	}
}

func TestStreamReplayStageExhaustedLadderFixture(t *testing.T) {
	const (
		model = "stream-ladder-unbuffered-model"
		authA = "stream-ladder-unbuffered-a"
		authB = "stream-ladder-unbuffered-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	for _, id := range []string{authA, authB} {
		_, _ = manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive})
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	var state streamReplayState
	state.noteExcluded(authA)
	state.noteExcluded(authB)
	if !manager.streamReplayStageExhausted([]string{"codex"}, model, state.excludedAuthIDs()) {
		t.Fatalf("expected exhausted for ladder fixture, excluded=%v", state.excludedAuthIDs())
	}
}

func TestStreamReplayStageExhaustedAfterTwoAuthsNoted(t *testing.T) {
	const (
		model = "stage-exhausted-model"
		authA = "stage-exhausted-a"
		authB = "stage-exhausted-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	for _, id := range []string{authA, authB} {
		_, _ = manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive})
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	var state streamReplayState
	state.setReplayScope([]string{"codex"}, model)
	state.noteExcluded(authA)
	state.noteExcluded(authB)
	if got := state.excludedAuthIDs(); len(got) != 2 {
		t.Fatalf("excluded = %v", got)
	}
	if !manager.streamReplayStageExhausted([]string{"codex"}, model, state.excludedAuthIDs()) {
		t.Fatal("expected exhausted stage")
	}
}

func TestStreamReplayStageExhaustedWithRegisteredAuths(t *testing.T) {
	const (
		model = "stage-exhausted-model"
		authA = "stage-exhausted-a"
		authB = "stage-exhausted-b"
	)
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	for _, id := range []string{authA, authB} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	var state streamReplayState
	state.noteExcluded(authA)
	state.noteExcluded(authB)
	if !manager.streamReplayStageExhausted([]string{"codex"}, model, state.excludedAuthIDs()) {
		t.Fatalf("expected codex stage exhausted with exclusions %v", state.excludedAuthIDs())
	}
}

func TestStreamReplayForbiddenSideEffectMarker(t *testing.T) {
	t.Parallel()
	if !streamReplayForbidden(cliproxyexecutor.Options{Metadata: map[string]any{"stream_replay_side_effects_committed": true}}) {
		t.Fatal("side-effect marker must disable replay")
	}
}
