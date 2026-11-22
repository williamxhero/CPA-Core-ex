package auth

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"testing"
)

func TestManualDisableBlocksRetainedTransportResend(t *testing.T) {
	m := NewManager(nil, nil, nil)
	ctx := context.Background()
	a, err := m.Register(ctx, &Auth{ID: "manual", Provider: "test", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	attempt := m.withInferenceAdmission(ctx, a, "model")
	if err = executor.AdmitInference(attempt); err != nil {
		t.Fatal(err)
	}
	current, _ := m.GetByID(a.ID)
	current.Disabled = true
	if _, err = m.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if !executor.IsInferenceAdmissionError(executor.AdmitInference(attempt)) {
		t.Fatal("retained execution was allowed to send after disable")
	}
}
