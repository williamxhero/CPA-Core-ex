package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// A native executor may successfully return an unchanged credential (for
// example, a Claude access-token-only file). That is not a token rotation and
// must not invalidate a concurrent management gate operation on another source.
func TestInferenceGateNoOpNativeRefreshKeepsManagementCASUsable(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("manual_disabled_%t", disabled), func(t *testing.T) {
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			if err := os.MkdirAll(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte(fmt.Sprintf(`{"type":"claude","access_token":"SYNTHETIC-NO-REFRESH-GRANT","disabled":%t}`, disabled))
			if err := os.WriteFile(filepath.Join(authDir, "access-only.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			f := newInventoryHarness(t, dir)
			f.manager.SetConfig(f.server.cfg)
			f.manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(f.server.cfg))
			var id string
			for _, a := range f.manager.List() {
				if a.Provider == "claude" {
					id = a.ID
				}
			}
			if id == "" {
				t.Fatal("missing synthetic native credential")
			}
			before := f.snapshot()
			independent := gateSource(t, f)
			readState := func() resource.GateState {
				t.Helper()
				var state resource.GateState
				if err := json.Unmarshal(f.request("inference-gates", 200), &state); err != nil {
					t.Fatal(err)
				}
				return state
			}
			initial := readState()
			if initial.Revision != 0 || len(initial.Gates) != 0 {
				t.Fatal("fixture did not start with empty gates")
			}
			refresh := func() {
				t.Helper()
				updated, err := f.manager.ForceRefreshAuth(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				if updated == nil || updated.Disabled != disabled {
					t.Fatal("no-op refresh changed manual credential state")
				}
				if after := f.snapshot(); !reflect.DeepEqual(before, after) {
					t.Fatal("no-op refresh changed public source authority")
				}
			}
			refresh()
			if state := readState(); state.Revision != initial.Revision {
				t.Fatalf("no-op native refresh invalidated management CAS: revision %d -> %d", initial.Revision, state.Revision)
			}
			gatePost(t, f, gateOp(independent, 0, "c310c394-aecf-4685-a909-683ad8fe5c4a", "owner-noop-regression", "pause"), 200)
			for range 3 {
				refresh()
			}
			if state := readState(); state.Revision != 1 || len(state.Gates) != 1 || state.Gates[0].Owner != "owner-noop-regression" {
				t.Fatal("no-op refresh republished or removed an independent owner gate")
			}
			gatePost(t, f, gateOp(independent, 1, "efc6be06-eb62-46a9-9e1e-fe6b0f8e3f01", "owner-noop-regression", "clear"), 200)
		})
	}
}
