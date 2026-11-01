package api

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestInferenceGateOtherOwnerManualHealthAndReloadRemainIndependent(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	source := gateSource(t, f)
	var id string
	for _, a := range f.manager.List() {
		if a.Index == source["auth_index"] {
			id = a.ID
		}
	}
	a, _ := f.manager.GetByID(id)
	a.Disabled = true
	a.Unavailable = true
	a.Quota.Exceeded = true
	a.ModelStates = map[string]*coreauth.ModelState{"synthetic-model": {Unavailable: true, Quota: coreauth.QuotaState{Exceeded: true}}}
	if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	before, _ := f.manager.GetByID(id)
	gatePost(t, f, gateOp(source, 0, "d0429edb-8e17-43de-aa68-575a69e840e9", "owner-a", "pause"), 200)
	gatePost(t, f, gateOp(source, 1, "792d20c6-2258-4dba-97cf-dff619dfd53a", "owner-b", "pause"), 200)
	gatePost(t, f, gateOp(source, 2, "440dcfab-d337-4980-8bf0-09e14154f095", "owner-a", "clear"), 200)
	after, _ := f.manager.GetByID(id)
	if before.Disabled != after.Disabled || before.Unavailable != after.Unavailable || !reflect.DeepEqual(before.Quota, after.Quota) || !reflect.DeepEqual(before.ModelStates, after.ModelStates) {
		t.Fatal("owner clear changed manual/health/quota state")
	}
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 1 || state.Gates[0].Owner != "owner-b" {
		t.Fatal("clearing one owner cleared another")
	}
	f.handler.SetConfig(f.server.cfg.CloneForRuntime())
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.ResetQuota(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	f.manager.MarkResult(context.Background(), coreauth.Result{AuthID: id, Provider: "codex", Model: "synthetic-model", Success: true, CompletedResponse: true})
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 1 || state.Gates[0].Owner != "owner-b" || state.Revision != 3 {
		t.Fatal("reload/reset/success implicitly cleared independent owner")
	}
}
