package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: clear-credential-gate <config> <auth-dir> <state-dir> <resource-id>")
		os.Exit(2)
	}
	configPath, authDir, stateDir, resourceID := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	c, err := resourcecatalog.Open(configPath, authDir, stateDir)
	if err != nil {
		fatal(err)
	}
	state, err := c.GateState()
	if err != nil {
		fatal(err)
	}
	var gate resource.Gate
	found := false
	for _, g := range state.Gates {
		if len(g.Targets) > 0 && g.Targets[0].ResourceID == resourceID {
			gate = g
			found = true
			break
		}
	}
	if !found {
		fmt.Println("no_matching_gate")
		return
	}
	snap, err := c.Snapshot()
	if err != nil {
		fatal(err)
	}
	var binding resource.Binding
	for _, r := range snap.Resources {
		if r.Target.ResourceID == resourceID && r.Kind == "credential" {
			binding = resource.Binding{Scope: snap.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
			break
		}
	}
	if len(binding.Targets) == 0 {
		fatal(fmt.Errorf("current binding missing for %s", resourceID))
	}
	op := resource.GateOperation{
		Version:          1,
		OpID:             uuid.NewString(),
		ExpectedRevision: state.Revision,
		Binding:          binding,
		AuthIndex:        "ops-clear",
		SourceVersion:    gate.SourceVersion,
		Subject:          "credential",
		Owner:            gate.Owner,
		Action:           "clear",
		Reason:           gate.Reason,
		EvidenceID:       "ops-clear:" + uuid.NewString(),
	}
	result, err := c.ApplyGate(op)
	if err != nil {
		fatal(err)
	}
	raw, _ := json.Marshal(result)
	fmt.Printf("cleared %s\n", raw)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
