package resourcecatalog_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

type providerGateBinder interface {
	ProviderGateBinding(resource.Binding) (resource.Binding, error)
}

func providerBinder(t *testing.T, c *resourcecatalog.Catalog) providerGateBinder {
	t.Helper()
	binder, ok := any(c).(providerGateBinder)
	if !ok {
		t.Fatal("Catalog does not validate issued provider gate bindings")
	}
	return binder
}

func providerFixture(t *testing.T, keys int) (*resourcecatalog.Catalog, string, string) {
	t.Helper()
	return providerFixtureFamily(t, keys, "codex")
}

func providerFixtureFamily(t *testing.T, keys int, family string) (*resourcecatalog.Catalog, string, string) {
	t.Helper()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	var members []string
	for i := 0; i < keys; i++ {
		members = append(members, fmt.Sprintf("{api-key: synthetic-A-%d}", i))
	}
	text := fmt.Sprintf("oauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  %s:\n    - {name: A, base-url: https://synthetic-a.invalid, keys: [%s]}\n    - {name: B, base-url: https://synthetic-b.invalid, keys: [{api-key: synthetic-B}]}\n", filepath.ToSlash(authDir), family, strings.Join(members, ", "))
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := resourcecatalog.Open(path, authDir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, path, authDir
}

func providerGroups(t *testing.T, c *resourcecatalog.Catalog) []resource.Binding {
	t.Helper()
	snapshot, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var groups []resource.Binding
	for _, parent := range snapshot.Resources {
		if parent.Kind != "provider" {
			continue
		}
		b := resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{parent.Target}}
		var members []resource.Target
		for _, child := range snapshot.Resources {
			if child.ParentID == parent.ResourceID {
				members = append(members, child.Target)
			}
		}
		sort.Slice(members, func(i, j int) bool { return members[i].ResourceID < members[j].ResourceID })
		b.Targets = append(b.Targets, members...)
		groups = append(groups, b)
	}
	return groups
}

func TestProviderGateBindingCompleteOrder(t *testing.T) {
	c, _, _ := providerFixture(t, 2)
	want := providerGroups(t, c)[0]
	input := resource.Binding{Scope: want.Scope, Targets: []resource.Target{want.Targets[2], want.Targets[0], want.Targets[1]}}
	before := append([]resource.Target(nil), input.Targets...)
	got, err := providerBinder(t, c).ProviderGateBinding(input)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete order permutation: got %+v, error %v, want %+v", got, err, want)
	}
	if !reflect.DeepEqual(input.Targets, before) {
		t.Fatal("canonicalization mutated caller authority")
	}
	got.Targets[0] = resource.Target{}
	if _, err := providerBinder(t, c).ProviderGateBinding(want); err != nil {
		t.Fatal("returned binding aliased catalog authority", err)
	}
}

func TestProviderGateOperationValidation(t *testing.T) {
	op := resource.GateOperation{Version: 1, OpID: "6ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d", Subject: "provider", Binding: resource.Binding{Targets: make([]resource.Target, 2)}, SourceVersion: strings.Repeat("a", 64), Owner: "owner-a", Action: "pause", Reason: "low_balance", EvidenceID: "evidence"}
	if !resourcecatalog.ValidGateOperation(op) {
		t.Fatal("well-bounded provider operation with empty auth_index rejected")
	}
	op.AuthIndex = "synthetic"
	if resourcecatalog.ValidGateOperation(op) {
		t.Fatal("provider operation accepted credential auth_index")
	}
	op.Subject = "credential"
	if !resourcecatalog.ValidGateOperation(op) {
		t.Fatal("legacy credential operation rejected")
	}
	op.AuthIndex = ""
	if resourcecatalog.ValidGateOperation(op) {
		t.Fatal("credential operation accepted empty auth_index")
	}
	op.Subject = "provider"
	for name, mutate := range map[string]func(*resource.GateOperation){
		"version":        func(o *resource.GateOperation) { o.Version = 2 },
		"op_id":          func(o *resource.GateOperation) { o.OpID = "unissued" },
		"subject":        func(o *resource.GateOperation) { o.Subject = "unknown" },
		"action":         func(o *resource.GateOperation) { o.Action = "resume" },
		"owner":          func(o *resource.GateOperation) { o.Owner = "" },
		"reason":         func(o *resource.GateOperation) { o.Reason = "bad reason" },
		"evidence":       func(o *resource.GateOperation) { o.EvidenceID = "" },
		"source_version": func(o *resource.GateOperation) { o.SourceVersion = "invalid" },
		"model":          func(o *resource.GateOperation) { o.Model = strings.Repeat("a", 257) },
		"auth_index":     func(o *resource.GateOperation) { o.AuthIndex = "not-empty" },
		"no_targets":     func(o *resource.GateOperation) { o.Targets = nil },
		"over64":         func(o *resource.GateOperation) { o.Targets = make([]resource.Target, 65) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := op
			mutate(&invalid)
			if resourcecatalog.ValidGateOperation(invalid) {
				t.Fatal("provider subject bypassed normal operation bounds")
			}
		})
	}
}

func providerOperation(b resource.Binding, owner string, revision uint64) resource.GateOperation {
	return resource.GateOperation{Version: 1, OpID: "6ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d", Subject: "provider", Binding: b, SourceVersion: strings.Repeat("a", 64), Owner: owner, ExpectedRevision: revision, Action: "pause", Reason: "low_balance", EvidenceID: "evidence"}
}

func credentialBinding(b resource.Binding, index int) resource.Binding {
	return resource.Binding{Scope: b.Scope, Targets: []resource.Target{b.Targets[index]}}
}

func TestProviderGateAdmissionIsolation(t *testing.T) {
	c, _, _ := providerFixture(t, 2)
	groups := providerGroups(t, c)
	a, b := groups[0], groups[1]
	op := providerOperation(resource.Binding{Scope: a.Scope, Targets: []resource.Target{a.Targets[2], a.Targets[0], a.Targets[1]}}, "provider-owner", 0)
	result, err := c.ApplyGate(op)
	if err != nil || !result.Durable || !result.Applied || result.Revision != 1 || result.DurableRevision != 1 || result.AppliedRevision != 1 {
		t.Fatalf("provider pause was not durably published: %+v %v", result, err)
	}
	for i := 1; i < len(a.Targets); i++ {
		member := credentialBinding(a, i)
		if err := c.AdmitInference(&member, "model"); !errors.Is(err, resourcecatalog.ErrGateDenied) {
			t.Fatalf("A member %d escaped provider pause: %v", i, err)
		}
		if err := c.GateBindingReady(&member); err != nil {
			t.Fatal("current paused member lost readiness", err)
		}
		if len(member.Targets) != 1 {
			t.Fatal("admission appended a provider parent to credential binding")
		}
	}
	unrelated := credentialBinding(b, 1)
	if err := c.AdmitInference(&unrelated, "model"); err != nil {
		t.Fatal("B was affected by A pause", err)
	}
	state, err := c.GateState()
	if err != nil || !state.AllSourcesReady || len(state.Gates) != 1 || !reflect.DeepEqual(state.Gates[0].Targets, a.Targets) {
		t.Fatalf("provider gate was not stored in canonical order: %+v %v", state, err)
	}
	replay, err := c.ApplyGate(op)
	if err != nil || replay != result {
		t.Fatal("exact opID replay changed its receipt", err)
	}
	op.Targets = a.Targets
	if _, err := c.ApplyGate(op); !errors.Is(err, resourcecatalog.ErrOperationConflict) {
		t.Fatal("opID replay accepted a different operation body", err)
	}
}

func TestProviderGateBindingRejectsIncomplete(t *testing.T) {
	c, _, _ := providerFixture(t, 2)
	groups := providerGroups(t, c)
	a, b := groups[0], groups[1]
	cases := map[string][]resource.Target{
		"empty":          nil,
		"parent_only":    a.Targets[:1],
		"members_only":   a.Targets[1:],
		"subset":         a.Targets[:2],
		"duplicate":      {a.Targets[0], a.Targets[1], a.Targets[1]},
		"foreign_member": {a.Targets[0], a.Targets[1], b.Targets[1]},
		"extra_member":   {a.Targets[0], a.Targets[1], a.Targets[2], b.Targets[1]},
		"two_parents":    {a.Targets[0], a.Targets[1], b.Targets[0]},
		"foreign_parent": {b.Targets[0], a.Targets[1], a.Targets[2]},
	}
	for _, field := range []string{"ResourceID", "Incarnation", "IdentityVersion", "CredentialVersion", "ConfigVersion", "MembershipVersion"} {
		for _, index := range []int{0, 1} {
			targets := append([]resource.Target(nil), a.Targets...)
			value := reflect.ValueOf(&targets[index]).Elem().FieldByName(field)
			if value.Kind() == reflect.String {
				value.SetString("forged")
			} else {
				value.SetUint(value.Uint() + 1)
			}
			cases[fmt.Sprintf("forged_%s_%d", field, index)] = targets
		}
	}
	for name, targets := range cases {
		t.Run(name, func(t *testing.T) {
			input := resource.Binding{Scope: a.Scope, Targets: targets}
			if _, err := providerBinder(t, c).ProviderGateBinding(input); !errors.Is(err, resourcecatalog.ErrConflict) {
				t.Fatal("incomplete or forged provider authority accepted", err)
			}
			if result, err := c.ApplyGate(providerOperation(input, "provider-owner", 0)); !errors.Is(err, resourcecatalog.ErrConflict) || result.Applied {
				t.Fatal("invalid group produced gate ACK", result, err)
			}
		})
	}
	for _, field := range []string{"InstanceID", "InstanceIncarnation", "BootEpoch", "Revision"} {
		t.Run("scope_"+field, func(t *testing.T) {
			input := a
			value := reflect.ValueOf(&input.Scope).Elem().FieldByName(field)
			if value.Kind() == reflect.String {
				value.SetString("foreign")
			} else {
				value.SetUint(value.Uint() + 1)
			}
			if _, err := providerBinder(t, c).ProviderGateBinding(input); !errors.Is(err, resourcecatalog.ErrConflict) {
				t.Fatal("foreign issued scope accepted", err)
			}
		})
	}
}

func TestProviderGateBindingTotalTargetLimit(t *testing.T) {
	for _, members := range []int{0, 63, 64} {
		t.Run(fmt.Sprintf("members_%d", members), func(t *testing.T) {
			c, _, _ := providerFixture(t, members)
			group := providerGroups(t, c)[0]
			_, err := providerBinder(t, c).ProviderGateBinding(group)
			if members == 63 && err != nil {
				t.Fatal("64 total targets rejected", err)
			}
			if members != 63 && !errors.Is(err, resourcecatalog.ErrConflict) {
				t.Fatal("empty or over-64 total group accepted", err)
			}
		})
	}
}

func providerYAMLField(t *testing.T, n *yaml.Node, name string) *yaml.Node {
	t.Helper()
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	t.Fatalf("missing fixture field %s", name)
	return nil
}

func editProviderConfig(t *testing.T, c *resourcecatalog.Catalog, path string, edit func(*yaml.Node)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc.Content[0])
	raw, err = yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := config.NormalizeConfigLayout(raw, true); err != nil {
		t.Fatalf("invalid fixture native layout: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
}

func codexGroups(t *testing.T, root *yaml.Node) *yaml.Node {
	t.Helper()
	return providerYAMLField(t, providerYAMLField(t, root, "api-keys"), "codex")
}

func TestProviderGateBindingUnreadyIdentity(t *testing.T) {
	for _, shape := range []string{"duplicate_child", "duplicate_parent"} {
		t.Run(shape, func(t *testing.T) {
			c, path, _ := providerFixture(t, 2)
			editProviderConfig(t, c, path, func(root *yaml.Node) {
				groups := codexGroups(t, root)
				if shape == "duplicate_parent" {
					providerYAMLField(t, groups.Content[1], "resource-id").Value = providerYAMLField(t, groups.Content[0], "resource-id").Value
					return
				}
				keys := providerYAMLField(t, groups.Content[0], "keys")
				providerYAMLField(t, keys.Content[1], "resource-id").Value = providerYAMLField(t, keys.Content[0], "resource-id").Value
			})
			for _, group := range providerGroups(t, c) {
				if _, err := providerBinder(t, c).ProviderGateBinding(group); !errors.Is(err, resourcecatalog.ErrConflict) && shape == "duplicate_parent" {
					t.Fatal("ambiguous provider identity accepted", err)
				}
			}
			if shape == "duplicate_child" {
				if _, err := providerBinder(t, c).ProviderGateBinding(providerGroups(t, c)[0]); !errors.Is(err, resourcecatalog.ErrConflict) {
					t.Fatal("unready member group accepted", err)
				}
			}
		})
	}
}

func TestProviderGateMembershipReconciliation(t *testing.T) {
	c, path, _ := providerFixture(t, 2)
	before := providerGroups(t, c)[0]
	op := providerOperation(before, "provider-owner", 0)
	if _, err := c.ApplyGate(op); err != nil {
		t.Fatal(err)
	}
	editProviderConfig(t, c, path, func(root *yaml.Node) {
		keys := providerYAMLField(t, codexGroups(t, root).Content[0], "keys")
		var added yaml.Node
		if err := yaml.Unmarshal([]byte("{api-key: synthetic-A-new}"), &added); err != nil {
			t.Fatal(err)
		}
		keys.Content = append(keys.Content, added.Content[0])
	})
	current := providerGroups(t, c)
	if len(current[0].Targets) != 4 {
		t.Fatal("fixture failed to add current provider member")
	}
	for i := 1; i < len(current[0].Targets); i++ {
		member := credentialBinding(current[0], i)
		if err := c.AdmitInference(&member, ""); !errors.Is(err, resourcecatalog.ErrUnavailable) {
			t.Fatalf("current member %d bypassed stale group restriction: %v", i, err)
		}
		if err := c.GateBindingReady(&member); !errors.Is(err, resourcecatalog.ErrUnavailable) {
			t.Fatal("stale provider membership reported ready", err)
		}
	}
	stale := credentialBinding(before, 1)
	if err := c.AdmitInference(&stale, ""); err == nil {
		t.Fatal("old scope credential was admitted")
	}
	b := credentialBinding(current[1], 1)
	if err := c.AdmitInference(&b, ""); err != nil {
		t.Fatal("B affected by stale A group", err)
	}
	state, err := c.GateState()
	if err != nil || state.AllSourcesReady || state.Gates[0].Applicability != "reconciliation_required" {
		t.Fatal("stale lifecycle hidden by gate state", state, err)
	}
	op = providerOperation(current[0], "provider-owner", 1)
	op.OpID = "7ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d"
	op.Action = "clear"
	if _, err := c.ApplyGate(op); err != nil {
		t.Fatal("current owner could not reconcile stale own membership", err)
	}
	state, err = c.GateState()
	if err != nil || !state.AllSourcesReady || len(state.Gates) != 0 || state.Revision != 2 {
		t.Fatal("stale own group row survived authorized clear", state, err)
	}
	for i := 1; i < len(current[0].Targets); i++ {
		member := credentialBinding(current[0], i)
		if err := c.AdmitInference(&member, ""); err != nil {
			t.Fatal("current owner clear failed to restore admission", err)
		}
	}
}

func TestProviderGateOwnerModelCredentialComposition(t *testing.T) {
	c, path, _ := providerFixtureFamily(t, 2, "openai-compatibility")
	editProviderConfig(t, c, path, func(root *yaml.Node) {
		group := providerYAMLField(t, providerYAMLField(t, root, "api-keys"), "openai-compatibility").Content[0]
		for i := 0; i+1 < len(group.Content); i += 2 {
			if group.Content[i].Value == "disabled" {
				group.Content[i+1].Value = "true"
				group.Content[i+1].Tag = "!!bool"
				return
			}
		}
		group.Content = append(group.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "disabled"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	})
	groups := providerGroups(t, c)
	a, b := groups[0], groups[1]
	apply := func(op resource.GateOperation) {
		t.Helper()
		op.OpID = uuid.NewString()
		if result, err := c.ApplyGate(op); err != nil || !result.Applied {
			t.Fatal("composition operation failed", result, err)
		}
	}
	apply(providerOperation(a, "shared-owner", 0))
	apply(providerOperation(a, "other-owner", 1))
	credential := providerOperation(credentialBinding(a, 1), "shared-owner", 2)
	credential.Subject, credential.AuthIndex = "credential", "synthetic"
	apply(credential)
	model := providerOperation(a, "shared-owner", 3)
	model.Model = "special"
	apply(model)
	apply(providerOperation(b, "shared-owner", 4))
	clear := providerOperation(a, "shared-owner", 4)
	clear.OpID, clear.Action = uuid.NewString(), "clear"
	if _, err := c.ApplyGate(clear); !errors.Is(err, resourcecatalog.ErrGateRevisionConflict) {
		t.Fatal("stale CAS cleared provider restrictions", err)
	}
	clear.ExpectedRevision = 5
	apply(clear)
	state, err := c.GateState()
	if err != nil || len(state.Gates) != 4 || state.Revision != 6 {
		t.Fatal("own clear erased another subject, model, owner, or provider", state, err)
	}
	clear.Owner, clear.ExpectedRevision = "other-owner", 6
	apply(clear)
	first, second := credentialBinding(a, 1), credentialBinding(a, 2)
	if err := c.AdmitInference(&first, "ordinary"); !errors.Is(err, resourcecatalog.ErrGateDenied) {
		t.Fatal("provider clear erased credential restriction", err)
	}
	if err := c.AdmitInference(&second, "ordinary"); err != nil {
		t.Fatal("cleared provider still denies unrestricted model", err)
	}
	if err := c.AdmitInference(&second, "special"); !errors.Is(err, resourcecatalog.ErrGateDenied) {
		t.Fatal("all-model clear erased model-specific provider restriction", err)
	}
	other := credentialBinding(b, 1)
	if err := c.AdmitInference(&other, "ordinary"); !errors.Is(err, resourcecatalog.ErrGateDenied) {
		t.Fatal("A clear erased same-owner B restriction", err)
	}
	credential.Action, credential.ExpectedRevision = "clear", 7
	apply(credential)
	if err := c.AdmitInference(&first, "ordinary"); err != nil {
		t.Fatal("explicit credential clear did not clear own credential gate", err)
	}
	if err := c.AdmitInference(&first, "special"); !errors.Is(err, resourcecatalog.ErrGateDenied) {
		t.Fatal("credential clear erased provider gate", err)
	}
	snapshot, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range snapshot.Resources {
		if row.ResourceID == a.Targets[0].ResourceID && !row.Manual.Disabled {
			t.Fatal("automatic gate clear modified manual disabled state")
		}
	}
}

func TestProviderGateLegacySerializationAndRestart(t *testing.T) {
	raw, err := json.Marshal(resource.Gate{})
	if err != nil || string(raw) != `{"targets":null,"owner":"","model":"","reason":"","evidenceId":"","sourceVersion":"","gateRevision":0}` {
		t.Fatal("optional subject changed legacy sealed row bytes", string(raw), err)
	}
	c, path, authDir := providerFixture(t, 2)
	group := providerGroups(t, c)[0]
	legacy := providerOperation(credentialBinding(group, 1), "legacy", 0)
	legacy.Subject, legacy.AuthIndex = "credential", "synthetic"
	if _, err := c.ApplyGate(legacy); err != nil {
		t.Fatal(err)
	}
	op := providerOperation(group, "provider-owner", 1)
	op.OpID = uuid.NewString()
	result, err := c.ApplyGate(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := resourcecatalog.Open(path, authDir, "")
	if err != nil {
		t.Fatal("restart rejected legacy/provider mixed sealed ledger", err)
	}
	defer func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	}()
	state, err := next.GateState()
	if err != nil || !state.AllSourcesReady || len(state.Gates) != 2 || state.Gates[0].Subject != "" || state.Gates[1].Subject != "provider" {
		t.Fatal("restart lost subject discrimination", state, err)
	}
	stored, receipt, err := next.GateOperation(op.OpID)
	if err != nil || !reflect.DeepEqual(stored, op) || receipt != result {
		t.Fatal("restart changed exact opID receipt", stored, receipt, err)
	}
	replay, err := next.ApplyGate(op)
	if err != nil || replay != result {
		t.Fatal("restart rejected exact receipt replay", replay, err)
	}
	current := providerGroups(t, next)[0]
	for i := 1; i < len(current.Targets); i++ {
		member := credentialBinding(current, i)
		if err := next.AdmitInference(&member, ""); !errors.Is(err, resourcecatalog.ErrGateDenied) {
			t.Fatal("restarted provider restriction did not apply", err)
		}
	}
	if _, err := providerBinder(t, next).ProviderGateBinding(group); !errors.Is(err, resourcecatalog.ErrConflict) {
		t.Fatal("old boot group retained new-operation authority", err)
	}
}

func TestProviderGateVerifiedProjectionAdmission(t *testing.T) {
	c, path, authDir := providerFixture(t, 1)
	editProviderConfig(t, c, path, func(root *yaml.Node) {
		var plugin yaml.Node
		text := "enabled: true\nconfigs:\n  cpa-credential-qwen:\n    enabled: true\n    base-url: https://synthetic-qwen.invalid/v1\n    api-keys: [{value: synthetic-projection}]\n"
		if err := yaml.Unmarshal([]byte(text), &plugin); err != nil {
			t.Fatal(err)
		}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "plugins"}, plugin.Content[0])
	})
	authPath := filepath.Join(authDir, "projection.json")
	if err := os.WriteFile(authPath, []byte(`{"type":"qwen","api_key":"synthetic-projection","base_url":"https://synthetic-qwen.invalid/v1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	auth := &coreauth.Auth{Provider: "qwen", SourcePluginID: "cpa-credential-qwen", Attributes: map[string]string{"api_key": "synthetic-projection", "base_url": "https://synthetic-qwen.invalid/v1"}}
	if err := c.BindAuths(authPath, raw, []*coreauth.Auth{auth}); err != nil {
		t.Fatal(err)
	}
	if auth.ResourceIdentity == nil || len(auth.ResourceIdentity.Targets) != 2 {
		t.Fatal("fixture lacks the proven credential/projection runtime binding")
	}
	before := append([]resource.Target(nil), auth.ResourceIdentity.Targets...)
	groups := providerGroups(t, c)
	op := providerOperation(groups[2], "projection-owner", 0)
	if _, err := providerBinder(t, c).ProviderGateBinding(op.Binding); err != nil {
		t.Fatal("verified symmetric projection group rejected", err)
	}
	if _, err := c.ApplyGate(op); err != nil {
		t.Fatal(err)
	}
	if err := c.AdmitInference(auth.ResourceIdentity, ""); !errors.Is(err, resourcecatalog.ErrGateDenied) {
		t.Fatal("materialized credential escaped its projected provider", err)
	}
	if err := c.GateBindingReady(auth.ResourceIdentity); err != nil {
		t.Fatal("current verified projection incorrectly unready", err)
	}
	if !reflect.DeepEqual(before, auth.ResourceIdentity.Targets) {
		t.Fatal("provider enforcement altered runtime credential/projection targets")
	}
	editProviderConfig(t, c, path, func(root *yaml.Node) {
		plugin := providerYAMLField(t, providerYAMLField(t, providerYAMLField(t, root, "plugins"), "configs"), "cpa-credential-qwen")
		providerYAMLField(t, plugin, "api-keys").Content = nil
	})
	if err := c.BindAuths(authPath, raw, []*coreauth.Auth{auth}); err != nil {
		t.Fatal(err)
	}
	if auth.ResourceIdentity == nil || len(auth.ResourceIdentity.Targets) != 1 {
		t.Fatal("fixture did not detach its old projection")
	}
	if err := c.AdmitInference(auth.ResourceIdentity, ""); !errors.Is(err, resourcecatalog.ErrUnavailable) {
		t.Fatal("detached formerly projected credential bypassed stale provider gate", err)
	}
	if err := c.GateBindingReady(auth.ResourceIdentity); !errors.Is(err, resourcecatalog.ErrUnavailable) {
		t.Fatal("detached formerly projected credential reported ready", err)
	}
	unrelated := credentialBinding(providerGroups(t, c)[1], 1)
	if err := c.AdmitInference(&unrelated, ""); err != nil {
		t.Fatal("detached projection staleness affected B", err)
	}
}

func TestProviderGateCurrentOwnerReplacesStaleOwnGroup(t *testing.T) {
	for _, change := range []string{"key_rotation", "config_edit", "member_removed", "members_reordered"} {
		t.Run(change, func(t *testing.T) {
			c, path, _ := providerFixture(t, 2)
			group := providerGroups(t, c)[0]
			if _, err := c.ApplyGate(providerOperation(group, "own", 0)); err != nil {
				t.Fatal(err)
			}
			other := providerOperation(group, "other", 1)
			other.OpID = uuid.NewString()
			if _, err := c.ApplyGate(other); err != nil {
				t.Fatal(err)
			}
			editProviderConfig(t, c, path, func(root *yaml.Node) {
				parent := codexGroups(t, root).Content[0]
				keys := providerYAMLField(t, parent, "keys")
				switch change {
				case "key_rotation":
					providerYAMLField(t, keys.Content[0], "api-key").Value = "synthetic-rotated"
				case "config_edit":
					providerYAMLField(t, parent, "name").Value = "renamed"
				case "member_removed":
					keys.Content = keys.Content[1:]
				case "members_reordered":
					keys.Content[0], keys.Content[1] = keys.Content[1], keys.Content[0]
				}
			})
			current := providerGroups(t, c)
			replacement := providerOperation(current[0], "own", 2)
			replacement.OpID = uuid.NewString()
			if _, err := c.ApplyGate(replacement); err != nil {
				t.Fatal("current owner could not reconcile own restriction", err)
			}
			state, err := c.GateState()
			if err != nil || len(state.Gates) != 2 || state.Gates[1].Owner != "own" || !reflect.DeepEqual(state.Gates[1].Targets, current[0].Targets) || state.Gates[1].Applicability != "current" {
				t.Fatal("replacement retained stale own row or dropped other owner", state, err)
			}
			if change != "members_reordered" && state.Gates[0].Applicability != "reconciliation_required" {
				t.Fatal("other owner's stale lifecycle silently rewritten")
			}
			b := credentialBinding(current[1], 1)
			if err := c.AdmitInference(&b, ""); err != nil {
				t.Fatal("stale A ownership affected B", err)
			}
			clear := providerOperation(current[0], "own", 3)
			clear.OpID, clear.Action = uuid.NewString(), "clear"
			if _, err := c.ApplyGate(clear); err != nil {
				t.Fatal(err)
			}
			state, err = c.GateState()
			if err != nil || len(state.Gates) != 1 || state.Gates[0].Owner != "other" {
				t.Fatal("own clear removed unrelated ownership", state, err)
			}
			clear.OpID, clear.Owner, clear.ExpectedRevision = uuid.NewString(), "other", 4
			if _, err := c.ApplyGate(clear); err != nil {
				t.Fatal("stale other row permanently blocked its current-owner clear", err)
			}
			member := credentialBinding(current[0], 1)
			if err := c.AdmitInference(&member, ""); err != nil {
				t.Fatal("reconciled current member still unavailable", err)
			}
		})
	}
}

func TestProviderGateConcurrentCAS(t *testing.T) {
	c, _, _ := providerFixture(t, 2)
	group := providerGroups(t, c)[0]
	type outcome struct {
		result resource.GateResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, owner := range []string{"one", "two"} {
		op := providerOperation(group, owner, 0)
		op.OpID = uuid.NewString()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := c.ApplyGate(op)
			results <- outcome{result, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	acks, conflicts := 0, 0
	for result := range results {
		switch {
		case result.err == nil && result.result.Applied && result.result.Revision == 1:
			acks++
		case errors.Is(result.err, resourcecatalog.ErrGateRevisionConflict):
			conflicts++
		default:
			t.Fatal("unexpected concurrent CAS result", result)
		}
	}
	if acks != 1 || conflicts != 1 {
		t.Fatal("concurrent CAS did not serialize exactly one publication", acks, conflicts)
	}
}

func TestProviderGateBindingRejectsStaleSeals(t *testing.T) {
	for _, target := range []string{"source", "gate_floor", "catalog"} {
		t.Run(target, func(t *testing.T) {
			c, path, _ := providerFixture(t, 1)
			group := providerGroups(t, c)[0]
			name := path
			switch target {
			case "gate_floor":
				name = filepath.Join(filepath.Dir(path), ".resource-catalog", "gate-floor-v1")
			case "catalog":
				name = filepath.Join(filepath.Dir(path), ".resource-catalog", "catalog.json")
			}
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(raw, byte('\n')), 0600); err != nil {
				t.Fatal(err)
			}
			if target == "catalog" {
				if err := os.WriteFile(name, []byte(`{"forged":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := providerBinder(t, c).ProviderGateBinding(group); !errors.Is(err, resourcecatalog.ErrUnavailable) {
				t.Fatal("binding validation ignored changed storage/source/gate seal", err)
			}
		})
	}
}

func TestProviderGatePreservesConfiguredRuntimeBindings(t *testing.T) {
	c, path, _ := providerFixture(t, 2)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	auths, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{Config: cfg, IDGenerator: synthesizer.NewStableIDGenerator()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BindConfiguredAuths(auths); err != nil {
		t.Fatal(err)
	}
	if len(auths) != 3 {
		t.Fatalf("expected exactly three real synthesized credentials, got %d", len(auths))
	}
	group := providerGroups(t, c)[0]
	if _, err := c.ApplyGate(providerOperation(group, "provider-owner", 0)); err != nil {
		t.Fatal(err)
	}
	denied, allowed := 0, 0
	for _, a := range auths {
		if a.ResourceIdentity == nil || len(a.ResourceIdentity.Targets) != 1 {
			t.Fatal("runtime credential binding no longer has exactly its credential target")
		}
		before := *a.ResourceIdentity
		err := c.AdmitInference(a.ResourceIdentity, "")
		if errors.Is(err, resourcecatalog.ErrGateDenied) {
			denied++
		} else if err == nil {
			allowed++
		} else {
			t.Fatal("runtime source unexpectedly unready", err)
		}
		if !reflect.DeepEqual(before, *a.ResourceIdentity) || len(a.ResourceIdentity.Targets) != 1 {
			t.Fatal("provider parent leaked into runtime credential authority")
		}
	}
	if denied != 2 || allowed != 1 {
		t.Fatal("runtime credential routing did not isolate A and B", denied, allowed)
	}
}

func TestProviderGateOverLimitUnrelatedProviderRemainsLegacyRoutable(t *testing.T) {
	c, _, _ := providerFixture(t, 64)
	groups := providerGroups(t, c)
	if _, err := c.ApplyGate(providerOperation(groups[1], "provider-B-owner", 0)); err != nil {
		t.Fatal(err)
	}
	member := credentialBinding(groups[0], 1)
	if err := c.AdmitInference(&member, ""); err != nil {
		t.Fatal("B restriction broke legacy admission of unrelated over-limit A", err)
	}
	if err := c.GateBindingReady(&member); err != nil {
		t.Fatal("unrelated over-limit A lost credential readiness", err)
	}
	if _, err := providerBinder(t, c).ProviderGateBinding(groups[0]); !errors.Is(err, resourcecatalog.ErrConflict) {
		t.Fatal("over-limit A acquired provider gate authority", err)
	}
}
