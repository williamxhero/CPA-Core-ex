package management

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// These are additive management HTTP projections, not plugin SDK requirements.
type runtimeSourceBinding struct {
	resource.Binding
	AuthIndex    string `json:"auth_index"`
	RuntimeAlias string `json:"runtime_alias"`
}
type credentialQueryCapabilityView struct {
	resource.CredentialQueryCapability
	SourceBindings bool `json:"source_bindings"`
}
type resourceCapabilitiesView struct {
	resource.Capabilities
	CredentialQuery *credentialQueryCapabilityView `json:"credential_query,omitempty"`
}
type credentialQuotaSourceBindingsView struct {
	Version  int                    `json:"version"`
	Sources  []resource.QuotaSource `json:"sources"`
	Bindings []runtimeSourceBinding `json:"bindings"`
}

// bindingFromCurrentAuth formats only already-current host-issued evidence. It
// does not acquire authority from plugin claims, locators or credential hashes.
func bindingFromCurrentAuth(a *coreauth.Auth) runtimeSourceBinding {
	return runtimeSourceBinding{Binding: resource.Binding{Scope: a.ResourceIdentity.Scope, Targets: append([]resource.Target(nil), a.ResourceIdentity.Targets...)}, AuthIndex: a.Index, RuntimeAlias: a.ResourceIdentity.Targets[0].ResourceID}
}

// quotaSourceBindingsView reuses the SAME once-validated Auth for its unchanged
// descriptor and binding. Nothing is cached across invocations or re-enrolled.
func (h *Handler) quotaSourceBindingsView(ctx context.Context) (credentialQuotaSourceBindingsView, bool) {
	unavailable := credentialQuotaSourceBindingsView{}
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		return unavailable, false
	}
	snapshot, err := h.resourceCatalog.Snapshot()
	if err != nil {
		return unavailable, false
	}
	view := credentialQuotaSourceBindingsView{Version: 1, Sources: []resource.QuotaSource{}, Bindings: []runtimeSourceBinding{}}
	bound := map[string]bool{}
	for _, a := range h.authManager.List() {
		a = h.currentRuntimeSource(a)
		if a == nil {
			continue
		}
		if a.ResourceIdentity.Scope != snapshot.Version {
			return unavailable, false
		}
		source := h.quotaSource(ctx, a)
		view.Sources = append(view.Sources, source)
		view.Bindings = append(view.Bindings, bindingFromCurrentAuth(a))
		for _, target := range a.ResourceIdentity.Targets {
			bound[target.ResourceID] = true
		}
	}
	for _, r := range snapshot.Resources {
		if (r.Kind == "credential" || r.Kind == "provider" && len(r.Members) == 0) && !bound[r.ResourceID] {
			view.Sources = append(view.Sources, resource.QuotaSource{Binding: resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{r.Target}}, Protocol: "unavailable", State: "unsupported", Reason: "runtime_binding_unavailable", AccountProvenance: "unverified", ManualDisabled: r.Manual.Disabled})
		}
	}
	// A concurrent source publication must not mix descriptors/bindings from
	// different whole scopes or dress stale/unavailable storage as a complete view.
	current, err := h.resourceCatalog.Snapshot()
	if err != nil || current.Version != snapshot.Version {
		return unavailable, false
	}
	return view, true
}
