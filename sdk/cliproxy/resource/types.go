// Package resource defines the secret-free resource catalog v1 read contract.
package resource

// Version binds a complete observation to a persistent instance and a boot.
type Version struct {
	InstanceID          string `json:"instance_id"`
	InstanceIncarnation string `json:"instance_incarnation"`
	BootEpoch           string `json:"boot_epoch"`
	Revision            uint64 `json:"snapshot_revision"`
}

// Target contains lifecycle preconditions, not routing eligibility or an ACK.
type Target struct {
	ResourceID        string `json:"resource_id"`
	Incarnation       string `json:"incarnation"`
	IdentityVersion   uint64 `json:"identity_version"`
	CredentialVersion uint64 `json:"credential_version"`
	ConfigVersion     uint64 `json:"config_version"`
	MembershipVersion uint64 `json:"membership_version"`
}

type ManualState struct {
	Disabled   bool `json:"disabled"`
	Excluded   bool `json:"excluded"`
	ZeroWeight bool `json:"zero_weight"`
}

// Row deliberately excludes source names, paths, URLs and auth metadata.
type RowCapabilities struct {
	Inventory bool `json:"inventory"`
	Query     bool `json:"query"`
	Gate      bool `json:"gate"`
}

type Row struct {
	Capabilities RowCapabilities `json:"capabilities"`
	Target
	Kind           string      `json:"kind"`
	Family         string      `json:"family"`
	SourceBindings []Target    `json:"source_bindings,omitempty"`
	BindingState   string      `json:"binding_state,omitempty"`
	ParentID       string      `json:"parent_id,omitempty"`
	Members        []string    `json:"members,omitempty"`
	Manual         ManualState `json:"manual"`
	Identity       string      `json:"identity"`
	Readiness      string      `json:"catalog_readiness"`
	Routing        string      `json:"runtime_readiness"`
}

type Snapshot struct {
	ContractVersion int `json:"version"`
	Version
	Complete  bool  `json:"complete"`
	Resources []Row `json:"resources"`
}

type Capabilities struct {
	CredentialQuery *CredentialQueryCapability `json:"credential_query,omitempty"`
	Scope           *Version                   `json:"scope,omitempty"`
	Version         int                        `json:"version"`
	Inventory       bool                       `json:"inventory"`
	Durable         bool                       `json:"durable"`
	Gate            bool                       `json:"gate"`
	Query           bool                       `json:"query"`
	PolicyLocked    bool                       `json:"policy_locked"`
	Reason          string                     `json:"reason"`
}

// CredentialQueryCapability versions the scoped operation, not generic billing
// or universal source coverage. Its presence conveys no admission/gate ACK.
type CredentialQueryCapability struct {
	Version     int  `json:"version"`
	Sources     bool `json:"sources"`
	ScopedQuery bool `json:"scoped_query"`
}

// Binding is host-issued evidence for a runtime source, never inference admission.
type Binding struct {
	Scope   Version  `json:"scope"`
	Targets []Target `json:"targets"`
}
