package resource

// GateOperation carries complete host-issued source authority and an owner CAS.
type GateOperation struct {
	Version          int    `json:"version"`
	OpID             string `json:"opId"`
	ExpectedRevision uint64 `json:"expectedGateRevision"`
	Binding
	AuthIndex     string `json:"auth_index"`
	SourceVersion string `json:"sourceVersion"`
	Subject       string `json:"subject"`
	Model         string `json:"model"`
	Owner         string `json:"owner"`
	Action        string `json:"action"`
	Reason        string `json:"reason"`
	EvidenceID    string `json:"evidenceId"`
}

type GateResult struct {
	Version         int    `json:"version"`
	OpID            string `json:"opId"`
	Status          string `json:"status"`
	Revision        uint64 `json:"gateRevision"`
	DurableRevision uint64 `json:"durableRevision"`
	AppliedRevision uint64 `json:"appliedRevision"`
	Durable         bool   `json:"durable"`
	Applied         bool   `json:"applied"`
	Error           string `json:"error"`
}

type Gate struct {
	Applicability string   `json:"applicability,omitempty"`
	Targets       []Target `json:"targets"`
	Owner         string   `json:"owner"`
	Model         string   `json:"model"`
	Reason        string   `json:"reason"`
	EvidenceID    string   `json:"evidenceId"`
	SourceVersion string   `json:"sourceVersion"`
	Revision      uint64   `json:"gateRevision"`
}

type GateState struct {
	AllSourcesReady bool    `json:"allSourcesReady"`
	Version         int     `json:"version"`
	Scope           Version `json:"scope"`
	Revision        uint64  `json:"gateRevision"`
	Ready           bool    `json:"ready"`
	Gates           []Gate  `json:"gates"`
}
