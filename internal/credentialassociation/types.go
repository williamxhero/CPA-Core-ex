// Package credentialassociation implements the frozen SPEC92 association wire.
// It does not perform upstream reads, interpret money, or attest Manager state.
package credentialassociation

import "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"

type Request struct {
	Version       uint64           `json:"version"`
	Selected      resource.Binding `json:"selected"`
	AuthIndex     string           `json:"auth_index"`
	SourceVersion string           `json:"sourceVersion"`
	Origin        string           `json:"origin"`
	Official      Config           `json:"official"`
	QueryID       string           `json:"queryId"`
	Nonce         string           `json:"nonce"`
	CandidateMAC  string           `json:"candidateMac"`
}
type Config struct {
	resource.Binding
	Version        uint64   `json:"version"`
	Adapter        string   `json:"adapter"`
	Endpoint       string   `json:"endpoint"`
	PrivateTargets []string `json:"privateTargets,omitempty"`
	TimeoutMS      uint64   `json:"timeoutMs,omitempty"`
	NewAPI         *NewAPI  `json:"newAPI,omitempty"`
}
type NewAPI struct {
	ProtocolConfirmed bool        `json:"protocolConfirmed"`
	InstanceVersion   string      `json:"instanceVersion"`
	Auth              string      `json:"auth"`
	UserID            string      `json:"userID,omitempty"`
	AccountScope      string      `json:"accountScope,omitempty"`
	NativeUnit        string      `json:"nativeUnit"`
	Conversion        *Conversion `json:"conversion,omitempty"`
}
type Conversion struct {
	Confirmed           bool   `json:"confirmed"`
	NativeUnit          string `json:"nativeUnit"`
	Currency            string `json:"currency"`
	MoneyPerNativeQuota string `json:"moneyPerNativeQuota"`
	ProofReference      string `json:"proofReference"`
	ContractVersion     string `json:"contractVersion"`
}
