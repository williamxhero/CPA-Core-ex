package resource

// FundingReading carries the exact official observation. Manager authenticates
// the read; Core binds it to the current runtime and decides admission.
type FundingReading struct {
	QueryID      string            `json:"queryId"`
	ObservedAtMS int64             `json:"observedAtMs"`
	Available    *bool             `json:"available"`
	Balances     []FundingCurrency `json:"balances"`
	DeepInfra    *DeepInfraFunding `json:"deepInfra,omitempty"`
}

type FundingCurrency struct {
	Currency string `json:"currency"`
	Total    string `json:"total"`
	Granted  string `json:"granted"`
	ToppedUp string `json:"toppedUp"`
}

// DeepInfraFunding carries only the minimum signed checklist facts and a
// service-keyed payer reference, never the original account identifier.
type DeepInfraFunding struct {
	Payer     string            `json:"payer"`
	CheckedAt int64             `json:"checkedAt"`
	Suspended *bool             `json:"suspended"`
	Reason    string            `json:"reason"`
	Stripe    string            `json:"stripe"`
	Recent    string            `json:"recent"`
	Overdue   string            `json:"overdue"`
	Credits   []DeepInfraCredit `json:"credits"`
}

type DeepInfraCredit struct {
	Remaining string `json:"remaining"`
	Expired   *bool  `json:"expired"`
	ExpiresAt *int64 `json:"expiresAt"`
}

type FundingGateEvidence struct {
	Source       string `json:"source"`
	ObservedAtMS int64  `json:"observedAtMs"`
}
