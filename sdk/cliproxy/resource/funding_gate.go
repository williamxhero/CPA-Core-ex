package resource

// FundingReading carries the exact official observation. Manager authenticates
// the read; Core binds it to the current runtime and decides admission.
type FundingReading struct {
	QueryID      string            `json:"queryId"`
	ObservedAtMS int64             `json:"observedAtMs"`
	Available    *bool             `json:"available"`
	Balances     []FundingCurrency `json:"balances"`
}

type FundingCurrency struct {
	Currency string `json:"currency"`
	Total    string `json:"total"`
	Granted  string `json:"granted"`
	ToppedUp string `json:"toppedUp"`
}

type FundingGateEvidence struct {
	Source       string `json:"source"`
	ObservedAtMS int64  `json:"observedAtMs"`
}
