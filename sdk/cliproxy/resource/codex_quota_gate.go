package resource

// Codex emits opaque limit IDs. Only this reviewed ID/name/model tuple is a
// route-scope authority; an arbitrary metered feature or display name is not.
const (
	CodexSparkModel     = "gpt-5.3-codex-spark"
	CodexSparkLimit     = "codex_bengalfox"
	CodexSparkLimitName = "GPT-5.3-Codex-Spark"
)

// CodexQuotaRejection is the narrowly typed fact extracted by the native
// adapter from a business response. No raw headers or credentials travel here.
type CodexQuotaRejection struct {
	Model         string
	Window        string
	WindowSeconds int64
	ObservedAtMS  int64
	ResetAtMS     int64
}

// QuotaGateEvidence gives administrators a precise, secret-free pause cause
// and time to recheck. RecheckAtMS does not authorize admission by itself.
type QuotaGateEvidence struct {
	Window        string `json:"window"`
	WindowSeconds int64  `json:"windowSeconds"`
	ObservedAtMS  int64  `json:"observedAtMs"`
	RecheckAtMS   int64  `json:"recheckAtMs,omitempty"`
}
