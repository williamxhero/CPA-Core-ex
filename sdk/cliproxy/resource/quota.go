package resource

// QuotaSource describes query authority, independently from inference admission.
type QuotaSource struct {
	Binding
	SourceVersion     string `json:"sourceVersion"`
	SourceID          string `json:"sourceId"`
	SubjectID         string `json:"subjectId"`
	AuthIndex         string `json:"auth_index,omitempty"`
	Protocol          string `json:"protocol"`
	State             string `json:"state"`
	Reason            string `json:"reason"`
	AccountProvenance string `json:"accountProvenance"`
	ManualDisabled    bool   `json:"manualDisabled"`
}

type QuotaQuery struct {
	Binding
	SourceVersion string `json:"sourceVersion"`
	SourceID      string `json:"sourceId"`
	SubjectID     string `json:"subjectId"`
	AuthIndex     string `json:"auth_index"`
	TimeoutMS     int64  `json:"timeoutMs,omitempty"`
}

type QuotaWindow struct {
	Name               string  `json:"name"`
	Model              string  `json:"model,omitempty"`
	LimitName          string  `json:"limitName,omitempty"`
	UsedPercent        float64 `json:"usedPercent"`
	RemainingFraction  float64 `json:"remainingFraction"`
	ResetAt            string  `json:"resetAt,omitempty"`
	SourceStatus       string  `json:"sourceStatus,omitempty"`
	LimitWindowSeconds int64   `json:"limitWindowSeconds,omitempty"`
}

// QuotaCredits is the Codex wallet observed with the same usage read.
// It is absent when that read did not include a credits object.
type QuotaCredits struct {
	HasCredits          bool   `json:"hasCredits"`
	Unlimited           bool   `json:"unlimited"`
	Balance             string `json:"balance,omitempty"`
	OverageLimitReached bool   `json:"overageLimitReached"`
}

// QuotaResetCredits is the Codex one-time rate-limit reset allowance observed
// with the same usage read. ApplicableAvailableCount is how many of those
// credits may be redeemed right now; it is absent when upstream omits it.
// No expiry is inferred: the usage read does not carry one.
type QuotaResetCredits struct {
	AvailableCount           int  `json:"availableCount"`
	ApplicableAvailableCount *int `json:"applicableAvailableCount,omitempty"`
}

// QuotaObservation never includes account IDs, tokens, raw responses or gate ACKs.
type QuotaObservation struct {
	Binding
	// StandardOnlyNoCredits requires explicit upstream shape and exact zero.
	// It is host-internal and omitted from the observation response.
	StandardOnlyNoCredits bool          `json:"-"`
	StandardPaidFunding   bool          `json:"-"`
	SourceVersion         string        `json:"sourceVersion"`
	ProtocolVersion       int           `json:"protocolVersion"`
	TimestampProvenance   string        `json:"timestampProvenance"`
	ReceivedAtMS          int64         `json:"receivedAtMs"`
	Protocol              string        `json:"protocol"`
	QueryStatus           string        `json:"queryStatus"`
	ErrorCode             string        `json:"errorCode,omitempty"`
	ObservedAtMS          int64         `json:"observedAtMs"`
	Windows               []QuotaWindow `json:"windows,omitempty"`
	Credits               *QuotaCredits `json:"credits,omitempty"`
	// ResetCredits is Codex-only and absent when the usage read omitted it.
	ResetCredits        *QuotaResetCredits  `json:"resetCredits,omitempty"`
	Complete            bool                `json:"complete"`
	AccountProvenance   string              `json:"accountProvenance"`
	RecoveryEligible    bool                `json:"recoveryEligible"`
	ClearedQuotaWindows []QuotaGateEvidence `json:"clearedQuotaWindows,omitempty"`
}
