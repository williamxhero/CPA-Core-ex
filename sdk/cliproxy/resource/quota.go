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
	Name              string  `json:"name"`
	Model             string  `json:"model,omitempty"`
	UsedPercent       float64 `json:"usedPercent"`
	RemainingFraction float64 `json:"remainingFraction"`
	ResetAt           string  `json:"resetAt,omitempty"`
	SourceStatus      string  `json:"sourceStatus,omitempty"`
}

// QuotaObservation never includes account IDs, tokens, raw responses or gate ACKs.
type QuotaObservation struct {
	Binding
	SourceVersion       string        `json:"sourceVersion"`
	ProtocolVersion     int           `json:"protocolVersion"`
	TimestampProvenance string        `json:"timestampProvenance"`
	ReceivedAtMS        int64         `json:"receivedAtMs"`
	Protocol            string        `json:"protocol"`
	QueryStatus         string        `json:"queryStatus"`
	ErrorCode           string        `json:"errorCode,omitempty"`
	ObservedAtMS        int64         `json:"observedAtMs"`
	Windows             []QuotaWindow `json:"windows,omitempty"`
	Complete            bool          `json:"complete"`
	AccountProvenance   string        `json:"accountProvenance"`
	RecoveryEligible    bool          `json:"recoveryEligible"`
}
