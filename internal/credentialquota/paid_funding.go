package credentialquota

import (
	"bytes"
	"io"
	"strings"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/regexp"
)

var codexPaidDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,59})(\.[0-9]{1,30})?$`)

// Personal Codex supports credits as an alternative to included usage. WHAM
// ties credits to the standard bucket, not to additional model-specific limits.
func codexStandardPaidFunding(data []byte) bool {
	var root struct {
		Plan       string             `json:"plan_type"`
		Additional *[]json.RawMessage `json:"additional_rate_limits"`
		Credits    *struct {
			Has       *bool           `json:"has_credits"`
			Unlimited *bool           `json:"unlimited"`
			Balance   json.RawMessage `json:"balance"`
			Overage   *bool           `json:"overage_limit_reached"`
		} `json:"credits"`
		Spend *struct {
			Reached *bool `json:"reached"`
		} `json:"spend_control"`
		Reached *struct {
			Kind string `json:"type"`
		} `json:"rate_limit_reached_type"`
	}
	if json.Unmarshal(data, &root) != nil ||
		(root.Plan != "plus" && root.Plan != "pro" && root.Plan != "prolite" && root.Plan != "promax") ||
		root.Additional == nil || len(*root.Additional) != 0 || root.Credits == nil ||
		root.Credits.Has == nil || !*root.Credits.Has || root.Credits.Unlimited == nil {
		return false
	}
	if root.Reached != nil && root.Reached.Kind != "rate_limit_reached" {
		return false
	}
	// An explicit non-blocking spend decision is required. An independent
	// spend limit must not be cleared by a positive nominal balance.
	if root.Credits.Overage != nil && *root.Credits.Overage ||
		root.Spend != nil && (root.Spend.Reached == nil || *root.Spend.Reached) ||
		root.Credits.Overage == nil && root.Spend == nil {
		return false
	}
	amount := creditBalanceText(root.Credits.Balance)
	return codexPaidDecimal.MatchString(amount) && strings.Trim(amount, "0.") != ""
}

// JSON object keys are matched case-insensitively by the typed decoder. Reject
// ambiguous keys before using an indication of credit funding for admission.
func unambiguousQuotaReading(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 24 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				name = strings.ToLower(name)
				if err != nil || !ok || seen[name] || !value(depth+1) {
					return false
				}
				seen[name] = true
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		}
		return true
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
