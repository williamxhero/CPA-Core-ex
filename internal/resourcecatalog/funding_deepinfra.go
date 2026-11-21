package resourcecatalog

import (
	"encoding/hex"
	"math/big"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func validPayerRef(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == value
}

func exactFundingDecimal(s string) *big.Rat {
	if !fundingDecimal.MatchString(s) {
		return nil
	}
	n, _ := new(big.Rat).SetString(s)
	return n
}

// Neither a dollar amount nor a suspension alone establishes that there is
// no alternative spendable funding for this independently authorized bearer.
func deepInfraFundingState(reading resource.FundingReading, now time.Time) string {
	d := reading.DeepInfra
	if d == nil || !validPayerRef(d.Payer) || d.Suspended == nil ||
		d.CheckedAt <= 0 || d.CheckedAt > now.Unix()+30 || now.Unix()-d.CheckedAt >= 300 ||
		reading.ObservedAtMS/1000-d.CheckedAt >= 300 || d.CheckedAt-reading.ObservedAtMS/1000 > 30 ||
		reading.Available != nil || reading.Balances != nil {
		return ""
	}
	stripe, recent, overdue := exactFundingDecimal(d.Stripe), exactFundingDecimal(d.Recent), exactFundingDecimal(d.Overdue)
	if stripe == nil || recent == nil || overdue == nil || overdue.Sign() != 0 {
		return ""
	}
	prepaid := new(big.Rat).Add(stripe, recent)
	if !*d.Suspended && d.Reason == "none" && prepaid.Sign() < 0 {
		return "clear"
	}
	if !*d.Suspended || d.Reason != "balance" || prepaid.Sign() < 0 || d.Credits == nil || len(d.Credits) > 32 {
		return ""
	}
	for _, bucket := range d.Credits {
		amount := exactFundingDecimal(bucket.Remaining)
		if amount == nil || amount.Sign() < 0 || bucket.Expired == nil ||
			(amount.Sign() > 0 && (!*bucket.Expired || bucket.ExpiresAt == nil || *bucket.ExpiresAt >= d.CheckedAt)) {
			return ""
		}
	}
	return "pause"
}
