package credentialassociation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// Matches compares only this fresh frozen envelope. It exports neither the
// expected MAC nor a reusable credential digest.
func Matches(q Request, credential string) bool {
	envelope, err := Envelope(q)
	if err != nil || credential == "" {
		return false
	}
	candidate, err := base64.RawURLEncoding.DecodeString(q.CandidateMAC)
	if err != nil || len(candidate) != 32 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(credential))
	mac.Write(envelope)
	return hmac.Equal(candidate, mac.Sum(nil))
}

type Proof struct {
	Version       int    `json:"version"`
	Kind          string `json:"kind"`
	ChallengeHash string `json:"challengeHash"`
}
type Response struct {
	Version         uint64           `json:"version"`
	Associated      bool             `json:"associated"`
	Reason          string           `json:"reason"`
	Selected        resource.Binding `json:"selected"`
	AuthIndex       string           `json:"auth_index"`
	SourceVersion   string           `json:"sourceVersion"`
	Origin          string           `json:"origin"`
	OfficialBinding resource.Binding `json:"officialBinding"`
	OfficialVersion uint64           `json:"officialVersion"`
	QueryID         string           `json:"queryId"`
	Nonce           string           `json:"nonce"`
	ContractHash    string           `json:"contractHash"`
	Proof           *Proof           `json:"proof,omitempty"`
}

func Result(q Request, associated bool, reason string) (Response, error) {
	config, err := ConfigBytes(q.Official)
	if err != nil {
		return Response{}, err
	}
	envelope, err := Envelope(q)
	if err != nil {
		return Response{}, err
	}
	hash := sha256.Sum256(config)
	result := Response{Version: 1, Associated: associated, Reason: reason, Selected: q.Selected, AuthIndex: q.AuthIndex, SourceVersion: q.SourceVersion, Origin: q.Origin, OfficialBinding: q.Official.Binding, OfficialVersion: q.Official.Version, QueryID: q.QueryID, Nonce: q.Nonce, ContractHash: hex.EncodeToString(hash[:])}
	if associated {
		hash := sha256.Sum256(envelope)
		result.Proof = &Proof{Version: 2, Kind: "selected_credential_hmac_v2", ChallengeHash: hex.EncodeToString(hash[:])}
	}
	return result, nil
}
