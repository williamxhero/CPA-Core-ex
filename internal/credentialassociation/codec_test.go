package credentialassociation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// This is the exact parent/consumer independently verified frozen vector file.
//
//go:embed testdata/association-v2-vectors.json
var vectorJSON []byte

type goldenResult struct {
	EncodedBytes       int    `json:"encodedBytes"`
	ChallengeHash      string `json:"challengeHash"`
	ContractHash       string `json:"contractHash"`
	CandidateMAC       string `json:"candidateMac"`
	EncodedEnvelopeHex string `json:"encodedEnvelopeHex"`
	EncodedConfigHex   string `json:"encodedConfigHex"`
}
type goldenFile struct {
	Key         string          `json:"syntheticKeyUTF8"`
	BaseRequest json.RawMessage `json:"baseRequest"`
	Base        goldenResult    `json:"base"`
	Vectors     []struct {
		Name    string `json:"name"`
		Replace []struct {
			Path  []any `json:"path"`
			Value any   `json:"value"`
		} `json:"replace"`
		Remove [][]any `json:"remove"`
		goldenResult
	} `json:"vectors"`
}

func vectorBase(t *testing.T) goldenFile {
	t.Helper()
	var f goldenFile
	if err := json.Unmarshal(vectorJSON, &f); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(vectorJSON)) != "dd2f4c07dc8b01d92bbce66c69b088c305fe44e3fc92351ab1189ccd7d8844ef" {
		t.Fatal("frozen vector bytes changed")
	}
	return f
}
func goldenCheck(t *testing.T, raw []byte, key string, want goldenResult) {
	t.Helper()
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	envelope, err := Envelope(req)
	if err != nil {
		t.Fatalf("frozen envelope codec: %v", err)
	}
	config, err := ConfigBytes(req.Official)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) != want.EncodedBytes || fmt.Sprintf("%x", sha256.Sum256(envelope)) != want.ChallengeHash || fmt.Sprintf("%x", sha256.Sum256(config)) != want.ContractHash {
		t.Fatal("frozen bytes/hash mismatch")
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(envelope)
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != want.CandidateMAC {
		t.Fatal("frozen MAC mismatch")
	}
	if want.EncodedEnvelopeHex != "" {
		b, _ := hex.DecodeString(want.EncodedEnvelopeHex)
		if !bytes.Equal(b, envelope) {
			t.Fatal("base envelope hex mismatch")
		}
	}
	if want.EncodedConfigHex != "" {
		b, _ := hex.DecodeString(want.EncodedConfigHex)
		if !bytes.Equal(b, config) {
			t.Fatal("base config hex mismatch")
		}
	}
}
func TestAssociationFrozenGoldenVectors(t *testing.T) {
	f := vectorBase(t)
	t.Run("base", func(t *testing.T) { goldenCheck(t, f.BaseRequest, f.Key, f.Base) })
	if len(f.Vectors) != 55 {
		t.Fatal("frozen55 missing")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var obj any
			json.Unmarshal(f.BaseRequest, &obj)
			parent := func(path []any) (any, any) {
				p := obj
				for _, part := range path[:len(path)-1] {
					switch x := p.(type) {
					case map[string]any:
						p = x[part.(string)]
					case []any:
						p = x[int(part.(float64))]
					}
				}
				return p, path[len(path)-1]
			}
			for _, change := range v.Replace {
				p, k := parent(change.Path)
				switch x := p.(type) {
				case map[string]any:
					x[k.(string)] = change.Value
				case []any:
					x[int(k.(float64))] = change.Value
				}
			}
			for _, path := range v.Remove {
				p, k := parent(path)
				delete(p.(map[string]any), k.(string))
			}
			raw, _ := json.Marshal(obj)
			goldenCheck(t, raw, f.Key, v.goldenResult)
		})
	}
}
