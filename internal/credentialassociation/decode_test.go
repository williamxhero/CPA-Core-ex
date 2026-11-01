package credentialassociation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func validWire(t *testing.T) []byte {
	t.Helper()
	f := vectorBase(t)
	var r map[string]any
	json.Unmarshal(f.BaseRequest, &r)
	r["candidateMac"] = f.Base.CandidateMAC
	raw, _ := json.Marshal(r)
	return raw
}
func TestAssociationStrictFrozenValidation(t *testing.T) {
	raw := validWire(t)
	if _, err := Decode(raw); err != nil {
		t.Fatalf("valid frozen wire rejected: %v", err)
	}
	bad := map[string][]byte{
		"top-duplicate":             []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)),
		"unknown":                   []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"unknown":true`, 1)),
		"case-shadow":               []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"Version":1`, 1)),
		"escaped-decoded-duplicate": []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"\u0076ersion":1`, 1)),
		"unicode-shadow":            []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"verſion":1`, 1)),
		"nested-duplicate":          []byte(strings.Replace(string(raw), `"auth":"inference-key-readonly-v1"`, `"auth":"inference-key-readonly-v1","auth":"inference-key-readonly-v1"`, 1)),
		"conversion-unknown":        []byte(strings.Replace(string(raw), `"confirmed":true`, `"confirmed":true,"unknown":true`, 1)),
		"bool-null":                 []byte(strings.Replace(string(raw), `"confirmed":true`, `"confirmed":null`, 1)),
		"array-null":                []byte(strings.Replace(string(raw), `"privateTargets":["10.0.0.1","10.0.0.2"]`, `"privateTargets":null`, 1)),
		"object-null":               []byte(strings.Replace(string(raw), `"conversion":{`, `"conversion":null,"other":{`, 1)),
		"zero-identity":             []byte(strings.Replace(string(raw), `"identity_version":1`, `"identity_version":0`, 1)),
		"zero-provider-credential":  []byte(strings.Replace(string(raw), `"credential_version":1`, `"credential_version":0`, 1)),
		"unsafe-snapshot":           []byte(strings.Replace(string(raw), `"snapshot_revision":9`, `"snapshot_revision":9007199254740992`, 1)),
		"config-max-not-allowed":    []byte(strings.Replace(string(raw), `"version":7`, `"version":9007199254740991`, 1)),
		"fraction":                  []byte(strings.Replace(string(raw), `"version":1`, `"version":1.0`, 1)),
		"exponent":                  []byte(strings.Replace(string(raw), `"version":1`, `"version":1e0`, 1)),
		"signed-zero":               []byte(strings.Replace(string(raw), `"membership_version":0`, `"membership_version":-0`, 1)),
		"counter-string":            []byte(strings.Replace(string(raw), `"identity_version":1`, `"identity_version":"1"`, 1)),
		"missing-membership":        []byte(strings.Replace(string(raw), `"membership_version":0,`, ``, 1)),
		"nonce-padding":             []byte(strings.Replace(string(raw), `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`, `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`, 1)),
		"nonce-short":               []byte(strings.Replace(string(raw), `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`, `AAAA`, 1)),
		"surrogate-high":            []byte(strings.Replace(string(raw), `synthetic-selected-index`, `\ud800`, 1)),
		"surrogate-low":             []byte(strings.Replace(string(raw), `synthetic-selected-index`, `\udc00`, 1)),
		"origin-no-explicit-port":   []byte(strings.Replace(string(raw), `https://synthetic.invalid:443`, `https://synthetic.invalid`, 1)),
		"origin-path":               []byte(strings.Replace(string(raw), `https://synthetic.invalid:443`, `https://synthetic.invalid:443/v1`, 1)),
		"origin-userinfo":           []byte(strings.Replace(string(raw), `https://synthetic.invalid:443`, `https://user@synthetic.invalid:443`, 1)),
		"origin-http":               []byte(strings.Replace(string(raw), `https://synthetic.invalid:443`, `http://synthetic.invalid:443`, 1)),
		"extra-json":                append(append([]byte{}, raw...), []byte(`{}`)...),
		"oversize":                  append(append([]byte{}, raw...), bytes.Repeat([]byte(" "), MaxBytes)...),
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(input, raw) {
				t.Fatal("negative fixture unchanged")
			}
			if _, err := Decode(input); err == nil {
				t.Fatal("malformed association accepted")
			}
		})
	}
}
