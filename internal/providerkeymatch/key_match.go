// Package providerkeymatch defines a nonce-bound credential equality challenge,
// never a balance, wallet, account identity or funding attestation.
package providerkeymatch

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const MaxBytes = 32 << 10

var ErrInvalid = errors.New("invalid key match query")

type Request struct {
	resource.Binding
	Version       int    `json:"version"`
	SourceVersion string `json:"sourceVersion"`
	AuthIndex     string `json:"auth_index"`
	Adapter       string `json:"adapter"`
	Nonce         string `json:"nonce"`
	Digest        string `json:"digest"`
}

// Response deliberately cannot serialize the challenge digest or credential.
type Response struct {
	resource.Binding
	Version       int    `json:"version"`
	SourceVersion string `json:"sourceVersion"`
	AuthIndex     string `json:"auth_index"`
	Adapter       string `json:"adapter"`
	Nonce         string `json:"nonce"`
	Authority     string `json:"authority"`
	Matched       bool   `json:"matched"`
}

func Decode(raw []byte) (Request, error) {
	var q Request
	if len(raw) > MaxBytes || !utf8.Valid(raw) || !validShape(raw) {
		return q, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF {
		return Request{}, ErrInvalid
	}
	if !canonicalUUID(q.Nonce) || q.Version != 1 || q.Adapter != "deepseek" ||
		q.AuthIndex == "" || len(q.AuthIndex) > 128 || strings.TrimSpace(q.AuthIndex) != q.AuthIndex ||
		!printableASCII(q.AuthIndex) || !lowerDigest(q.Digest) || !lowerDigest(q.SourceVersion) || !validBinding(q.Binding) {
		return Request{}, ErrInvalid
	}
	return q, nil
}

func canonicalUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

func printableASCII(s string) bool {
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func validBinding(b resource.Binding) bool {
	s := b.Scope
	if !canonicalUUID(s.InstanceID) || !canonicalUUID(s.InstanceIncarnation) || !canonicalUUID(s.BootEpoch) || s.Revision == 0 || len(b.Targets) == 0 || len(b.Targets) > 64 {
		return false
	}
	for _, t := range b.Targets {
		if !canonicalUUID(t.ResourceID) || !canonicalUUID(t.Incarnation) || t.IdentityVersion == 0 || t.CredentialVersion == 0 || t.ConfigVersion == 0 {
			return false
		}
	}
	return true
}

// exactObject validates names and duplicates before encoding/json can apply
// case folding or last-field-wins. All frozen fields must be present, not null.
func exactObject(raw []byte, fields []string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	out := make(map[string]json.RawMessage, len(fields))
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !slices.Contains(fields, name) || out[name] != nil {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		out[name] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(out) != len(fields) {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

func validShape(raw []byte) bool {
	root, ok := exactObject(raw, []string{"version", "scope", "targets", "sourceVersion", "auth_index", "adapter", "nonce", "digest"})
	if !ok {
		return false
	}
	if _, ok := exactObject(root["scope"], []string{"instance_id", "instance_incarnation", "boot_epoch", "snapshot_revision"}); !ok {
		return false
	}
	var targets []json.RawMessage
	if json.Unmarshal(root["targets"], &targets) != nil || len(targets) == 0 || len(targets) > 64 {
		return false
	}
	for _, target := range targets {
		if _, ok := exactObject(target, []string{"resource_id", "incarnation", "identity_version", "credential_version", "config_version", "membership_version"}); !ok {
			return false
		}
	}
	return true
}

func lowerDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

// Matches uses the actual executor-resolved key and the frozen UTF-8 message.
// The digest is per challenge; no stable credential fingerprint is produced.
func Matches(key string, q Request) bool {
	provided, err := hex.DecodeString(q.Digest)
	if err != nil || !lowerDigest(q.Digest) {
		return false
	}
	m := hmac.New(sha256.New, []byte(key))
	_, _ = io.WriteString(m, "cpa-provider-key-match-v1\n"+q.Nonce+"\n"+q.SourceVersion+"\n"+q.AuthIndex)
	return hmac.Equal(m.Sum(nil), provided)
}
