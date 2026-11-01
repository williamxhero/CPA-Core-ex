package credentialassociation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const safeCounter uint64 = 9007199254740991

var opaqueID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var sourceRevision = regexp.MustCompile(`^[0-9a-f]{64}$`)

type shape struct {
	kind     byte
	fields   map[string]*shape
	optional map[string]bool
	item     *shape
	max      int
}

var str = &shape{kind: 's'}
var number = &shape{kind: 'n'}
var boolean = &shape{kind: 'b'}

func object(fields map[string]*shape, optional ...string) *shape {
	s := &shape{kind: 'o', fields: fields, optional: map[string]bool{}}
	for _, k := range optional {
		s.optional[k] = true
	}
	return s
}
func list(item *shape, max int) *shape { return &shape{kind: 'a', item: item, max: max} }

var scopeShape = object(map[string]*shape{"instance_id": str, "instance_incarnation": str, "boot_epoch": str, "snapshot_revision": number})
var targetShape = object(map[string]*shape{"resource_id": str, "incarnation": str, "identity_version": number, "credential_version": number, "config_version": number, "membership_version": number})
var bindingShape = object(map[string]*shape{"scope": scopeShape, "targets": list(targetShape, 64)})
var conversionShape = object(map[string]*shape{"confirmed": boolean, "nativeUnit": str, "currency": str, "moneyPerNativeQuota": str, "proofReference": str, "contractVersion": str})
var newAPIShape = object(map[string]*shape{"protocolConfirmed": boolean, "instanceVersion": str, "auth": str, "userID": str, "accountScope": str, "nativeUnit": str, "conversion": conversionShape}, "userID", "accountScope", "conversion")
var configShape = object(map[string]*shape{"scope": scopeShape, "targets": list(targetShape, 64), "version": number, "adapter": str, "endpoint": str, "privateTargets": list(str, 16), "timeoutMs": number, "newAPI": newAPIShape}, "privateTargets", "timeoutMs", "newAPI")
var requestShape = object(map[string]*shape{"version": number, "selected": bindingShape, "auth_index": str, "sourceVersion": str, "origin": str, "official": configShape, "queryId": str, "nonce": str, "candidateMac": str})

// Decode rejects all shadowing BEFORE encoding/json's case-insensitive struct
// matching or map overwrite can discard the original field sequence.
func Decode(raw []byte) (Request, error) {
	var r Request
	if len(raw) > MaxBytes || !utf8.Valid(raw) || !validSurrogates(raw) {
		return r, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if validateShape(d, requestShape, 0) != nil {
		return r, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return r, ErrInvalid
	}
	if json.Unmarshal(raw, &r) != nil || !validRequest(r) {
		return Request{}, ErrInvalid
	}
	return r, nil
}
func validateShape(d *json.Decoder, s *shape, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	switch s.kind {
	case 's':
		v, ok := token.(string)
		if !ok || len(v) > 4096 || !utf8.ValidString(v) {
			return ErrInvalid
		}
	case 'n':
		v, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		text := v.String()
		if text == "" || len(text) > 20 || len(text) > 1 && text[0] == '0' {
			return ErrInvalid
		}
		for _, c := range text {
			if c < '0' || c > '9' {
				return ErrInvalid
			}
		}
		if _, err := strconv.ParseUint(text, 10, 64); err != nil {
			return ErrInvalid
		}
	case 'b':
		if _, ok := token.(bool); !ok {
			return ErrInvalid
		}
	case 'o':
		if token != json.Delim('{') {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			if !ok || seen[name] || s.fields[name] == nil {
				return ErrInvalid
			}
			seen[name] = true
			if validateShape(d, s.fields[name], depth+1) != nil {
				return ErrInvalid
			}
		}
		for k := range s.fields {
			if !s.optional[k] && !seen[k] {
				return ErrInvalid
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case 'a':
		if token != json.Delim('[') {
			return ErrInvalid
		}
		n := 0
		for d.More() {
			n++
			if n > s.max || validateShape(d, s.item, depth+1) != nil {
				return ErrInvalid
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validRequest(r Request) bool {
	if r.Version != 1 || r.AuthIndex == "" || !sourceRevision.MatchString(r.SourceVersion) || !opaqueID.MatchString(r.QueryID) || !ValidBinding(r.Selected) || !ValidBinding(r.Official.Binding) || r.Official.Version == 0 || r.Official.Version >= safeCounter || r.Official.TimeoutMS > 60000 {
		return false
	}
	if !validBlock(r.Nonce) || !validBlock(r.CandidateMAC) {
		return false
	}
	origin, ok := HTTPSOrigin(r.Origin)
	u, err := url.Parse(r.Origin)
	if !ok || origin != r.Origin || err != nil || u.Path != "" {
		return false
	}
	_, err = Envelope(r)
	return err == nil
}
func validBlock(s string) bool {
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func ValidBinding(b resource.Binding) bool {
	s := b.Scope
	if !opaqueID.MatchString(s.InstanceID) || !opaqueID.MatchString(s.InstanceIncarnation) || !opaqueID.MatchString(s.BootEpoch) || s.Revision == 0 || s.Revision > safeCounter || len(b.Targets) == 0 || len(b.Targets) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, t := range b.Targets {
		if seen[t.ResourceID] || !opaqueID.MatchString(t.ResourceID) || !opaqueID.MatchString(t.Incarnation) || t.IdentityVersion == 0 || t.IdentityVersion > safeCounter || t.CredentialVersion == 0 || t.CredentialVersion > safeCounter || t.ConfigVersion == 0 || t.ConfigVersion > safeCounter || t.MembershipVersion > safeCounter {
			return false
		}
		seen[t.ResourceID] = true
	}
	return true
}

// HTTPSOrigin is syntactic only: no DNS, redirect, credential or transport permit.
// Path recognition remains the actual executor's responsibility.
func HTTPSOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return "", false
		}
		host = ip.String()
	} else {
		if len(host) > 253 {
			return "", false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", false
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", false
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != port {
		return "", false
	}
	return "https://" + net.JoinHostPort(host, port), true
}

// encoding/json replaces unpaired escaped UTF-16 surrogates. Reject the raw
// invalid sequence instead, without rejecting legitimate literal U+FFFD text.
func validSurrogates(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			in = !in
			continue
		}
		if !in || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !in
}
