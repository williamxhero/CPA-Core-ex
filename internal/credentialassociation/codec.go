package credentialassociation

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const MaxBytes = 32 * 1024

var ErrInvalid = errors.New("invalid credential association")

type encoder struct {
	bytes.Buffer
	bad bool
}

func (e *encoder) u(n uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); e.Write(b[:]) }
func (e *encoder) c(n int) {
	if n < 0 || n > MaxBytes {
		e.bad = true
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	e.Write(b[:])
}
func (e *encoder) o(b []byte) {
	if len(b) > MaxBytes || e.Len()+len(b)+4 > MaxBytes {
		e.bad = true
		return
	}
	e.c(len(b))
	e.Write(b)
}
func (e *encoder) s(s string) {
	if !utf8.ValidString(s) || len(s) > 4096 {
		e.bad = true
		return
	}
	e.o([]byte(s))
}
func (e *encoder) b(v bool) {
	if v {
		e.WriteByte(1)
	} else {
		e.WriteByte(0)
	}
}
func (e *encoder) binding(b resource.Binding) {
	e.s(b.Scope.InstanceID)
	e.s(b.Scope.InstanceIncarnation)
	e.s(b.Scope.BootEpoch)
	e.u(b.Scope.Revision)
	e.c(len(b.Targets))
	for _, t := range b.Targets {
		e.s(t.ResourceID)
		e.s(t.Incarnation)
		e.u(t.IdentityVersion)
		e.u(t.CredentialVersion)
		e.u(t.ConfigVersion)
		e.u(t.MembershipVersion)
	}
}
func (e *encoder) config(c Config) {
	e.binding(c.Binding)
	e.u(c.Version)
	e.s(c.Adapter)
	e.s(c.Endpoint)
	e.c(len(c.PrivateTargets))
	for _, v := range c.PrivateTargets {
		e.s(v)
	}
	e.u(c.TimeoutMS)
	e.b(c.NewAPI != nil)
	if n := c.NewAPI; n != nil {
		e.b(n.ProtocolConfirmed)
		e.s(n.InstanceVersion)
		e.s(n.Auth)
		e.s(n.UserID)
		e.s(n.AccountScope)
		e.s(n.NativeUnit)
		e.b(n.Conversion != nil)
		if v := n.Conversion; v != nil {
			e.b(v.Confirmed)
			e.s(v.NativeUnit)
			e.s(v.Currency)
			e.s(v.MoneyPerNativeQuota)
			e.s(v.ProofReference)
			e.s(v.ContractVersion)
		}
	}
}
func (e *encoder) finish() ([]byte, error) {
	if e.bad || e.Len() > MaxBytes {
		return nil, ErrInvalid
	}
	return e.Bytes(), nil
}

// Envelope encodes fixed fields without asserting their authority or validity.
// Altered-field codec vectors can intentionally fail subsequent API validation.
// candidateMac is deliberately excluded, allowing a caller to construct the MAC.
func Envelope(r Request) ([]byte, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(r.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != r.Nonce {
		return nil, ErrInvalid
	}
	e := new(encoder)
	e.s("CPA-SPEC92-CREDENTIAL-ASSOCIATION-V2")
	e.u(r.Version)
	e.binding(r.Selected)
	e.s(r.AuthIndex)
	e.s(r.SourceVersion)
	e.s(r.Origin)
	e.config(r.Official)
	e.s(r.QueryID)
	e.o(nonce)
	return e.finish()
}
func ConfigBytes(c Config) ([]byte, error) { e := new(encoder); e.config(c); return e.finish() }
