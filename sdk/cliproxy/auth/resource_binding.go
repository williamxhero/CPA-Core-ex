package auth

// SourceIdentityBinder is instance-local and validates original persisted bytes.
// Plugin-returned markers are not authority. Unknown/multi-auth sources stay unbound.
type SourceIdentityBinder interface {
	BindAuths(path string, data []byte, auths []*Auth) error
}

// SourceIdentityWriter enrolls host saves before runtime publication.
type SourceIdentityWriter interface {
	SourceIdentityBinder
	SaveAuthFile(path string, data []byte) ([]byte, error)
}
