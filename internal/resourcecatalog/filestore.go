package resourcecatalog

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type diskRecord struct {
	FileSeal       string          `json:"file_seal"`
	Target         resource.Target `json:"target"`
	CredentialSeal string          `json:"credential_seal"`
	ConfigSeal     string          `json:"config_seal"`
	MembershipSeal string          `json:"membership_seal"`
	Deleted        bool            `json:"deleted"`
	Blocked        bool            `json:"blocked"`
	Kind           string          `json:"kind"`
	Family         string          `json:"family"`
}
type diskState struct {
	Gates               *gateLedger            `json:"gates,omitempty"`
	GateSeal            string                 `json:"gate_seal,omitempty"`
	Format              int                    `json:"format"`
	InstanceID          string                 `json:"instance_id"`
	InstanceIncarnation string                 `json:"instance_incarnation"`
	Revision            uint64                 `json:"revision"`
	Records             map[string]*diskRecord `json:"records"`
	SourceSeal          string                 `json:"source_seal"`
}

func loadState(dir string) (*diskState, error) {
	data, err := os.ReadFile(filepath.Join(dir, "catalog.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	var state diskState
	if json.Unmarshal(data, &state) != nil || !validState(&state) {
		return nil, ErrUnavailable
	}
	return &state, nil
}
func removeTemporaryFile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.WithError(err).Warn("resource catalog temporary file cleanup failed")
	}
}

// prepareWrite returns a flushed, closed file ready for durable replacement.
func prepareWrite(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".resource-write-*")
	if err != nil {
		return "", ErrUnavailable
	}
	name := f.Name()
	success := false
	defer func() {
		if !success {
			removeTemporaryFile(name)
		}
	}()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	errClose := f.Close()
	if err != nil || errClose != nil {
		return "", ErrUnavailable
	}
	success = true
	return name, nil
}

func atomicWrite(path string, data []byte) error {
	name, err := prepareWrite(path, data)
	if err != nil {
		return err
	}
	defer removeTemporaryFile(name)
	return replaceFile(name, path)
}
func saveState(dir string, state *diskState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return ErrUnavailable
	}
	return atomicWrite(filepath.Join(dir, "catalog.json"), data)
}
func validID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && len(id) == 36 && u.Version() == 4 && u.String() == id
}
func validSeal(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }
func validState(s *diskState) bool {
	if s == nil || s.Format != 1 || s.Records == nil || !validID(s.InstanceID) || !validID(s.InstanceIncarnation) || s.Revision == 0 || !validSeal(s.SourceSeal) {
		return false
	}
	for id, r := range s.Records {
		if r == nil || !validID(id) || id != r.Target.ResourceID || !validID(r.Target.Incarnation) || r.Target.IdentityVersion == 0 || r.Target.CredentialVersion == 0 || r.Target.ConfigVersion == 0 || !validSeal(r.CredentialSeal) || !validSeal(r.ConfigSeal) || !validSeal(r.FileSeal) || (r.Kind != "provider" && r.Kind != "credential") {
			return false
		}
		if r.Kind == "provider" && (r.Target.MembershipVersion == 0 || !validSeal(r.MembershipSeal)) {
			return false
		}
	}
	return true
}
