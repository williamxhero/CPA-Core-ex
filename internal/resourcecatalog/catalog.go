// Package resourcecatalog owns opt-in file-backed resource inventory.
package resourcecatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

var (
	ErrUnavailable = errors.New("resource catalog unavailable")
	ErrConflict    = errors.New("resource catalog version conflict")
	ErrUnsupported = errors.New("resource catalog filesystem unsupported")
	// ErrSuperseded means a journal recorded source seals but replaced no files,
	// then the sources moved. The journal is gone and reconciliation must republish.
	ErrSuperseded = errors.New("resource catalog publication superseded")
)

type Catalog struct {
	ownedFileReplacements map[string]string
	configuredProjection  *configuredSourceProjection

	mu                                  sync.Mutex
	lock                                *os.File
	closed, failed                      bool
	configPath, authDir, stateDir, boot string
	key                                 []byte
	writeFile                           func(string, []byte) error
	state                               *diskState
	snapshot                            resource.Snapshot
}

// Open explicitly opts into source marker migration. GET never calls Open.
func Open(configPath, authDir, stateDir string) (*Catalog, error) {
	var err error
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	authDir, err = filepath.Abs(authDir)
	if err != nil {
		return nil, ErrUnavailable
	}
	stateDir, err = physicalPath(statePath(configPath, stateDir))
	if err != nil {
		return nil, err
	}
	authDir, err = physicalPath(authDir)
	if err != nil {
		return nil, err
	}
	if containsPath(authDir, stateDir) || containsPath(stateDir, authDir) {
		return nil, ErrUnavailable
	}
	if err = verifySourceMode(configPath, authDir, stateDir); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(stateDir, 0700); err != nil {
		return nil, ErrUnavailable
	}
	lock, err := lockWriter(filepath.Join(stateDir, "writer.lock"))
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			if errClose := lock.Close(); errClose != nil {
				log.WithError(errClose).Warn("resource catalog initialization lock cleanup failed")
			}
		}
	}()
	_, errExistingKey := os.Lstat(filepath.Join(stateDir, "seal.key"))
	existingKey := !os.IsNotExist(errExistingKey)
	key, err := loadSealKey(stateDir)
	if err != nil {
		return nil, err
	}
	c := &Catalog{lock: lock, configPath: configPath, authDir: authDir, stateDir: stateDir, key: key, boot: uuid.NewString(), writeFile: atomicWrite}
	if err = c.recoverPublication(); err != nil && !errors.Is(err, ErrSuperseded) {
		return nil, err
	}
	state, err := loadState(stateDir)
	if err != nil {
		return nil, err
	}
	if state == nil {
		if existingKey {
			return nil, ErrUnavailable
		}
		// Persist the empty issued ledger before reading fallible sources. A failed
		// first migration can then resume without confusing it with a lost ledger.
		state = &diskState{Format: 1, InstanceID: uuid.NewString(), InstanceIncarnation: uuid.NewString(), Revision: 1, SourceSeal: sealValue(key, map[string]string{}), Records: map[string]*diskRecord{}}
		if err = saveState(stateDir, state); err != nil {
			return nil, err
		}
	}
	c.state = state
	if err = c.initializeGates(); err != nil {
		return nil, err
	}
	if err = c.reconcileLocked(); errors.Is(err, ErrSuperseded) {
		err = c.reconcileLocked()
	}
	if err != nil {
		return nil, err
	}
	success = true
	return c, nil
}

func (c *Catalog) versionLocked() resource.Version {
	return resource.Version{InstanceID: c.state.InstanceID, InstanceIncarnation: c.state.InstanceIncarnation, BootEpoch: c.boot, Revision: c.state.Revision}
}

// Version is the last published version, even while sources await reconciliation.
func (c *Catalog) Version() resource.Version {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.versionLocked()
}

// Reconcile serializes source publication. Stale or cross-boot callers cannot write.
func (c *Catalog) Reconcile(expected resource.Version) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.failed {
		return ErrUnavailable
	}
	if expected != c.versionLocked() {
		return ErrConflict
	}
	// A journal is an unfinished publication, not proof the catalog is corrupt.
	// Finish it, or drop it when it replaced nothing and the sources have since moved.
	// Only a journal that remains after that attempt disables further publication.
	if err := c.finishOutstandingJournal(); err != nil {
		return err
	}
	if !c.storageCurrentLocked() {
		c.failed = true
		return ErrUnavailable
	}
	err := c.reconcileLocked()
	if errors.Is(err, ErrSuperseded) {
		err = c.reconcileLocked()
	}
	if err != nil {
		if _, errJournal := os.Stat(filepath.Join(c.stateDir, "journal.json")); !os.IsNotExist(errJournal) {
			c.failed = true
		}
	}
	return err
}

// finishOutstandingJournal completes a journal left by an interrupted publish.
// A zero-write journal whose sources moved is removed by finishPublication and
// reported as ErrSuperseded; that is not a storage failure.
func (c *Catalog) finishOutstandingJournal() error {
	journal := filepath.Join(c.stateDir, "journal.json")
	if _, err := os.Stat(journal); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return ErrUnavailable
	}
	err := c.recoverPublication()
	if errors.Is(err, ErrSuperseded) {
		return nil
	}
	if err != nil {
		return err
	}
	state, err := loadState(c.stateDir)
	if err != nil || state == nil {
		return ErrUnavailable
	}
	c.state = state
	return nil
}

func (c *Catalog) reconcileLocked() error {
	if err := verifySourceMode(c.configPath, c.authDir, c.stateDir); err != nil {
		return err
	}
	files, rows, err := sources(c.configPath, c.authDir)
	if err != nil {
		return err
	}
	if err = bindPluginProjections(rows, c.key); err != nil {
		return err
	}
	// Work on an isolated proposal; failed persistence cannot publish new versions.
	raw, err := json.Marshal(c.state)
	if err != nil {
		return ErrUnavailable
	}
	var state diskState
	if json.Unmarshal(raw, &state) != nil {
		return ErrUnavailable
	}
	values := map[string]string{}
	combinedValues := map[string]string{}
	for _, f := range files {
		b := f.original
		if f.changed {
			b, err = f.encode()
			if err != nil {
				return err
			}
		}
		values[f.path] = seal(c.key, b)
		combinedValues[f.path] = sealValue(c.key, []string{seal(c.key, []byte(f.fileID)), values[f.path]})
	}
	stamp := sealValue(c.key, combinedValues)
	if state.Revision == 0 || state.SourceSeal != stamp {
		if !advance(&state.Revision) {
			return ErrUnavailable
		}
	}
	state.SourceSeal = stamp
	snapshot := resource.Snapshot{ContractVersion: 1, Version: resource.Version{InstanceID: state.InstanceID, InstanceIncarnation: state.InstanceIncarnation, BootEpoch: c.boot, Revision: state.Revision}, Complete: true, Resources: []resource.Row{}}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.row.ResourceID]++
	}
	for id, record := range state.Records {
		if counts[id] == 0 && !record.Deleted {
			record.Deleted = true
			if !advance(&record.Target.IdentityVersion) {
				return ErrUnavailable
			}
		}
	}
	for _, r := range rows {
		credentialSeal, configSeal, errSeal := rowSeals(c.key, r)
		if errSeal != nil {
			return errSeal
		}
		fileSeal := seal(c.key, []byte(r.file.fileID))
		record := state.Records[r.row.ResourceID]
		if record == nil && !r.fresh {
			r.row.Target = resource.Target{}
			r.row.Identity = "ambiguous"
			r.row.Readiness = "not_ready"
			snapshot.Resources = append(snapshot.Resources, r.row)
			continue
		}
		if record == nil {
			record = &diskRecord{Kind: r.row.Kind, Family: r.row.Family, Target: resource.Target{ResourceID: r.row.ResourceID, Incarnation: uuid.NewString(), IdentityVersion: 1, CredentialVersion: 1, ConfigVersion: 1}}
			state.Records[r.row.ResourceID] = record
		}
		if (record.Deleted || (record.FileSeal != "" && record.FileSeal != fileSeal && c.ownedFileReplacements[r.row.ResourceID] != fileSeal) || counts[r.row.ResourceID] > 1 || record.Kind != r.row.Kind || record.Family != r.row.Family) && !record.Blocked {
			record.Blocked = true
			record.Target.Incarnation = uuid.NewString()
			if !advance(&record.Target.IdentityVersion) {
				return ErrUnavailable
			}
		}
		if record.Blocked {
			r.row.Identity = "ambiguous"
			r.row.Readiness = "not_ready"
		}
		if r.row.Family == "unsupported" {
			r.row.Readiness = "unsupported"
		}
		// An unproven source replacement stays blocked, but changed credentials
		// still fence old observations. Never attribute one of several duplicate
		// sources to the shared record or repeatedly advance an unchanged seal.
		if counts[r.row.ResourceID] == 1 {
			if record.CredentialSeal != "" && record.CredentialSeal != credentialSeal {
				record.Target.Incarnation = uuid.NewString()
				if !advance(&record.Target.IdentityVersion) {
					return ErrUnavailable
				}
				if !advance(&record.Target.CredentialVersion) {
					return ErrUnavailable
				}
			}
			record.CredentialSeal = credentialSeal
		}
		if !record.Blocked {
			if record.ConfigSeal != "" && record.ConfigSeal != configSeal {
				if !advance(&record.Target.ConfigVersion) {
					return ErrUnavailable
				}
			}
			record.FileSeal = fileSeal
			record.ConfigSeal = configSeal
			if r.row.Kind == "provider" {
				members := append([]string{}, r.row.Members...)
				sort.Strings(members)
				membershipSeal := sealValue(c.key, members)
				if record.MembershipSeal != "" && record.MembershipSeal != membershipSeal {
					if !advance(&record.Target.MembershipVersion) {
						return ErrUnavailable
					}
					if !advance(&record.Target.ConfigVersion) {
						return ErrUnavailable
					}
					if !advance(&record.Target.IdentityVersion) {
						return ErrUnavailable
					}
				}
				if record.Target.MembershipVersion == 0 {
					record.Target.MembershipVersion = 1
				}
				record.MembershipSeal = membershipSeal
			}
		}
		r.row.Target = record.Target
		snapshot.Resources = append(snapshot.Resources, r.row)
	}
	for i := range snapshot.Resources {
		row := &snapshot.Resources[i]
		if rows[i].parent != nil && (rows[i].parent.row.Identity != "valid" || rows[i].parent.row.Readiness != "ready") {
			row.Readiness = "not_ready"
		}
		if state.Records[row.ParentID] == nil {
			row.ParentID = ""
		}
		members := []string{}
		for _, id := range row.Members {
			if state.Records[id] != nil {
				members = append(members, id)
			}
		}
		row.Members = members
	}
	for i := range snapshot.Resources {
		row := &snapshot.Resources[i]
		if rows[i].parent != nil && (rows[i].parent.row.Identity != "valid" || rows[i].parent.row.Readiness != "ready") {
			row.Readiness = "not_ready"
		}
		if row.Kind != "provider" {
			continue
		}
		for _, child := range snapshot.Resources {
			if child.ParentID == row.ResourceID && child.Readiness != "ready" {
				row.Readiness = "not_ready"
			}
		}
	}

	for i, source := range rows {
		row := &snapshot.Resources[i]
		for _, related := range source.projections {
			for _, candidate := range snapshot.Resources {
				if candidate.ResourceID == related.row.ResourceID {
					if row.Identity == "valid" && candidate.Identity == "valid" && row.Readiness == "ready" && candidate.Readiness == "ready" {
						row.SourceBindings = append(row.SourceBindings, candidate.Target)
					} else if candidate.Identity == "valid" {
						// A blocked or deleted config record is not a second valid
						// source. It must not take a matching auth file offline.
						row.BindingState = "ambiguous_projection"
						row.Readiness = "not_ready"
					}
				}
			}
		}
	}
	// Projection validation can make a child unavailable after source identity
	// validation; propagate that result to its provider before publication.
	for i := range snapshot.Resources {
		parent := &snapshot.Resources[i]
		if parent.Kind != "provider" {
			continue
		}
		for _, child := range snapshot.Resources {
			if child.ParentID == parent.ResourceID && child.Readiness != "ready" {
				parent.Readiness = "not_ready"
			}
		}
	}
	if !validState(&state) {
		return ErrUnavailable
	}
	recordsChanged := sealValue(c.key, state.Records) != sealValue(c.key, c.state.Records)
	if recordsChanged && state.SourceSeal == c.state.SourceSeal {
		if !advance(&state.Revision) {
			return ErrUnavailable
		}
		snapshot.Version.Revision = state.Revision
	}
	if state.SourceSeal != c.state.SourceSeal || recordsChanged {
		if err = c.publish(&state, files, rows, values); err != nil {
			return err
		}
	}
	c.state = &state
	c.snapshot = snapshot
	return nil
}

func (c *Catalog) storageCurrentLocked() bool {
	if c.closed || c.failed {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.stateDir, "journal.json")); !os.IsNotExist(err) {
		return false
	}
	key, err := os.ReadFile(filepath.Join(c.stateDir, "seal.key"))
	if err != nil || !bytes.Equal(key, c.key) {
		return false
	}
	persisted, err := loadState(c.stateDir)
	return err == nil && persisted != nil && sealValue(c.key, persisted) == sealValue(c.key, c.state)
}

func (c *Catalog) currentLocked() bool {
	if !c.storageCurrentLocked() || verifySourceMode(c.configPath, c.authDir, c.stateDir) != nil {
		return false
	}
	values, err := sourceValues(c.configPath, c.authDir, c.key)
	return err == nil && sealValue(c.key, values) == c.state.SourceSeal
}

// Snapshot validates source freshness without issuing identities or writing files.
func (c *Catalog) Snapshot() (resource.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() {
		return resource.Snapshot{}, ErrUnavailable
	}
	result := c.snapshot
	result.Resources = append([]resource.Row{}, c.snapshot.Resources...)
	for i := range result.Resources {
		result.Resources[i].SourceBindings = append([]resource.Target(nil), result.Resources[i].SourceBindings...)
		result.Resources[i].Members = append([]string(nil), result.Resources[i].Members...)
	}
	return result, nil
}
func (c *Catalog) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if err := c.lock.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func advance(value *uint64) bool {
	if *value == ^uint64(0) {
		return false
	}
	*value++
	return true
}
