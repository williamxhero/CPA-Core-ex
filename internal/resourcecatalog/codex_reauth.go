package resourcecatalog

import (
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// SaveReauthenticatedCodex publishes a fresh, verified OAuth grant in the
// administrator's existing local slot. The caller holds the Codex file lock
// and supplies the account ID from the fresh OAuth exchange, never from a
// management request or a credential upload.
func (c *Catalog) SaveReauthenticatedCodex(path, verifiedAccountID string, data map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	path, err := filepath.Abs(path)
	if err != nil || !containsPath(c.authDir, path) {
		return ErrConflict
	}
	before, err := readSource(path, true)
	if err != nil || verifiedAccountID == "" || scalar(before.root, "type") != "codex" ||
		scalar(before.root, "account_id") != verifiedAccountID || data["account_id"] != verifiedAccountID ||
		data["type"] != "codex" {
		return ErrConflict
	}
	marker := scalar(before.root, "resource_id")
	record := c.state.Records[marker]
	if record == nil || record.Deleted || record.Kind != "credential" || record.Family != "codex" {
		return ErrConflict
	}
	// Only a unique, already-observed native file can be repaired. Never adopt
	// a copied marker, a deleted slot, or two competing files with one marker.
	var matched *resource.Row
	for i := range c.snapshot.Resources {
		row := &c.snapshot.Resources[i]
		if row.ResourceID != marker {
			continue
		}
		if matched != nil {
			return ErrConflict
		}
		matched = row
	}
	if matched == nil || matched.Target != record.Target {
		return ErrConflict
	}
	oldSeal, _, err := rowSeals(c.key, &sourceRow{file: before, node: before.root, marker: "resource_id", row: *matched})
	fileSeal := seal(c.key, []byte(before.fileID))
	if err != nil || oldSeal != record.CredentialSeal ||
		(record.Blocked && record.FileSeal == fileSeal) || (!record.Blocked && record.FileSeal != fileSeal) {
		return ErrConflict
	}
	access, _ := data["access_token"].(string)
	refresh, _ := data["refresh_token"].(string)
	if strings.TrimSpace(access) == "" || strings.TrimSpace(refresh) == "" {
		return ErrConflict
	}
	data["resource_id"] = marker
	if err = codex.WriteJSONFileAtomic(path, data); err != nil {
		return err
	}
	after, err := readSource(path, true)
	if err != nil || scalar(after.root, "resource_id") != marker ||
		scalar(after.root, "account_id") != verifiedAccountID ||
		scalar(after.root, "access_token") != access || scalar(after.root, "refresh_token") != refresh {
		return ErrConflict
	}
	c.ownedFileReplacements = map[string]string{marker: seal(c.key, []byte(after.fileID))}
	c.reauthenticatedCodex = marker
	defer func() {
		c.ownedFileReplacements = nil
		c.reauthenticatedCodex = ""
	}()
	return c.reconcileLocked()
}
