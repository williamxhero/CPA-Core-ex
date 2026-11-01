package resourcecatalog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// SaveAuthFile is an owned write, not permission to adopt copied envelopes.
// Existing files retain their physical identity; enrollment of new files uses
// the ordinary durable marker journal before any runtime auth can be published.
func (c *Catalog) SaveAuthFile(path string, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() {
		return nil, ErrUnavailable
	}
	path, err := filepath.Abs(path)
	if err != nil || !containsPath(c.authDir, path) || !strings.HasSuffix(strings.ToLower(path), ".json") {
		return nil, ErrUnavailable
	}
	var proposed map[string]any
	if json.Unmarshal(data, &proposed) != nil || proposed == nil {
		return nil, ErrUnavailable
	}
	existing, errExisting := readSource(path, true)
	exists := errExisting == nil
	if !exists {
		if _, errStat := os.Lstat(path); !os.IsNotExist(errStat) {
			return nil, ErrUnavailable
		}
	}
	incoming, _ := proposed["resource_id"].(string)
	if exists {
		if proposedType, ok := proposed["type"].(string); !ok || strings.TrimSpace(proposedType) != scalar(existing.root, "type") {
			return nil, ErrConflict
		}
		marker := scalar(existing.root, "resource_id")
		record := c.state.Records[marker]
		if record == nil || record.Blocked || record.Deleted || record.FileSeal != seal(c.key, []byte(existing.fileID)) {
			return nil, ErrConflict
		}
		if incoming != "" && incoming != marker {
			return nil, ErrConflict
		}
		proposed["resource_id"] = marker
		for _, name := range []string{"disabled", "weight", "excluded_models", "excluded-models"} {
			if _, provided := proposed[name]; !provided {
				if value := field(existing.root, name); value != nil {
					var decoded any
					if value.Decode(&decoded) != nil {
						return nil, ErrUnavailable
					}
					proposed[name] = decoded
				}
			}
		}
	} else if incoming != "" {
		return nil, ErrConflict
	}
	encoded, err := json.Marshal(proposed)
	if err != nil {
		return nil, ErrUnavailable
	}
	if exists && bytes.Equal(encoded, existing.original) {
		return append([]byte(nil), existing.original...), nil
	}
	flags := os.O_WRONLY
	if !exists {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	handleInfo, errHandle := file.Stat()
	if errHandle != nil {
		_ = file.Close()
		return nil, ErrUnavailable
	}
	writeErr := func() error {
		pathInfo, errPath := os.Lstat(path)
		if errPath != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(handleInfo, pathInfo) {
			return ErrConflict
		}
		if exists {
			current, errRead := readSource(path, true)
			if errRead != nil || current.fileID != existing.fileID || !bytes.Equal(current.original, existing.original) {
				return ErrConflict
			}
			if errTruncate := file.Truncate(0); errTruncate != nil {
				return ErrUnavailable
			}
		}
		if _, errWrite := file.Write(encoded); errWrite != nil {
			return ErrUnavailable
		}
		if errSync := file.Sync(); errSync != nil {
			return ErrUnavailable
		}
		return nil
	}()
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, ErrUnavailable
	}
	pathInfo, errPath := os.Lstat(path)
	if errPath != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(handleInfo, pathInfo) {
		return nil, ErrConflict
	}
	if exists {
		id, errID := sourceFileID(path)
		if errID != nil || id != existing.fileID {
			return nil, ErrConflict
		}
	}
	if err = c.reconcileLocked(); err != nil {
		return nil, err
	}
	enrolled, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	return enrolled, nil
}
