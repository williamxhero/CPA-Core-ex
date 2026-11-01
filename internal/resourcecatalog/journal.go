package resourcecatalog

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

type markerIntent struct {
	Slot  []int  `json:"slot"`
	Field string `json:"field"`
	ID    string `json:"id"`
}
type sourceIntent struct {
	Resources      []string       `json:"resources"`
	BeforeFileSeal string         `json:"before_file_seal"`
	Path           string         `json:"path"`
	JSON           bool           `json:"json"`
	Before         string         `json:"before"`
	After          string         `json:"after"`
	Markers        []markerIntent `json:"markers"`
}
type publication struct {
	ID        string            `json:"transaction_id"`
	Format    int               `json:"format"`
	Next      diskState         `json:"next"`
	Sources   map[string]string `json:"sources"`
	FileSeals map[string]string `json:"file_seals"`
	Writes    []sourceIntent    `json:"writes"`
}
type journalEnvelope struct {
	Data json.RawMessage `json:"data"`
	Seal string          `json:"seal"`
}

func nodeSlot(root, target *yaml.Node, path []int) ([]int, bool) {
	if root == target {
		return append([]int{}, path...), true
	}
	for i, child := range root.Content {
		if slot, ok := nodeSlot(child, target, append(append([]int{}, path...), i)); ok {
			return slot, true
		}
	}
	return nil, false
}
func resolveSlot(root *yaml.Node, path []int) *yaml.Node {
	for _, i := range path {
		if root == nil || i < 0 || i >= len(root.Content) {
			return nil
		}
		root = root.Content[i]
	}
	return root
}

// publish journals only issued markers and sealed preconditions, never credentials.
// The files are individually durable replacements, NOT a cross-file transaction.
func (c *Catalog) publish(state *diskState, files []*sourceFile, rows []*sourceRow, values map[string]string) error {
	if files == nil {
		var err error
		files, _, err = sources(c.configPath, c.authDir)
		if err != nil {
			return err
		}
		current := map[string]string{}
		for _, f := range files {
			current[f.path] = sourceValue(c.key, f)
		}
		if sealValue(c.key, current) != c.state.SourceSeal {
			return ErrConflict
		}
	}
	p := publication{ID: uuid.NewString(), Format: 2, Next: *state, Sources: values, FileSeals: map[string]string{}}
	for _, f := range files {
		p.FileSeals[f.path] = seal(c.key, []byte(f.fileID))
	}
	for _, f := range files {
		if !f.changed {
			continue
		}
		intent := sourceIntent{Path: f.path, JSON: f.json, BeforeFileSeal: seal(c.key, []byte(f.fileID)), Before: seal(c.key, f.original), After: values[f.path]}
		for _, r := range rows {
			if r.file == f && p.Next.Records[r.row.ResourceID] != nil {
				intent.Resources = append(intent.Resources, r.row.ResourceID)
			}
			if r.file != f || !r.fresh {
				continue
			}
			slot, ok := nodeSlot(f.root, r.node, nil)
			if !ok {
				return ErrUnavailable
			}
			intent.Markers = append(intent.Markers, markerIntent{Slot: slot, Field: r.marker, ID: r.row.ResourceID})
		}
		p.Writes = append(p.Writes, intent)
	}
	if err := c.writePublication(&p); err != nil {
		return err
	}
	err := c.finishPublication(&p)
	if err == nil {
		*state = p.Next
	}
	return err
}

func (c *Catalog) writePublication(p *publication) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return ErrUnavailable
	}
	envelope, err := json.Marshal(journalEnvelope{Data: raw, Seal: seal(c.key, raw)})
	if err != nil {
		return ErrUnavailable
	}
	return c.writeFile(filepath.Join(c.stateDir, "journal.json"), envelope)
}

func (c *Catalog) recoverPublication() error {
	raw, err := os.ReadFile(filepath.Join(c.stateDir, "journal.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	var env journalEnvelope
	if json.Unmarshal(raw, &env) != nil || !hmac.Equal([]byte(env.Seal), []byte(seal(c.key, env.Data))) {
		return ErrUnavailable
	}
	var p publication
	if json.Unmarshal(env.Data, &p) != nil || p.Format != 2 || !validID(p.ID) || !validState(&p.Next) {
		return ErrUnavailable
	}
	return c.finishPublication(&p)
}
func (c *Catalog) finishPublication(p *publication) error {
	if len(p.FileSeals) != len(p.Sources) {
		return ErrUnavailable
	}
	for path, content := range p.Sources {
		if !validSeal(content) || !validSeal(p.FileSeals[path]) {
			return ErrUnavailable
		}
	}
	for _, intent := range p.Writes {
		// A journal can write only this catalog's selected config or contained auth files.
		if intent.Path != c.configPath && (!intent.JSON || !containsPath(c.authDir, intent.Path) || !strings.HasSuffix(strings.ToLower(intent.Path), ".json")) {
			return ErrUnavailable
		}
		f, err := readSource(intent.Path, intent.JSON)
		if err != nil {
			return err
		}
		current := seal(c.key, f.original)
		if current == intent.After {
			// Matching bytes alone cannot prove that this is our replacement.
			if seal(c.key, []byte(f.fileID)) != p.FileSeals[intent.Path] {
				return ErrConflict
			}
			continue
		}
		if current != intent.Before || seal(c.key, []byte(f.fileID)) != intent.BeforeFileSeal {
			return ErrConflict
		}
		if !intent.JSON {
			data, _, errNormalize := config.NormalizeConfigLayout(f.original, true)
			if errNormalize != nil {
				return ErrUnavailable
			}
			var doc yaml.Node
			if yaml.Unmarshal(data, &doc) != nil {
				return ErrUnavailable
			}
			f.root = doc.Content[0]
		}
		for _, marker := range intent.Markers {
			n := resolveSlot(f.root, marker.Slot)
			if n == nil || n.Kind != yaml.MappingNode || scalar(n, marker.Field) != "" {
				return ErrUnavailable
			}
			put(n, marker.Field, marker.ID)
		}
		data, errEncode := f.encode()
		if errEncode != nil || seal(c.key, data) != intent.After {
			return ErrUnavailable
		}
		if err = backupSource(f.path+"."+p.Next.InstanceID+"."+strconv.FormatUint(p.Next.Revision, 10)+".catalog-v1-backup", f.original); err != nil {
			return err
		}
		name, errPrepare := prepareWrite(f.path, data)
		if errPrepare != nil {
			return errPrepare
		}
		defer removeTemporaryFile(name)
		fileID, errID := sourceFileID(name)
		if errID != nil {
			return errID
		}
		// Journal the prepared file object's identity BEFORE the rename. Recovery
		// can authorize this object, never an arbitrary copy with equal bytes.
		p.FileSeals[f.path] = seal(c.key, []byte(fileID))
		if err = c.writePublication(p); err != nil {
			return err
		}
		again, errRead := readSource(f.path, intent.JSON)
		if errRead != nil || seal(c.key, again.original) != intent.Before || seal(c.key, []byte(again.fileID)) != intent.BeforeFileSeal {
			return ErrConflict
		}
		if err = replaceFile(name, f.path); err != nil {
			return err
		}
	}
	complete, err := sourceValues(c.configPath, c.authDir, c.key)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for path, content := range p.Sources {
		expected[path] = sealValue(c.key, []string{p.FileSeals[path], content})
	}
	if sealValue(c.key, complete) != sealValue(c.key, expected) {
		return ErrConflict
	}
	for _, intent := range p.Writes {
		for _, id := range intent.Resources {
			if record := p.Next.Records[id]; record != nil && !record.Blocked {
				record.FileSeal = p.FileSeals[intent.Path]
			}
		}
	}
	p.Next.SourceSeal = sealValue(c.key, complete)
	if !validState(&p.Next) {
		return ErrUnavailable
	}
	if err = saveState(c.stateDir, &p.Next); err != nil {
		return err
	}

	if p.Next.Gates != nil && p.Next.Gates.Revision > 0 {
		if err = c.writeFile(c.configPath+".gate-floor-v1", c.gateAnchorBytes(&p.Next)); err != nil {
			return ErrUnavailable
		}
	}
	if err = os.Remove(filepath.Join(c.stateDir, "journal.json")); err != nil {
		return ErrUnavailable
	}
	return syncDirectory(c.stateDir)
}
func backupSource(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return ErrUnavailable
		}
		existing, errRead := os.ReadFile(path)
		if errRead != nil || !bytes.Equal(existing, data) {
			return ErrUnavailable
		}
		return nil
	} else if !os.IsNotExist(err) {
		return ErrUnavailable
	}
	return atomicWrite(path, data)
}
