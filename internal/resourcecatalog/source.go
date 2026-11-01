package resourcecatalog

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

var families = []string{"gemini", "interactions", "vertex", "codex", "claude", "xai", "meta", "openai-compatibility"}

type sourceFile struct {
	fileID   string
	path     string
	original []byte
	root     *yaml.Node
	json     bool
	changed  bool
}

type sourceRow struct {
	row          resource.Row
	node         *yaml.Node
	file         *sourceFile
	marker       string
	plugin       bool
	pluginConfig *yaml.Node
	projections  []*sourceRow
	fresh        bool
	parent       *sourceRow
}

func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func put(n *yaml.Node, key, value string) {
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	if old := field(n, key); old != nil {
		*old = *v
		return
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}
func scalar(n *yaml.Node, key string) string {
	if v := field(n, key); v != nil {
		return v.Value
	}
	return ""
}
func manual(n *yaml.Node, parent *sourceRow, isJSON bool) (resource.ManualState, error) {
	m := resource.ManualState{}
	if parent != nil {
		m = parent.row.Manual
	}
	if v := field(n, "disabled"); v != nil {
		// Config uses typed YAML booleans; auth metadata accepts JSON booleans only.
		if !isJSON || v.Tag == "!!bool" {
			var disabled bool
			if err := v.Decode(&disabled); err != nil {
				return m, ErrUnavailable
			}
			m.Disabled = m.Disabled || disabled
		}
	}
	if v := field(n, "weight"); v != nil {
		var value any
		if (!isJSON && v.Tag != "!!int") || v.Decode(&value) != nil {
			return m, ErrUnavailable
		}
		weight, err := credentialweight.ParseValue(value)
		if err != nil {
			return m, ErrUnavailable
		}
		m.ZeroWeight = weight == 0
	}
	for _, key := range []string{"excluded-models", "excluded_models"} {
		if v := field(n, key); v != nil && (parent == nil || v.Tag != "!!null") {
			// A non-null child list overrides inherited exclusions, including [].
			m.Excluded = len(v.Content) > 0
		}
	}
	return m, nil
}
func safeFamily(s string) string {
	for _, f := range append(append([]string{}, families...), "antigravity", "gemini-cli", "qwen", "opencode-go", "iflow", "kimi", "kiro", "devin") {
		if s == f {
			return f
		}
	}
	return "unsupported"
}
func readSource(path string, isJSON bool) (*sourceFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	fileID, err := sourceFileID(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	if isJSON && !json.Valid(data) {
		return nil, ErrUnavailable
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, ErrUnavailable
	}
	// Decode to reject duplicate mapping keys, including in JSON envelopes.
	var shape any
	if err = doc.Decode(&shape); err != nil {
		return nil, ErrUnavailable
	}
	afterID, errID := sourceFileID(path)
	if errID != nil || afterID != fileID {
		return nil, ErrUnavailable
	}
	return &sourceFile{fileID: fileID, path: path, original: data, root: doc.Content[0], json: isJSON}, nil
}
func (f *sourceFile) encode() ([]byte, error) {
	if f.json {
		var v any
		if err := f.root.Decode(&v); err != nil {
			return nil, ErrUnavailable
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, ErrUnavailable
		}
		return b, nil
	}
	b, err := yaml.Marshal(f.root)
	if err != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}

// sources enumerates persisted rows before config flattening or auth synthesis.
func sources(configPath, authDir string) ([]*sourceFile, []*sourceRow, error) {
	cfg, err := readSource(configPath, false)
	if err != nil {
		return nil, nil, err
	}
	// Validate native types before publication, without runtime sanitization or
	// filtering: raw keyless, disabled and zero-weight rows still belong here.
	var typed config.Config
	if err = yaml.Unmarshal(cfg.original, &typed); err != nil {
		return nil, nil, ErrUnavailable
	}
	data, _, err := config.NormalizeConfigLayout(cfg.original, true)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, ErrUnavailable
	}
	cfg.root = doc.Content[0]
	files := []*sourceFile{cfg}
	rows := []*sourceRow{}
	appendRow := func(f *sourceFile, n *yaml.Node, kind, family, marker string, parent *sourceRow) (*sourceRow, error) {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil, ErrUnavailable
		}
		manualState, errManual := manual(n, parent, f.json)
		if errManual != nil {
			return nil, errManual
		}
		r := &sourceRow{file: f, node: n, marker: marker, parent: parent, row: resource.Row{Capabilities: resource.RowCapabilities{Inventory: true}, Kind: kind, Family: family, Manual: manualState, Identity: "valid", Readiness: "ready", Routing: "unknown"}}
		r.row.ResourceID = scalar(n, marker)
		if r.row.ResourceID == "" {
			r.fresh = true
			r.row.ResourceID = uuid.NewString()
			put(n, marker, r.row.ResourceID)
			f.changed = true
		}
		if parent != nil {
			r.row.ParentID = parent.row.ResourceID
			parent.row.Members = append(parent.row.Members, r.row.ResourceID)
		}
		rows = append(rows, r)
		return r, nil
	}
	for _, family := range families {
		groups := field(field(cfg.root, "api-keys"), family)
		if groups == nil {
			continue
		}
		if groups.Kind != yaml.SequenceNode {
			return nil, nil, ErrUnavailable
		}
		for _, group := range groups.Content {
			parent, errGroup := appendRow(cfg, group, "provider", family, "resource-id", nil)
			if errGroup != nil {
				return nil, nil, errGroup
			}
			keys := field(group, "keys")
			if keys == nil || keys.Kind != yaml.SequenceNode {
				return nil, nil, ErrUnavailable
			}
			for _, key := range keys.Content {
				if _, errKey := appendRow(cfg, key, "credential", family, "resource-id", parent); errKey != nil {
					return nil, nil, errKey
				}
			}
		}
	}
	if plugins := field(cfg.root, "plugins"); plugins != nil {
		configs := field(plugins, "configs")
		if configs != nil && configs.Kind != yaml.MappingNode {
			return nil, nil, ErrUnavailable
		}
		if configs != nil {
			for i := 0; i+1 < len(configs.Content); i += 2 {
				id, node := configs.Content[i].Value, configs.Content[i+1]
				family := knownPluginFamily(id)
				parent, errPlugin := appendRow(cfg, node, "provider", family, "resource-id", nil)
				if errPlugin != nil {
					return nil, nil, errPlugin
				}
				// Plugin enablement is manual state, not absence from inventory.
				parent.row.Manual.Disabled = scalar(plugins, "enabled") != "true" || scalar(node, "enabled") != "true"
				if family == "unsupported" {
					continue
				}
				parent.plugin = true
				parent.pluginConfig = node
				keys := field(node, "api-keys")
				if keys == nil {
					continue
				}
				if keys.Kind != yaml.SequenceNode {
					return nil, nil, ErrUnavailable
				}
				for _, key := range keys.Content {
					child, errKey := appendRow(cfg, key, "credential", family, "resource-id", parent)
					if errKey != nil {
						return nil, nil, errKey
					}
					child.plugin = true
					child.pluginConfig = node
				}
			}
		}
	}
	paths, err := authSourcePaths(authDir)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	for _, path := range paths {
		f, errFile := readSource(path, true)
		if errFile != nil {
			return nil, nil, errFile
		}
		files = append(files, f)
		_, errRow := appendRow(f, f.root, "credential", safeFamily(scalar(f.root, "type")), "resource_id", nil)
		if errRow != nil {
			return nil, nil, errRow
		}
	}
	for _, r := range rows {
		if !r.file.json || (r.row.Family != "qwen" && r.row.Family != "opencode-go") {
			continue
		}
		r.plugin = true
		for _, parent := range rows {
			if parent.plugin && parent.row.Kind == "provider" && parent.row.Family == r.row.Family {
				r.pluginConfig = parent.node
			}
		}
	}
	return files, rows, nil
}

type sourceSealProjection uint8

const (
	physicalAndContent sourceSealProjection = iota
	contentOnly
)

func sourceValues(configPath, authDir string, key []byte) (map[string]string, error) {
	return collectSourceValues(configPath, authDir, key, physicalAndContent)
}

func sourceContentValues(configPath, authDir string, key []byte) (map[string]string, error) {
	return collectSourceValues(configPath, authDir, key, contentOnly)
}

func sourceValue(key []byte, f *sourceFile) string {
	return sealValue(key, []string{seal(key, []byte(f.fileID)), seal(key, f.original)})
}

func collectSourceValues(configPath, authDir string, key []byte, projection sourceSealProjection) (map[string]string, error) {
	result := map[string]string{}
	collect := func(path string, isJSON bool) error {
		f, err := readSource(path, isJSON)
		if err != nil {
			return err
		}
		if projection == physicalAndContent {
			result[path] = sourceValue(key, f)
		} else {
			result[path] = seal(key, f.original)
		}
		return nil
	}
	if err := collect(configPath, false); err != nil {
		return nil, err
	}
	paths, err := authSourcePaths(authDir)
	if err != nil {
		// Preserve each existing projection's source-coverage error contract.
		if projection == physicalAndContent {
			return nil, ErrUnavailable
		}
		return nil, err
	}
	for _, path := range paths {
		if errRead := collect(path, true); errRead != nil {
			return nil, errRead
		}
	}
	return result, nil
}

// The token store loads recursively; a complete source inventory must do the same.
func authSourcePaths(authDir string) ([]string, error) {
	paths := []string{}
	err := filepath.WalkDir(authDir, func(path string, entry fs.DirEntry, errWalk error) error {
		if errWalk != nil {
			return ErrUnavailable
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsupported
		}
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}
