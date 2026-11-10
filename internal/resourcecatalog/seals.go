package resourcecatalog

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"

	"gopkg.in/yaml.v3"
)

// Seals detect changes only. They never generate or match resource identities.
func seal(key, data []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}
func sealValue(key []byte, v any) string { data, _ := json.Marshal(v); return seal(key, data) }
func loadSealKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "seal.key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, ErrUnavailable
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	for _, name := range []string{"catalog.json", "journal.json"} {
		if _, errStat := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(errStat) {
			return nil, ErrUnavailable
		}
	}
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, ErrUnavailable
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	errClose := f.Close()
	if err != nil || errClose != nil {
		return nil, ErrUnavailable
	}
	return key, nil
}
func nodeValue(n *yaml.Node, omit map[string]bool) map[string]any {
	v := map[string]any{}
	if n == nil {
		return v
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if omit[k] {
			continue
		}
		var value any
		_ = n.Content[i+1].Decode(&value)
		v[k] = value
	}
	return v
}

// Config credentials follow native null inheritance and the runtime's typed
// normalization. Compatibility children use their provider's endpoint/headers.
func effectiveConfigCredentials(r *sourceRow) (map[string]any, error) {
	var apiKey, baseURL string
	var headers map[string]string
	for _, name := range []string{"api-key", "base-url", "headers"} {
		value := field(r.node, name)
		if r.parent != nil && name != "api-key" && (r.row.Family == "openai-compatibility" || value == nil || value.Tag == "!!null") {
			value = field(r.parent.node, name)
		}
		if value == nil || value.Tag == "!!null" {
			continue
		}
		var errDecode error
		switch name {
		case "api-key":
			errDecode = value.Decode(&apiKey)
		case "base-url":
			errDecode = value.Decode(&baseURL)
		case "headers":
			errDecode = value.Decode(&headers)
		}
		if errDecode != nil {
			return nil, ErrUnavailable
		}
	}
	credentials := map[string]any{}
	if apiKey = strings.TrimSpace(apiKey); apiKey != "" {
		credentials["api-key"] = apiKey
	}
	baseURL = strings.TrimSpace(baseURL)
	if r.row.Family == "meta" && baseURL == "" {
		baseURL = "https://api.meta.ai/v1"
	}
	if baseURL != "" {
		credentials["base-url"] = baseURL
	}
	if headers = config.NormalizeHeaders(headers); len(headers) != 0 {
		credentials["headers"] = headers
	}
	return credentials, nil
}

func rowSeals(key []byte, r *sourceRow) (string, string, error) {
	// Qwen quota enrollment refers to these generations; it cannot itself rotate
	// them. Query-source revisions still fence enrollment edits independently.
	// Derived projection bookkeeping is not administrator configuration, so it
	// must not advance the generation that enrollment pins.
	queryEnrollment := r.plugin && r.row.Family == "qwen"
	conf := nodeValue(r.node, map[string]bool{r.marker: true, "keys": true, "api-keys": true, "quota-resource-bindings": queryEnrollment})
	// The file store materializes the runtime default disabled:false on the
	// first save. Treat omitted and explicit false as the same configuration;
	// an explicit true still remains in the seal and rotates the generation.
	if queryEnrollment && r.file.json {
		if disabled, ok := conf["disabled"].(bool); ok && !disabled {
			delete(conf, "disabled")
		}
	}
	if r.plugin && !queryEnrollment {
		ids := []string{}
		for _, related := range r.projections {
			ids = append(ids, related.row.ResourceID)
		}
		conf["host-source-bindings"] = ids
		conf["host-binding-state"] = r.row.BindingState
	}
	if r.plugin && r.file.json {
		conf["host-plugin-config"] = nodeValue(r.pluginConfig, map[string]bool{"resource-id": true, "api-keys": true, "quota-resource-bindings": queryEnrollment})
	}
	var parent any
	if r.parent != nil {
		parent = nodeValue(r.parent.node, map[string]bool{"resource-id": true, "keys": true, "api-keys": true, "quota-resource-bindings": queryEnrollment})
	}
	var credentials map[string]any
	if r.plugin {
		var err error
		credentials, err = pluginCredentials(r)
		if err != nil {
			return "", "", err
		}
	} else if r.file.json {
		credentials = nodeValue(r.node, map[string]bool{r.marker: true, "name": true, "label": true, "disabled": true, "weight": true, "excluded_models": true, "excluded-models": true, "priority": true, "prefix": true})
	} else {
		var err error
		credentials, err = effectiveConfigCredentials(r)
		if err != nil {
			return "", "", err
		}
	}
	return sealValue(key, credentials), sealValue(key, []any{r.row.Kind, r.row.Family, conf, parent, r.row.ParentID}), nil
}
