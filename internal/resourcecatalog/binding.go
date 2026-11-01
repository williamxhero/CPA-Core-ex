package resourcecatalog

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

// BindAuths replaces reserved plugin claims with host-issued source evidence.
// No source migration, upstream request, gate or query is performed here.
func (c *Catalog) BindAuths(path string, data []byte, auths []*coreauth.Auth) error {
	for _, a := range auths {
		if a != nil {
			a.ResourceIdentity = nil
			delete(a.Attributes, coreauth.AttributeResourceID)
			delete(a.Attributes, coreauth.AttributeProviderResourceID)
			delete(a.Metadata, "resource_id")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() {
		return ErrUnavailable
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !containsPath(c.authDir, absolute) {
		return ErrUnavailable
	}
	f, err := readSource(absolute, true)
	if err != nil || !bytes.Equal(f.original, data) {
		return ErrConflict
	}
	if len(auths) != 1 || auths[0] == nil || coreauth.IsPluginVirtualAuth(auths[0]) {
		return nil
	}
	a := auths[0]
	marker := scalar(f.root, "resource_id")
	for _, row := range c.snapshot.Resources {
		if row.ResourceID != marker || row.Identity != "valid" || row.Readiness != "ready" || row.Family == "unsupported" {
			continue
		}
		family := a.Provider
		if family == "gemini" {
			family = "gemini-cli"
		}
		if a.SourcePluginID != "" && knownPluginFamily(a.SourcePluginID) != row.Family {
			return nil
		}
		if row.Family == "qwen" || row.Family == "opencode-go" {
			if knownPluginFamily(a.SourcePluginID) != row.Family {
				return nil
			}
			cfg, errConfig := readSource(c.configPath, false)
			if errConfig != nil {
				return errConfig
			}
			configs := field(field(cfg.root, "plugins"), "configs")
			var pluginConfig *yaml.Node
			if configs != nil {
				for i := 0; i+1 < len(configs.Content); i += 2 {
					if knownPluginFamily(configs.Content[i].Value) == row.Family {
						pluginConfig = configs.Content[i+1]
					}
				}
			}
			source := &sourceRow{file: f, node: f.root, plugin: true, pluginConfig: pluginConfig, row: row}
			expected, errCredentials := pluginCredentials(source)
			if errCredentials != nil {
				return errCredentials
			}
			actual := map[string]any{}
			if storage, ok := a.Storage.(interface{ RawJSON() []byte }); ok {
				if raw := storage.RawJSON(); len(raw) > 0 {
					if json.Unmarshal(raw, &actual) != nil {
						return ErrUnavailable
					}
				}
			} else {
				for k, v := range a.Metadata {
					actual[k] = v
				}
			}
			selected := func(name string) string {
				value, _ := actual[name].(string)
				if strings.TrimSpace(value) == "" {
					value = a.Attributes[name]
				}
				return strings.TrimSpace(value)
			}
			key, endpoint := selected("api_key"), selected("base_url")
			if endpoint == "" {
				endpoint = expected["base-url"].(string)
			}
			if key != expected["api-key"] || strings.TrimRight(endpoint, "/") != expected["base-url"] {
				return nil
			}
		}
		if row.Family != family {
			return nil
		}
		if a.Attributes == nil {
			a.Attributes = map[string]string{}
		}
		if a.Metadata == nil {
			a.Metadata = map[string]any{}
		}
		a.Attributes[coreauth.AttributePath] = absolute
		a.Attributes[coreauth.AttributeSource] = absolute
		a.Attributes[coreauth.AttributeSourceBackend] = coreauth.AuthSourceFile
		a.Attributes[coreauth.AttributeResourceID] = marker
		a.Metadata["resource_id"] = marker
		targets := append([]resource.Target{row.Target}, row.SourceBindings...)
		a.ResourceIdentity = &resource.Binding{Scope: c.snapshot.Version, Targets: targets}
		if setter, ok := a.Storage.(interface{ SetMetadata(map[string]any) }); ok {
			setter.SetMetadata(a.Metadata)
		}
		return nil
	}
	return nil
}

// BindingCurrent checks every lifecycle target; copied runtime claims cannot
// survive a source replacement or a different instance/boot.
func (c *Catalog) BindingCurrent(b *resource.Binding) bool {
	if b == nil || len(b.Targets) == 0 {
		return false
	}
	s, err := c.Snapshot()
	if err != nil || s.Version != b.Scope {
		return false
	}
	for _, target := range b.Targets {
		found := false
		for _, row := range s.Resources {
			if row.Target == target && row.Identity == "valid" && row.Readiness == "ready" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
