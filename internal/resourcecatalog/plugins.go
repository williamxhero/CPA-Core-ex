package resourcecatalog

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func pluginCredentials(r *sourceRow) (map[string]any, error) {
	var key, endpoint string
	if r.file.json {
		key = scalar(r.node, "api_key")
		endpoint = scalar(r.node, "base_url")
	} else if r.row.Kind == "credential" {
		key = os.ExpandEnv(scalar(r.node, "value"))
	}
	key = strings.TrimSpace(key)
	if strings.TrimSpace(endpoint) == "" {
		var value *yaml.Node
		if r.pluginConfig != nil {
			value = field(r.pluginConfig, "base-url")
		}
		if value != nil && value.Tag != "!!null" {
			if value.Decode(&endpoint) != nil {
				return nil, ErrUnavailable
			}
		} else if r.row.Family == "qwen" {
			endpoint = "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
		} else {
			endpoint = "https://opencode.ai/zen/go/v1"
		}
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	return map[string]any{"api-key": key, "base-url": endpoint}, nil
}

// Known plugin schemas are host-owned adapters, not a generic plugin ABI.
func knownPluginFamily(id string) string {
	switch id {
	case "cpa-credential-qwen":
		return "qwen"
	case "cpa-credential-opencode":
		return "opencode-go"
	default:
		return "unsupported"
	}
}

// Compare effective secrets only to prove a projection, never to issue identity.
// Multiple matching files or members are ambiguous, not deduplicated by labels.
func bindPluginProjections(rows []*sourceRow, key []byte) error {
	configs, files := map[string][]*sourceRow{}, map[string][]*sourceRow{}
	for _, r := range rows {
		if !r.plugin || r.row.Kind != "credential" {
			continue
		}
		credentials, err := pluginCredentials(r)
		if err != nil {
			return err
		}
		if credentials["api-key"] == "" {
			r.row.Readiness = "not_ready"
			r.row.BindingState = "missing_credential"
			continue
		}
		proof := sealValue(key, []any{r.row.Family, credentials})
		if r.file.json {
			files[proof] = append(files[proof], r)
			r.row.BindingState = "standalone"
		} else {
			configs[proof] = append(configs[proof], r)
			r.row.BindingState = "unmaterialized"
		}
	}
	for proof, members := range configs {
		projections := files[proof]
		if len(members) == 1 && len(projections) == 1 {
			members[0].projections = projections
			projections[0].projections = members
			members[0].row.BindingState = "verified_projection"
			projections[0].row.BindingState = "verified_projection"
		} else if len(members) > 1 || len(projections) > 1 {
			for _, r := range append(append([]*sourceRow{}, members...), projections...) {
				r.row.BindingState = "ambiguous_projection"
				r.row.Readiness = "not_ready"
			}
		}
	}
	return nil
}
