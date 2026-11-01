package config

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResourceBinding carries issued source markers, never routing identity or keys.
// Group fields exist only at the flattened legacy boundary.
type ResourceBinding struct {
	ResourceID        string `yaml:"resource-id,omitempty" json:"resource-id,omitempty"`
	ResourceGroupID   string `yaml:"resource-group-id,omitempty" json:"-"`
	ResourceGroupName string `yaml:"resource-group-name,omitempty" json:"-"`
	// ResourceSourceRef is transient manual-save provenance, NOT durable identity.
	ResourceSourceRef string `yaml:"resource-source-ref,omitempty" json:"-"`
}

// A save records where each input row was emitted, including unmarked new rows.
// These slots are an owned-write receipt, never a way to match an external source.
type resourceSaveSlot struct{ group, child int }
type resourceSaveProjection map[string][]resourceSaveSlot

func resourceWriterBindings(cfg *Config) map[string][]*ResourceBinding {
	out := make(map[string][]*ResourceBinding)
	for i := range cfg.GeminiKey {
		out["gemini"] = append(out["gemini"], &cfg.GeminiKey[i].ResourceBinding)
	}
	for i := range cfg.InteractionsKey {
		out["interactions"] = append(out["interactions"], &cfg.InteractionsKey[i].ResourceBinding)
	}
	for i := range cfg.VertexCompatAPIKey {
		out["vertex"] = append(out["vertex"], &cfg.VertexCompatAPIKey[i].ResourceBinding)
	}
	for i := range cfg.CodexKey {
		out["codex"] = append(out["codex"], &cfg.CodexKey[i].ResourceBinding)
	}
	for i := range cfg.ClaudeKey {
		out["claude"] = append(out["claude"], &cfg.ClaudeKey[i].ResourceBinding)
	}
	for i := range cfg.XAIKey {
		out["xai"] = append(out["xai"], &cfg.XAIKey[i].ResourceBinding)
	}
	for i := range cfg.MetaKey {
		out["meta"] = append(out["meta"], &cfg.MetaKey[i].ResourceBinding)
	}
	for i := range cfg.OpenAICompatibility {
		group := &cfg.OpenAICompatibility[i]
		out["openai-compatibility"] = append(out["openai-compatibility"], &group.ResourceBinding)
		for j := range group.APIKeyEntries {
			out["openai-compatibility"] = append(out["openai-compatibility"], &group.APIKeyEntries[j].ResourceBinding)
		}
	}
	return out
}

// groupLegacyKeys emits exactly one group per input row, before filtered rows.
func (p resourceSaveProjection) ungrouped(provider string, keys *yaml.Node) {
	if keys == nil {
		return
	}
	for i, key := range keys.Content {
		if provider == "openai-compatibility" {
			p[provider] = append(p[provider], resourceSaveSlot{i, -1})
			if children := yamlPath(key, "api-key-entries"); children != nil {
				for j := range children.Content {
					p[provider] = append(p[provider], resourceSaveSlot{i, j})
				}
			}
		} else {
			p[provider] = append(p[provider], resourceSaveSlot{i, 0})
		}
	}
}

func (p resourceSaveProjection) unchanged(provider string, input, groups *yaml.Node) error {
	known := make(map[string]resourceSaveSlot)
	for i, group := range groups.Content {
		ref, err := resourceGroupSourceRef(group, i)
		if err != nil {
			return err
		}
		known[ref] = resourceSaveSlot{i, -1}
		if keys := yamlPath(group, "keys"); keys != nil {
			for j := range keys.Content {
				known[ref+"/"+strconv.Itoa(j)] = resourceSaveSlot{i, j}
			}
		}
	}
	var rows []*yaml.Node
	if input != nil {
		for _, row := range input.Content {
			rows = append(rows, row)
			if provider == "openai-compatibility" {
				if keys := yamlPath(row, "api-key-entries"); keys != nil {
					rows = append(rows, keys.Content...)
				}
			}
		}
	}
	for _, row := range rows {
		slot, ok := known[mappingScalarValue(row, "resource-source-ref")]
		if !ok {
			return fmt.Errorf("resource source requires manual-save provenance")
		}
		p[provider] = append(p[provider], slot)
	}
	return nil
}

// Prepare all metadata before I/O, but publish it only after a successful write.
func (p resourceSaveProjection) prepare(cfg *Config, data []byte) (string, map[*ResourceBinding]ResourceBinding, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return "", nil, err
	}
	root := document.Content[0]
	ref, err := resourceDocumentSourceRef(root)
	if err != nil || ref == "" {
		return ref, nil, err
	}
	updates := make(map[*ResourceBinding]ResourceBinding)
	for family, bindings := range resourceWriterBindings(cfg) {
		groups := yamlPath(root, "api-keys."+family)
		if groups == nil || !resourceProjectionRequired(root, groups) {
			continue
		}
		slots := p[family]
		if len(slots) != len(bindings) {
			return "", nil, fmt.Errorf("resource save projection is incomplete")
		}
		for i, slot := range slots {
			if slot.group < 0 || slot.group >= len(groups.Content) {
				return "", nil, fmt.Errorf("resource save projection is incomplete")
			}
			group := groups.Content[slot.group]
			next, errRef := resourceGroupSourceRef(group, slot.group)
			if errRef != nil {
				return "", nil, errRef
			}
			binding := *bindings[i]
			binding.ResourceID = mappingScalarValue(group, "resource-id")
			if slot.child >= 0 {
				keys := yamlPath(group, "keys")
				if keys == nil || slot.child >= len(keys.Content) {
					return "", nil, fmt.Errorf("resource save projection is incomplete")
				}
				next += "/" + strconv.Itoa(slot.child)
				binding.ResourceID = mappingScalarValue(keys.Content[slot.child], "resource-id")
				if family != "openai-compatibility" {
					binding.ResourceGroupID = mappingScalarValue(group, "resource-id")
					binding.ResourceGroupName = mappingScalarValue(group, "name")
				}
			}
			binding.ResourceSourceRef = next
			updates[bindings[i]] = binding
		}
	}
	return ref, updates, nil
}

// Keep ordinary unmarked opt-out configs on their existing YAML/runtime boundary.
func resourceProjectionRequired(root, groups *yaml.Node) bool {
	var enabled bool
	if setting := yamlPath(root, "resource-catalog.enabled"); setting != nil && setting.Decode(&enabled) == nil && enabled {
		return true
	}
	for _, group := range groups.Content {
		if yamlPath(group, "resource-id") != nil {
			return true
		}
		if keys := yamlPath(group, "keys"); keys != nil {
			for _, key := range keys.Content {
				if yamlPath(key, "resource-id") != nil {
					return true
				}
			}
		}
	}
	return false
}

// Deletions carry no remaining child reference. Pin the entire source document
// so a stale view cannot delete entries that were never represented in that view.
func resourceDocumentSourceRef(root *yaml.Node) (string, error) {
	if configs := yamlPath(root, "plugins.configs"); configs != nil && resourceProjectionRequired(root, configs) {
		data, err := yaml.Marshal(root)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", sha256.Sum256(data)), nil
	}
	for _, family := range v8KeyFamilies {
		groups := yamlPath(root, "api-keys."+family.current)
		if groups == nil || !resourceProjectionRequired(root, groups) {
			continue
		}
		data, err := yaml.Marshal(root)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", sha256.Sum256(data)), nil
	}
	return "", nil
}

// Empty non-null values override shared defaults. Nullable pointer settings have
// no per-child "use global" spelling while a group override exists.
func emptySharedKeyOverride(field string) *yaml.Node {
	switch field {
	case "headers":
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	case "models", "excluded-models", "request-scoped-errors":
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	case "priority":
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "0"}
	case "prefix", "proxy-url":
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}
	}
	return nil
}

// Bind a reversible source projection to the exact group document. Its slot is
// local provenance only: no catalog or observation may use it as an identity.
func resourceGroupSourceRef(group *yaml.Node, index int) (string, error) {
	data, err := yaml.Marshal(group)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x/%d", sha256.Sum256(data), index), nil
}

// regroupResourceKeys reverses source provenance, never durable-ID/name/key matching.
func regroupResourceKeys(keys *yaml.Node, provider string, original, baseline *yaml.Node, projection resourceSaveProjection) (*yaml.Node, error) {
	if provider == "openai-compatibility" {
		out := groupLegacyKeys(keys, provider)
		if err := preserveFilteredCompatibility(out, original, baseline, keys); err != nil {
			return nil, err
		}
		projection.ungrouped(provider, keys)
		return out, nil
	}
	known := map[string]*yaml.Node{}
	sourceRefs := map[*yaml.Node]string{}
	knownKeyRefs := map[string]bool{}
	for index, g := range original.Content {
		id, err := resourceGroupSourceRef(g, index)
		if err != nil {
			return nil, err
		}
		sourceRefs[g] = id
		if list := yamlPath(g, "keys"); list != nil {
			for keyIndex := range list.Content {
				knownKeyRefs[id+"/"+strconv.Itoa(keyIndex)] = true
			}
		}
		known[id] = g
	}
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	groups := map[string]*yaml.Node{}
	groupSlots := map[string]int{}
	for _, key := range keys.Content {
		ref := mappingScalarValue(key, "resource-source-ref")
		if ref != "" && !knownKeyRefs[ref] {
			return nil, fmt.Errorf("resource source changed; reload before saving")
		}
		if ref == "" && (mappingScalarValue(key, "resource-group-id") != "" || mappingScalarValue(key, "resource-id") != "") {
			return nil, fmt.Errorf("resource source requires manual-save provenance")
		}
		id := ""
		if last := strings.LastIndex(ref, "/"); last >= 0 {
			id = ref[:last]
		}
		source := known[id]
		if source == nil {
			copy := deepCopyNode(key)
			deleteYAMLPath(copy, "resource-group-id")
			deleteYAMLPath(copy, "resource-group-name")
			deleteYAMLPath(copy, "resource-source-ref")
			fallback := groupLegacyKeys(&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{copy}}, provider)
			projection[provider] = append(projection[provider], resourceSaveSlot{len(out.Content), 0})
			out.Content = append(out.Content, fallback.Content...)
			continue
		}
		group := groups[id]
		base := mappingScalarValue(key, "base-url")
		if group == nil {
			group = deepCopyNode(source)
			if value := copyYAMLPathValue(key, "base-url"); value != nil {
				setYAMLPath(group, "base-url", value)
			} else {
				// An omitted typed endpoint is an explicit clear, not inheritance.
				deleteYAMLPath(group, "base-url")
			}
			setYAMLPath(group, "keys", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			groups[id] = group
			groupSlots[id] = len(out.Content)
			out.Content = append(out.Content, group)
		} else if mappingScalarValue(group, "base-url") != base {
			return nil, fmt.Errorf("resource group has conflicting endpoints")
		}
		copy := deepCopyNode(key)
		for _, field := range []string{"base-url", "resource-group-id", "resource-group-name", "resource-source-ref"} {
			deleteYAMLPath(copy, field)
		}
		list := yamlPath(group, "keys")
		projection[provider] = append(projection[provider], resourceSaveSlot{groupSlots[id], len(list.Content)})
		list.Content = append(list.Content, copy)
	}
	// A filtered runtime row is not an explicit source deletion.
	baselineRefs := map[string]bool{}
	// A prior owned edit may have made an input row runtime-filtered. It still
	// carries proven provenance and must not also be copied as an untouched row.
	for _, key := range keys.Content {
		baselineRefs[mappingScalarValue(key, "resource-source-ref")] = true
	}
	if baseline != nil {
		for _, key := range baseline.Content {
			marker := mappingScalarValue(key, "resource-source-ref")
			baselineRefs[marker] = true
		}
	}
	for _, source := range original.Content {
		id := sourceRefs[source]
		list := yamlPath(source, "keys")
		if list == nil {
			continue
		}
		kept := []*yaml.Node{}
		for keyIndex, key := range list.Content {
			marker := id + "/" + strconv.Itoa(keyIndex)
			if !baselineRefs[marker] {
				copy := deepCopyNode(key)
				for i := 0; i+1 < len(source.Content); i += 2 {
					field := source.Content[i].Value
					if value := yamlPath(copy, field); sharedKeyFields[field] && (value == nil || value.Tag == "!!null") {
						setYAMLPath(copy, field, deepCopyNode(source.Content[i+1]))
					}
				}
				kept = append(kept, copy)
			}
		}
		if len(kept) == 0 && len(list.Content) != 0 {
			continue
		}
		group := groups[id]
		if group == nil {
			group = deepCopyNode(source)
			setYAMLPath(group, "keys", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			groups[id] = group
			out.Content = append(out.Content, group)
		}
		target := yamlPath(group, "keys")
		target.Content = append(target.Content, kept...)
	}
	for _, group := range groups {
		for field := range sharedKeyFields {
			if yamlPath(group, field) == nil {
				continue
			}
			for _, key := range yamlPath(group, "keys").Content {
				if yamlPath(key, field) != nil {
					continue
				}
				if empty := emptySharedKeyOverride(field); empty != nil {
					setYAMLPath(key, field, empty)
				} else {
					// Materialized siblings keep their effective settings when a
					// typed edit clears this child's nullable override.
					deleteYAMLPath(group, field)
				}
			}
		}
	}
	return out, nil
}

func preserveFilteredCompatibility(out, original, baseline, input *yaml.Node) error {
	knownGroups := map[string]bool{}
	knownChildren := map[string]bool{}
	for index, source := range original.Content {
		ref, err := resourceGroupSourceRef(source, index)
		if err != nil {
			return err
		}
		knownGroups[ref] = true
		if children := yamlPath(source, "keys"); children != nil {
			for i := range children.Content {
				knownChildren[ref+"/"+strconv.Itoa(i)] = true
			}
		}
	}
	marker := func(group *yaml.Node) string { return mappingScalarValue(group, "resource-source-ref") }

	represented := map[string]*yaml.Node{}
	if baseline != nil {
		for _, g := range baseline.Content {
			represented[marker(g)] = g
		}
	}
	generated := map[string]*yaml.Node{}
	generatedInputs := map[string]*yaml.Node{}
	for index, g := range out.Content {
		entry := input.Content[index]
		ref := marker(entry)
		if ref != "" && !knownGroups[ref] {
			return fmt.Errorf("resource source changed; reload before saving")
		}
		if ref == "" && mappingScalarValue(entry, "resource-id") != "" {
			return fmt.Errorf("resource source requires manual-save provenance")
		}
		if children := yamlPath(entry, "api-key-entries"); children != nil {
			for _, child := range children.Content {
				childRef := marker(child)
				if childRef != "" && !knownChildren[childRef] {
					return fmt.Errorf("resource source changed; reload before saving")
				}
				if childRef != "" && !strings.HasPrefix(childRef, ref+"/") {
					return fmt.Errorf("resource source has conflicting provider provenance")
				}
				if childRef == "" && mappingScalarValue(child, "resource-id") != "" {
					return fmt.Errorf("resource source requires manual-save provenance")
				}
			}
		}
		generated[marker(entry)] = g
		generatedInputs[marker(entry)] = entry
	}
	for index, source := range original.Content {
		id, err := resourceGroupSourceRef(source, index)
		if err != nil {
			return err
		}
		before := represented[id]
		after := generated[id]
		if before == nil && after == nil {
			out.Content = append(out.Content, deepCopyNode(source))
			continue
		}
		if after == nil {
			continue
		}
		baselineKeys := map[string]bool{}
		for _, entry := range []*yaml.Node{before, generatedInputs[id]} {
			if entry == nil {
				continue
			}
			if entries := yamlPath(entry, "api-key-entries"); entries != nil {
				for _, key := range entries.Content {
					baselineKeys[marker(key)] = true
				}
			}
		}
		sourceKeys := yamlPath(source, "keys")
		if sourceKeys == nil {
			continue
		}
		afterKeys := yamlPath(after, "keys")
		for keyIndex, key := range sourceKeys.Content {
			if !baselineKeys[id+"/"+strconv.Itoa(keyIndex)] {
				afterKeys.Content = append(afterKeys.Content, deepCopyNode(key))
			}
		}
	}
	return nil
}

// Receipts are local to a loaded writer and replaced, never mutated, after a
// successful save. Runtime clones can share them without rebasing older writers.
type resourceSourceRow struct{ id, ref, parent string }
type resourceSourceReceipt map[string][]resourceSourceRow

func resourceSourceRows(cfg *Config, updates map[*ResourceBinding]ResourceBinding) resourceSourceReceipt {
	if cfg.ResourceCatalog.sourceDocument == "" {
		return nil
	}
	out := make(resourceSourceReceipt)
	value := func(binding *ResourceBinding) ResourceBinding {
		if next, ok := updates[binding]; ok {
			return next
		}
		return *binding
	}
	for family, bindings := range resourceWriterBindings(cfg) {
		if family == "openai-compatibility" {
			continue
		}
		for _, binding := range bindings {
			row := value(binding)
			out[family] = append(out[family], resourceSourceRow{id: row.ResourceID, ref: row.ResourceSourceRef})
		}
	}
	for i := range cfg.OpenAICompatibility {
		group := &cfg.OpenAICompatibility[i]
		binding := value(&group.ResourceBinding)
		parent := binding.ResourceSourceRef
		out["openai-compatibility"] = append(out["openai-compatibility"], resourceSourceRow{id: binding.ResourceID, ref: parent})
		for j := range group.APIKeyEntries {
			child := value(&group.APIKeyEntries[j].ResourceBinding)
			out["openai-compatibility"] = append(out["openai-compatibility"], resourceSourceRow{id: child.ResourceID, ref: child.ResourceSourceRef, parent: parent})
		}
	}
	return out
}

// JSON omits private provenance, and compatibility GET also omits the provider
// marker. Resolve only unique addresses in this writer's fenced receipt. These
// addresses recover source context, not issuance, validity or account continuity.
func restoreResourceManagementReferences(root *yaml.Node, receipt resourceSourceReceipt) error {
	for _, family := range v8KeyFamilies {
		keys := yamlPath(root, family.old)
		if keys == nil {
			continue
		}
		compat := family.current == "openai-compatibility"
		known := receipt[family.current]
		lookup := func(id string, child bool, parent string) (resourceSourceRow, error) {
			var match resourceSourceRow
			count := 0
			for _, row := range known {
				if row.id == id && id != "" && (row.parent != "") == child && (parent == "" || row.parent == parent) {
					match = row
					count++
				}
			}
			if count != 1 || match.ref == "" {
				return resourceSourceRow{}, fmt.Errorf("resource source requires unambiguous manual-save provenance")
			}
			return match, nil
		}
		used := make(map[string]bool)
		claim := func(node *yaml.Node, ref string) error {
			if ref == "" {
				return nil
			}
			if used[ref] {
				return fmt.Errorf("resource source has conflicting manual-save provenance")
			}
			used[ref] = true
			setYAMLPath(node, "resource-source-ref", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ref})
			return nil
		}
		for _, key := range keys.Content {
			ref := mappingScalarValue(key, "resource-source-ref")
			id := mappingScalarValue(key, "resource-id")
			if ref == "" && id != "" {
				row, err := lookup(id, false, "")
				if err != nil {
					return err
				}
				ref = row.ref
			}
			children := yamlPath(key, "api-key-entries")
			if compat && ref == "" && children != nil {
				for _, child := range children.Content {
					childID := mappingScalarValue(child, "resource-id")
					if childID == "" {
						continue
					}
					row, err := lookup(childID, true, "")
					if err != nil {
						return err
					}
					if ref != "" && ref != row.parent {
						return fmt.Errorf("resource source has conflicting provider provenance")
					}
					ref = row.parent
				}
				if ref != "" {
					for _, row := range known {
						if row.ref == ref && row.parent == "" {
							setYAMLPath(key, "resource-id", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: row.id})
						}
					}
				}
			}
			if err := claim(key, ref); err != nil {
				return err
			}
			if !compat || children == nil {
				continue
			}
			for _, child := range children.Content {
				childRef := mappingScalarValue(child, "resource-source-ref")
				childID := mappingScalarValue(child, "resource-id")
				if childRef == "" && childID != "" {
					if ref == "" {
						return fmt.Errorf("resource source requires provider provenance")
					}
					row, err := lookup(childID, true, ref)
					if err != nil {
						return err
					}
					childRef = row.ref
				}
				if err := claim(child, childRef); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// A receipt includes rows that this writer emitted before they became filtered.
// Fresh disk parsing cannot recover that ownership or turn other rows into deletes.
func (r resourceSourceReceipt) projection(family string) *yaml.Node {
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	groups := make(map[string]*yaml.Node)
	for _, row := range r[family] {
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setYAMLPath(node, "resource-source-ref", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: row.ref})
		if row.parent == "" {
			out.Content = append(out.Content, node)
			if family == "openai-compatibility" {
				setYAMLPath(node, "api-key-entries", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
				groups[row.ref] = node
			}
		} else if group := groups[row.parent]; group != nil {
			keys := yamlPath(group, "api-key-entries")
			keys.Content = append(keys.Content, node)
		}
	}
	return out
}

func resourceSourceReferences(rows *yaml.Node) map[string]bool {
	out := make(map[string]bool)
	if rows != nil {
		for _, row := range rows.Content {
			out[mappingScalarValue(row, "resource-source-ref")] = true
			if keys := yamlPath(row, "api-key-entries"); keys != nil {
				for _, key := range keys.Content {
					out[mappingScalarValue(key, "resource-source-ref")] = true
				}
			}
		}
	}
	return out
}

// ValidateResourceManagementUpdate protects the native v8 source write boundary.
// Native clients edit the raw source tree; IDs must remain in their issued family
// and parent scope. Unmarked additions remain eligible for catalog enrollment.
func ValidateResourceManagementUpdate(original, updated []byte, cfg *Config) error {
	var before yaml.Node
	if err := yaml.Unmarshal(original, &before); err != nil {
		return err
	}
	if len(before.Content) != 1 {
		return fmt.Errorf("invalid resource source")
	}
	ref, err := resourceDocumentSourceRef(before.Content[0])
	if err != nil {
		return err
	}
	if ref == "" {
		return nil
	}
	// Enrollment may have just added markers after the runtime config was loaded.
	// A native source no-op is safe without inventing or rebasing a writer receipt.
	var proposed yaml.Node
	if err = yaml.Unmarshal(updated, &proposed); err != nil {
		return err
	}
	var oldKeys, newKeys any
	var oldPlugins, newPlugins any
	if n := yamlPath(before.Content[0], "plugins.configs"); n != nil {
		if err = n.Decode(&oldPlugins); err != nil {
			return err
		}
	}
	if n := yamlPath(before.Content[0], "api-keys"); n != nil {
		if err = n.Decode(&oldKeys); err != nil {
			return err
		}
	}
	if len(proposed.Content) == 1 {
		if n := yamlPath(proposed.Content[0], "api-keys"); n != nil {
			if err = n.Decode(&newKeys); err != nil {
				return err
			}
		}
	}
	if len(proposed.Content) == 1 {
		if n := yamlPath(proposed.Content[0], "plugins.configs"); n != nil {
			if err = n.Decode(&newPlugins); err != nil {
				return err
			}
		}
	}
	if reflect.DeepEqual(oldKeys, newKeys) && reflect.DeepEqual(oldPlugins, newPlugins) {
		return nil
	}
	if cfg == nil || ref != cfg.ResourceCatalog.sourceDocument {
		return fmt.Errorf("resource source changed; reload before saving")
	}
	type scope struct{ family, parent, kind, id string }
	collect := func(data []byte) (map[scope]int, error) {
		normalized, _, errNormalize := NormalizeConfigLayout(data, true)
		if errNormalize != nil {
			return nil, errNormalize
		}
		var doc yaml.Node
		if errDecode := yaml.Unmarshal(normalized, &doc); errDecode != nil {
			return nil, errDecode
		}
		result := make(map[scope]int)
		for _, family := range v8KeyFamilies {
			groups := yamlPath(doc.Content[0], "api-keys."+family.current)
			if groups == nil {
				continue
			}
			for index, group := range groups.Content {
				id := mappingScalarValue(group, "resource-id")
				if id != "" {
					result[scope{family.current, "", "provider", id}]++
				}
				parent := id
				if parent == "" {
					parent = fmt.Sprintf("unmarked-%d", index)
				}
				if keys := yamlPath(group, "keys"); keys != nil {
					for _, key := range keys.Content {
						if child := mappingScalarValue(key, "resource-id"); child != "" {
							result[scope{family.current, parent, "credential", child}]++
						}
					}
				}
			}
		}
		if plugins := yamlPath(doc.Content[0], "plugins.configs"); plugins != nil {
			for i := 0; i+1 < len(plugins.Content); i += 2 {
				plugin, node := plugins.Content[i].Value, plugins.Content[i+1]
				id := mappingScalarValue(node, "resource-id")
				if id != "" {
					result[scope{"plugin/" + plugin, "", "provider", id}]++
				}
				if keys := yamlPath(node, "api-keys"); keys != nil {
					for _, child := range keys.Content {
						if marker := mappingScalarValue(child, "resource-id"); marker != "" {
							result[scope{"plugin/" + plugin, id, "credential", marker}]++
						}
					}
				}
			}
		}
		return result, nil
	}
	known, err := collect(original)
	if err != nil {
		return err
	}
	next, err := collect(updated)
	if err != nil {
		return err
	}
	for key, count := range next {
		if count > known[key] {
			return fmt.Errorf("resource source requires unambiguous management provenance")
		}
	}
	return nil
}
