package spec

import (
	"go.yaml.in/yaml/v3"
)

// pathLines maps each key under top-level "paths" to its 1-based line.
// It works for YAML and JSON (JSON is YAML). On any parse problem it returns
// an empty map: SpecLine is then 0, which reporters treat as "unknown line".
func pathLines(data []byte) map[string]int {
	lines := map[string]int{}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return lines
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return lines
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "paths" || top.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		paths := top.Content[i+1]
		for j := 0; j+1 < len(paths.Content); j += 2 {
			k := paths.Content[j]
			if _, dup := lines[k.Value]; !dup {
				lines[k.Value] = k.Line
			}
		}
	}
	return lines
}
