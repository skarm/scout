package mcp

import (
	"sort"
)

func (s *Server) tools() []any {
	keys := make([]string, 0, len(s.options.Targets))
	for k := range s.options.Targets {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	targetSchema := map[string]any{"type": "string", "enum": keys}
	desc := "Scan untrusted skill/plugin bytes without execution. Use a named operator-authorized target OR a filename plus base64 upload (128 KiB maximum). Findings do not imply complete analysis."
	desc += " Operator-selected inspection profile: " + s.scanner.InspectionPlan().Name + ". The tool cannot change the check set or grant network access."
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"target":      targetSchema,
			"name":        map[string]any{"type": "string"},
			"data_base64": map[string]any{"type": "string"},
		},
	}

	out := []any{map[string]any{
		"name":        "scan_skill",
		"description": desc,
		"inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false},
	}}
	if len(s.options.Targets) > 0 {
		out = append(out, map[string]any{
			"name":        "compare_skills",
			"description": "Freshly scan two operator-authorized targets and compare evidence; old findings are not auto-approved.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"previous", "candidate"},
				"properties":           map[string]any{"previous": targetSchema, "candidate": targetSchema},
			},
		})
	}

	return out
}
