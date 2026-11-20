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

	input := "a filename and base64 upload (128 KiB maximum)"
	if len(keys) > 0 {
		input = "a named operator-authorized target or " + input
	}

	desc := "Scan untrusted skill/plugin bytes without execution. Provide " + input + ". Findings do not imply complete analysis."
	desc += " Operator-selected inspection profile: " + s.scanner.InspectionPlan().Name + ". The tool cannot change the check set or grant network access."
	uploadFields := []string{fieldName, fieldUploadData}
	properties := map[string]any{
		fieldName:       map[string]any{"type": "string", "minLength": 1},
		fieldUploadData: map[string]any{"type": "string"},
	}
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
	}

	out := []any{map[string]any{
		"name":        toolScanSkill,
		"description": desc,
		"inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false},
	}}
	if len(keys) == 0 {
		schema["required"] = uploadFields
	} else {
		targetSchema := map[string]any{"type": "string", "enum": keys}
		properties[fieldTarget] = targetSchema
		schema["oneOf"] = []map[string]any{
			{"required": []string{fieldTarget}, "maxProperties": 1},
			{"required": uploadFields, "maxProperties": 2},
		}

		out = append(out, map[string]any{
			"name":        toolCompareSkills,
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
