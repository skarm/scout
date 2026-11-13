package document_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestDeclaredHookShellUsesOriginalDocumentAndIsIdempotent(t *testing.T) {
	const body = `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash -c 'printf ready'"}]}]}}`
	for _, input := range []string{body, strings.Repeat(" ", 512) + body} {
		original := document.Prepare(t.Context(), artifact.NewFile("config/lifecycle.custom", []byte(input), false))
		prepared := original.WithDeclaredHookShell(t.Context())
		repeated := prepared.WithDeclaredHookShell(t.Context())
		units := repeated.Units()
		var jsonUnits, hookUnits int
		for _, unit := range units {
			switch {
			case unit.Language == "json" && unit.Origin == "file":
				jsonUnits++
			case unit.Origin == document.OriginHookShell:
				hookUnits++
			}
		}
		if jsonUnits != 1 || hookUnits != 2 || len(prepared.Units()) != len(units) {
			t.Fatalf("wanted one JSON unit and two shell units: JSON %d, hook %d", jsonUnits, hookUnits)
		}
		payload := units[len(units)-1]
		if payload.Origin != document.OriginHookShell || payload.View.Text() != "printf ready" ||
			input[payload.Span.Start:payload.Span.End] != "printf ready" || repeated.HookEvent(payload.Span) != "Stop" {
			t.Fatalf("incorrect projected payload or source: %+v", payload)
		}
		if original.HookEvent(payload.Span) != "" || len(original.Units()) >= len(prepared.Units()) {
			t.Fatal("declared preparation mutated the original document")
		}
	}
}

func TestDeclaredHookShellDoesNotRetryRejectedJSON(t *testing.T) {
	const input = `{"hooks":{},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"printf ready"}]}]}}`
	original := document.Prepare(t.Context(), artifact.NewFile("custom.json", []byte(input), false))
	prepared := original.WithDeclaredHookShell(t.Context())
	if len(prepared.Units()) != 1 || prepared.Units()[0].Language != "json" || prepared.Units()[0].Tree != nil {
		t.Fatalf("ambiguous JSON was interpreted: %+v", prepared.Units())
	}
}

func TestHookShellProjectsCommandsAndLiteralScripts(t *testing.T) {
	for _, tc := range []struct {
		name, input, script, evidence, event string
		units                                int
	}{
		{"direct", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"printf ready"}]}]}}`, "printf ready", "printf ready", "SessionStart", 1},
		{"shell command", `{"PreToolUse":[{"hooks":[{"type":"command","command":"/bin/bash -ec 'printf \"ready\"'"}]}]}`, `printf "ready"`, `printf \"ready\"`, "PreToolUse", 2},
		{"argv", `{"Stop":[{"hooks":[{"type":"command","command":"sh","args":["-c","printf \"ready\"","name"]}]}]}`, `printf "ready"`, `printf \"ready\"`, "Stop", 1},
		{"JSON unicode and newline", `{"Stop":[{"hooks":[{"type":"command","command":"bash -c 'printf \uD83D\uDE00\n: '"}]}]}`, "printf 😀\n: ", `printf \uD83D\uDE00\n: `, "Stop", 2},
		{"double quoted literal", `{"Stop":[{"hooks":[{"type":"command","command":"bash -c \"printf ready\""}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"nested fixed script", `{"Stop":[{"hooks":[{"type":"command","command":"bash -c 'sh -c \"printf ready\"'"}]}]}`, "printf ready", "printf ready", "Stop", 3},
		{"options after c", `{"Stop":[{"hooks":[{"type":"command","command":"bash -c -e 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"named option before c", `{"Stop":[{"hooks":[{"type":"command","command":"bash -o pipefail -c 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"named option after c in argv", `{"Stop":[{"hooks":[{"type":"command","command":"bash","args":["-c","-o","errexit","printf ready"]}]}]}`, "printf ready", "printf ready", "Stop", 1},
		{"argv terminator", `{"Stop":[{"hooks":[{"type":"command","command":"bash","args":["-c","--","printf ready"]}]}]}`, "printf ready", "printf ready", "Stop", 1},
		{"shell terminator", `{"Stop":[{"hooks":[{"type":"command","command":"bash -c -- 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"noexec disabled again", `{"Stop":[{"hooks":[{"type":"command","command":"bash -nc +n 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"inside a conditional", `{"Stop":[{"hooks":[{"type":"command","command":"if true; then bash -c 'printf ready'; fi"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"inside command substitution", `{"Stop":[{"hooks":[{"type":"command","command":"printf '%s' \"$(sh -c 'printf ready')\""}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"inside assignment substitution", `{"Stop":[{"hooks":[{"type":"command","command":"value=$(sh -c 'printf ready')"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"inside redirect substitution", `{"Stop":[{"hooks":[{"type":"command","command":": >\"$(sh -c 'printf ready')\""}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"command wrapper", `{"Stop":[{"hooks":[{"type":"command","command":"command -p -- bash -c 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"exec wrapper", `{"Stop":[{"hooks":[{"type":"command","command":"exec bash -c 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
		{"explicit interpreter despite local function", `{"Stop":[{"hooks":[{"type":"command","command":"bash() { :; }; command bash -c 'printf ready'"}]}]}`, "printf ready", "printf ready", "Stop", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := document.Prepare(t.Context(), artifact.NewFile("hooks/hooks.json", []byte(tc.input), false))
			var units []document.Unit
			for _, unit := range doc.Units() {
				if unit.Origin == document.OriginHookShell {
					units = append(units, unit)
				}
			}
			if len(units) != tc.units || units[len(units)-1].View.Text() != tc.script {
				t.Fatalf("wrong hook projections: %+v", units)
			}
			span := units[len(units)-1].Span
			if got := tc.input[span.Start:span.End]; got != tc.evidence || doc.HookEvent(span) != tc.event {
				t.Fatalf("wrong original hook evidence: %q, event %q", got, doc.HookEvent(span))
			}
		})
	}
}

func TestHookShellRequiresCommandHandlerAndStaticPayload(t *testing.T) {
	for _, tc := range []struct {
		name, handler string
		units         int
		gap           bool
	}{
		{"prompt", `{"type":"prompt","command":"bash -c 'printf ready'"}`, 0, false},
		{"PowerShell", `{"type":"command","shell":"powershell","command":"bash -c 'printf ready'"}`, 0, false},
		{"literal data", `{"type":"command","command":"echo \"bash -c 'printf ready'\""}`, 1, false},
		{"syntax only", `{"type":"command","command":"bash -nc 'printf ready'"}`, 1, false},
		{"syntax only argv", `{"type":"command","command":"bash","args":["-nc","printf ready"]}`, 0, false},
		{"syntax only after c", `{"type":"command","command":"bash -c -n 'printf ready'"}`, 1, false},
		{"named noexec", `{"type":"command","command":"bash","args":["-c","-o","noexec","printf ready"]}`, 0, false},
		{"dynamic named option", `{"type":"command","command":"bash -c -o \"$MODE\" 'printf ready'"}`, 1, true},
		{"argv unsupported options", `{"type":"command","command":"bash","args":["-O","extglob","-c","printf ready"]}`, 0, true},
		{"argv missing payload", `{"type":"command","command":"bash","args":["-c","--"]}`, 0, true},
		{"command lookup only", `{"type":"command","command":"command -v bash -c 'printf ready'"}`, 1, false},
		{"local function named bash", `{"type":"command","command":"bash() { :; }; bash -c 'printf ready'"}`, 1, true},
		{"dynamic payload", `{"type":"command","command":"bash -c \"$PAYLOAD\""}`, 1, true},
		{"NUL", `{"type":"command","command":"echo \u0000"}`, 0, true},
		{"argv is not shell syntax", `{"type":"command","command":"echo","args":["bash -c 'printf ready'"]}`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const prefix = "{\n\"SessionStart\":[{\"hooks\":["
			input := prefix + tc.handler + `]}]}`
			doc := document.Prepare(t.Context(), artifact.NewFile("hooks.json", []byte(input), false))
			count := 0
			for _, unit := range doc.Units() {
				if unit.Origin == document.OriginHookShell {
					count++
				}
			}
			found := false
			for _, issue := range doc.Diagnostics() {
				if issue.Code == "hook_command_unverified" {
					found = issue.Line == 2 && issue.Column > 0 && issue.AffectsScope
				}
			}
			if count != tc.units || found != tc.gap {
				t.Fatalf("units = %d; diagnostics = %+v", count, doc.Diagnostics())
			}
			if event := doc.HookEvent(source.Span{Start: strings.Index(input, "SessionStart"), End: len(prefix)}); event != "" {
				t.Fatalf("event key is not command evidence: %q", event)
			}
		})
	}
}
