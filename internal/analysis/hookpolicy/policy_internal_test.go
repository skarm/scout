// Exercises private implementation details and package fixtures.
package hookpolicy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

func TestClosedDisableSettingGrammar(t *testing.T) {
	for _, tc := range []struct {
		field string
		valid bool
	}{
		{field: `"$schema":"https://example.invalid/schema"`, valid: true},
		{field: `"$schema":4`, valid: false},
		{field: `"model":"sample"`, valid: true},
		{field: `"model":"\u0000"`, valid: false},
		{field: `"includeCoAuthoredBy":false`, valid: true},
		{field: `"includeCoAuthoredBy":"false"`, valid: false},
		{field: `"env":{"KEY":"value"}`, valid: true},
		{field: `"env":{"KEY":false}`, valid: false},
		{field: `"env":[]`, valid: false},
		{field: `"statusLine":{"type":"command","command":"echo hi"}`, valid: true},
		{field: `"statusLine":{"command":["echo","hi"]}`, valid: true},
		{field: `"statusLine":{"type":1}`, valid: false},
		{field: `"statusLine":{"command":{}}`, valid: false},
		{field: `"statusLine":[]`, valid: false},
		{field: `"fileSuggestion":{}`, valid: true},
		{field: `"future":true`, valid: false},
		{
			field: `"permissions":{"allow":["Read(src/**)","mcp__server__tool*"],"ask":["Bash(echo (ok))"],"deny":["*"],"additionalDirectories":["../other"],"defaultMode":"plan","disableAutoMode":"disable","disableBypassPermissionsMode":"disable"}`,
			valid: true,
		},
		{field: `"permissions":[]`, valid: false},
		{field: `"permissions":{"allow":false}`, valid: false},
		{field: `"permissions":{"allow":["Read(unterminated"]}`, valid: false},
		{field: `"permissions":{"allow":["Read(a)(b)"]}`, valid: false},
		{field: `"permissions":{"allow":["Read(()"]}`, valid: false},
		{field: `"permissions":{"allow":["Read()"]}`, valid: false},
		{field: `"permissions":{"allow":["Read)"]}`, valid: false},
		{field: `"permissions":{"allow":["Read*"]}`, valid: false},
		{field: `"permissions":{"allow":["!"]}`, valid: false},
		{field: `"permissions":{"allow":[""]}`, valid: false},
		{field: `"permissions":{"allow":[1]}`, valid: false},
		{field: `"permissions":{"defaultMode":1}`, valid: false},
		{field: `"permissions":{"defaultMode":"unknown"}`, valid: false},
		{field: `"permissions":{"disableAutoMode":true}`, valid: false},
		{field: `"permissions":{"disableAutoMode":"enable"}`, valid: false},
		{field: `"hooks":[]`, valid: false},
		{field: `"hooks":{"Unknown":[]}`, valid: false},
		{field: `"hooks":{"SessionStart":{}}`, valid: false},
		{field: `"hooks":{"SessionStart":[null]}`, valid: false},
		{field: `"hooks":{"SessionStart":[{"matcher":3,"hooks":[]}]}`, valid: false},
		{field: `"hooks":{"SessionStart":[{}]}`, valid: false},
		{field: `"hooks":{"SessionStart":[{"hooks":[null]}]}`, valid: false},
	} {
		t.Run(tc.field, func(t *testing.T) {
			n := policyNode(t, `{"disableAllHooks":true,`+tc.field+`}`)
			if got := validDisable(n); got != tc.valid {
				t.Fatalf("valid=%v want %v", got, tc.valid)
			}
			state := Local(n)
			if state.Disabled != tc.valid || state.Uncertain == tc.valid {
				t.Fatal(state)
			}
		})
	}
	for _, input := range []string{`null`, `[]`, `{}`, `{"disableAllHooks":false}`, `{"disableAllHooks":1}`} {
		if validDisable(policyNode(t, input)) {
			t.Fatal(input)
		}
	}
	if validDisable(nil) || Local(nil) != (State{}) {
		t.Fatal("nil settings")
	}
}

func TestClosedHookHandlerGrammar(t *testing.T) {
	for _, tc := range []struct {
		handler string
		valid   bool
	}{
		{handler: `{"type":"command","command":"echo hi","args":["hello"]}`, valid: true},
		{handler: `{"type":"command"}`, valid: false},
		{handler: `{"type":"command","command":" "}`, valid: false},
		{handler: `{"type":"command","command":"echo","args":{}}`, valid: false},
		{handler: `{"type":"http","url":"https://example.invalid/hook"}`, valid: true},
		{handler: `{"type":"http","url":"http://example.invalid/hook"}`, valid: true},
		{handler: `{"type":"http","url":1}`, valid: false},
		{handler: `{"type":"http","url":"file:///tmp/x"}`, valid: false},
		{handler: `{"type":"http","url":"https:/path"}`, valid: false},
		{handler: `{"type":"http","url":"https://%"}`, valid: false},
		{handler: `{"type":"prompt","prompt":"Review this"}`, valid: true},
		{handler: `{"type":"agent","prompt":"Review this"}`, valid: true},
		{handler: `{"type":"agent"}`, valid: false},
		{handler: `{"type":"mcp_tool","server":"s","tool":"t"}`, valid: true},
		{handler: `{"type":"mcp_tool","server":"s"}`, valid: false},
		{handler: `{"type":"future"}`, valid: false},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			n := policyNode(t, `{"disableAllHooks":true,"hooks":{"SessionStart":[{"matcher":"*","hooks":[`+tc.handler+`]}]}}`)
			if validDisable(n) != tc.valid {
				t.Fatalf("want valid=%v", tc.valid)
			}
		})
	}
	for _, field := range []struct{ name, valid, invalid string }{
		{name: "if", valid: `""`, invalid: `1`},
		{name: "statusMessage", valid: `"status"`, invalid: `false`},
		{name: "model", valid: `"m"`, invalid: `[]`},
		{name: "rewakeMessage", valid: `"m"`, invalid: `{}`},
		{name: "rewakeSummary", valid: `"s"`, invalid: `null`},
		{name: "once", valid: `true`, invalid: `"true"`},
		{name: "async", valid: `false`, invalid: `0`},
		{name: "asyncRewake", valid: `true`, invalid: `null`},
		{name: "continueOnBlock", valid: `true`, invalid: `[]`},
		{name: "timeout", valid: `0.25`, invalid: `0`},
		{name: "timeout", valid: `1`, invalid: `-1`},
		{name: "timeout", valid: `1`, invalid: `"1"`},
		{name: "timeout", valid: `1`, invalid: `1e999`},
		{name: "shell", valid: `"bash"`, invalid: `"zsh"`},
		{name: "shell", valid: `"powershell"`, invalid: `1`},
		{name: "allowedEnvVars", valid: `["TOKEN"]`, invalid: `[1]`},
		{name: "headers", valid: `{"X":"v"}`, invalid: `{"X":false}`},
		{name: "headers", valid: `{}`, invalid: `[]`},
		{name: "input", valid: `{}`, invalid: `[]`},
	} {
		for _, valid := range []bool{false, true} {
			value := field.invalid
			if valid {
				value = field.valid
			}
			t.Run(fmt.Sprint(field.name, value), func(t *testing.T) {
				h := `{"type":"command","command":"echo hi","` + field.name + `":` + value + `}`
				n := policyNode(t, `{"disableAllHooks":true,"hooks":{"SessionStart":[{"hooks":[`+h+`]}]}}`)
				if got := validDisable(n); got != valid {
					t.Fatalf("%s valid=%v", h, got)
				}
			})
		}
	}
	if text(&jsonconfig.Node{Kind: "string", String: strings.Repeat("a", 65537)}, false) {
		t.Fatal("oversize text")
	}
}

func FuzzMCPWildcard(f *testing.F) {
	old := regexp.MustCompile(`^mcp__[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]*\*$`)
	for _, s := range []string{"", "mcp__a__*", "mcp____*", "mcp_____*", "mcp__a__b*", "mcp__a__**", "mcp__a____b*", "MCP__a__*", "mcp__a__b\n*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := mcpWildcard(s), old.MatchString(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	})
}

func policyNode(t *testing.T, text string) *jsonconfig.Node {
	t.Helper()
	n, err := jsonconfig.Parse(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
