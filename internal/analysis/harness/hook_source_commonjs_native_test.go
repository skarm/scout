//go:build !coreonly && cgo

package harness_test

import (
	"slices"
	"testing"

	"github.com/skarm/scout/internal/analysis/harness"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestCommonJSHookDoesNotCallUpdatedBindings(t *testing.T) {
	for _, tc := range []struct {
		name, call string
		linked     bool
		handler    string
	}{
		{name: "unchanged export", call: "handler.run();", linked: true},
		{name: "alternate spelling of local reference", call: "function start() { handler.run(); } st\\u0061rt();", linked: true},
		{name: "alternate spelling of exported property", call: "handler.r\\u0075n();", linked: true},
		{name: "alternate spelling in module export", call: "handler.run();", handler: "function run() {} mod\\u0075le.exp\\u006frts = {run};", linked: true},
		{name: "shadowing declaration with alternate spelling", call: "{ const h\\u0061ndler = {}; handler.run(); }"},
		{name: "unrelated counter", call: "let count = 0; count++; handler.run();", linked: true},
		{name: "snapshot of original function", call: "function invoke() { handler.run(); } const saved = invoke; invoke++; saved();", linked: true},
		{name: "incremented function", call: "function invoke() { handler.run(); } invoke++; invoke();"},
		{name: "decremented function in block", call: "function invoke() { handler.run(); } if (true) { --invoke; } invoke();"},
		{name: "updated function alias", call: "function invoke() { handler.run(); } const saved = invoke; saved++; saved();"},
		{name: "incremented export", call: "handler.run++; handler.run();"},
		{name: "decremented export", call: "--handler.run; handler.run();"},
		{name: "deleted export", call: "delete handler.run; handler.run();"},
		{name: "updated module alias", call: "const saved = handler; saved.run++; handler.run();"},
		{name: "deleted module alias", call: "const saved = handler; delete saved.run; handler.run();"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handler
			if handler == "" {
				handler = "function run() { return; }\nmodule.exports = {run};\n"
			}
			_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash",
				`node "${CLAUDE_PLUGIN_ROOT}/dispatch.cjs"`, false,
				artifact.NewFile("p/dispatch.cjs", []byte("const handler = require('./handler.cjs');\n"+tc.call+"\n"), false),
				artifact.NewFile("p/handler.cjs", []byte(handler), false))
			linked := slices.ContainsFunc(hooks.Paths, func(p harness.HookSourcePath) bool {
				return p.Target == "p/handler.cjs"
			})
			if linked != tc.linked {
				t.Fatalf("export linked = %v, want %v: %+v", linked, tc.linked, hooks.Paths)
			}

			if !slices.ContainsFunc(hooks.Diagnostics, func(d report.Diagnostic) bool {
				return d.Code == "hook_source_node_scope_unverified" && d.AffectsScope
			}) {
				t.Fatalf("Node runtime boundary lost: %+v", hooks.Diagnostics)
			}
		})
	}
}

func TestCommonJSPatternsBindOnlyTargets(t *testing.T) {
	for _, tc := range []struct {
		name, declaration string
		linked            bool
	}{
		{"object default shadows", "const {handler = {run(){}}} = {};", false},
		{"escaped object default shadows", "const {h\\u0061ndler = {run(){}}} = {};", false},
		{"nested object default shadows", "const [{handler = {run(){}}}] = [{}];", false},
		{"renamed default leaves reference", "const {value: other = handler} = {};", true},
		{"array default leaves reference", "const [other = handler] = [];", true},
		{"object default leaves reference", "const {other = handler} = {};", true},
		{"plain array shadows", "const [handler] = [{run(){}}];", false},
		{"renamed default shadows", "const {value: handler = {run(){}}} = {};", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash",
				`node "${CLAUDE_PLUGIN_ROOT}/dispatch.cjs"`, false,
				artifact.NewFile("p/dispatch.cjs", []byte("const handler = require('./handler.cjs');\n{"+tc.declaration+" handler.run();}\n"), false),
				artifact.NewFile("p/handler.cjs", []byte("function run() {}\nmodule.exports = {run};\n"), false))
			linked := slices.ContainsFunc(hooks.Paths, func(p harness.HookSourcePath) bool {
				return p.Target == "p/handler.cjs"
			})
			if linked != tc.linked {
				t.Fatalf("export linked=%v, want %v: %+v", linked, tc.linked, hooks.Paths)
			}
		})
	}
}

func TestCommonJSInvocationEffectsRespectLexicalBindings(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		linked     bool
	}{
		{"sibling closure after rebind", "function invoke(){handler.run()} function other(){invoke()} function start(){invoke = () => {}; other()} start();", false},
		{"sequence closure after rebind", "function invoke(){handler.run()} function other(){invoke()} function start(){(invoke = () => {}, other())} start();", false},
		{"parameter shadow preserves outer", "function invoke(){handler.run()} function clear(invoke){invoke++} clear(); invoke();", true},
		{"block shadow preserves outer", "function invoke(){handler.run()} function clear(){ { function invoke(){} invoke++ } } clear(); invoke();", true},
		{"uncalled helper preserves outer", "function invoke(){handler.run()} function clear(){invoke++} invoke();", true},
		{"argument snapshot before later rebind", "function invoke(){handler.run()} function start(saved){saved()} start(invoke, invoke = () => {});", true},
		{"uncertain branch preserves other path", "function invoke(){handler.run()} function call(){invoke()} if (unknown) { invoke++; } else { call(); }", true},
		{"uncertain branch invalidates continuation", "function invoke(){handler.run()} function clear(){invoke++} if (unknown) clear(); invoke();", false},
		{"block outer binding hidden by caller local", "function invoke(){handler.run()} function clear(){invoke++} { const invoke = 1; if (unknown) clear(); } invoke();", false},
		{"preexisting closure isolated across branches", "function invoke(){handler.run()} function clear(){invoke++} function call(){invoke()} if (unknown) { clear(); } else { call(); }", true},
		{"argument call executes once", "function invoke(){handler.run()} function start(){} start(invoke());", true},
		{"unchanged", "function invoke(){handler.run()} function start(){invoke()} start();", true},
		{"argument rebind", "function invoke(){handler.run()} function start(){invoke()} start(invoke = () => {});", false},
		{"argument update", "function invoke(){handler.run()} function start(){invoke()} start(invoke++);", false},
		{"callee captured before argument", "function invoke(){handler.run()} invoke(invoke = () => {});", true},
		{"helper rebind", "function invoke(){handler.run()} function clear(){invoke = () => {}} clear(); invoke();", false},
		{"snapshot survives helper rebind", "function invoke(){handler.run()} const saved = invoke; function clear(){invoke = () => {}} clear(); saved();", true},
		{"unrelated helper rebind", "function invoke(){handler.run()} function other(){} function clear(){other = () => {}} clear(); invoke();", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, hooks := inspectShellHook(t, `bash "${CLAUDE_PLUGIN_ROOT}/start.sh"`, "bash", `node "${CLAUDE_PLUGIN_ROOT}/dispatch.cjs"`, false,
				artifact.NewFile("p/dispatch.cjs", []byte("const handler = require('./handler.cjs');\n"+tc.body+"\n"), false),
				artifact.NewFile("p/handler.cjs", []byte("function run(){} module.exports = {run};\n"), false))
			count := 0
			for _, path := range hooks.Paths {
				if path.Target == "p/handler.cjs" {
					count++
				}
			}
			want := 0
			if tc.linked {
				want = 1
			}
			if count != want {
				t.Fatalf("handler paths=%d want=%d", count, want)
			}
		})
	}
}
