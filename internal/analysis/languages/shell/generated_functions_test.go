package shell_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/shell"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestGeneratedShellUsesFunctionCallSiteEffects(t *testing.T) {
	const write = "cat > helper.sh <<'END'\nprintf first\nEND\n"
	const def = "prepare() {\n" + write + "}\n"
	const pathChange = "PATH=/custom/bin:$PATH\n"
	const hashChange = "hash -p /usr/bin/true cat\n"
	for _, tc := range []struct {
		name, text string
		views      int
		limited    bool
	}{
		{"path change after only call", def + "prepare\n" + pathChange, 1, false},
		{"hash change after only call", def + "prepare\n" + hashChange, 1, false},
		{"path change between calls", def + "prepare\n" + pathChange + "prepare\n", 1, true},
		{"hash change between calls", def + "prepare\n" + hashChange + "prepare\n", 1, true},
		{"only call after path change", def + pathChange + "prepare\n", 0, true},
		{"only call after hash change", def + hashChange + "prepare\n", 0, true},
		{"hash combined options change lookup", def + "hash -rp /usr/bin/true cat\nprepare\n", 0, true},
		{"hash accepts an attached pathname", def + "hash -p/usr/bin/true cat\nprepare\n", 0, true},
		{"hash option and target resolved from bindings", def + "flag=-p writer=cat\nhash \"$flag\" /usr/bin/true -- \"$writer\"\nprepare\n", 0, true},
		{"unrelated hash target stays harmless", def + "hash -rp /usr/bin/true other\nprepare\n", 1, false},
		{"hash option terminator protects filenames", def + "hash -- -p cat\nprepare\n", 1, false},
		{"printf resolves its variable operand", def + "key=PATH\nprintf -v \"$key\" %s /custom/bin\nprepare\n", 0, true},
		{"printf accepts an attached variable name", def + "printf -vPATH %s /custom/bin\nprepare\n", 0, true},
		{"printf unknown variable may change lookup", def + "printf -v \"$key\" %s /custom/bin\nprepare\n", 0, true},
		{"printf unrelated variable stays harmless", def + "key=other\nprintf -v \"$key\" %s /custom/bin\nprepare\n", 1, false},
		{"export joins literal name fragments", def + "export PA\"TH\"=/custom/bin\nprepare\n", 0, true},
		{"unset resolves its variable operand", def + "key=PATH\nunset -v \"$key\"\nprepare\n", 0, true},
		{"read may assign to an unresolved name", def + "read \"$key\"\nprepare\n", 0, true},
		{"read prompt is not a variable operand", def + "read -rp \"$prompt\" other\nprepare\n", 1, false},
		{"read array option names a variable", def + "read -aPATH\nprepare\n", 0, true},
		{"nameref can change lookup indirectly", def + "declare -n ref=PATH\nref=/custom/bin\nprepare\n", 0, true},
		{"declaration parser retains nameref option", def + "if condition; then declare -n ref=PATH; fi\nref=/custom/bin\nprepare\n", 0, true},
		{"later writer function declaration", def + "prepare\ncat() { :; }\n", 1, false},
		{"writer function declared between calls", def + "prepare\ncat() { :; }\nprepare\n", 1, true},
		{"direct call in a group", def + "{ prepare; }\n" + pathChange, 1, false},
		{"direct call in a subshell", def + "( prepare )\n" + pathChange, 1, false},
		{"direct call in a branch", def + "if :; then prepare; fi\n" + pathChange, 1, false},
		{"call in else uses state before either branch", def + "if condition; then\n" + pathChange + "else prepare; fi\n", 1, false},
		{"call after branch sees possible path change", def + "if condition; then\n" + pathChange + "else prepare; fi\nprepare\n", 1, true},
		{"temporary path does not affect later call", def + "PATH=/custom/bin prepare\nprepare\n", 1, true},
		{"temporary path reaches nested call", def + "outer() { prepare; }\nPATH=/custom/bin outer\nprepare\n", 1, true},
		{"transitive call before path change", def + "outer() { prepare; }\nouter\n" + pathChange, 1, false},
		{"transitive effects between nested calls", def + "change() { " + pathChange + "}\nouter() { prepare; change; prepare; }\nouter\n", 1, true},
		{"earlier pipeline stage does not change later call", def + "change() { " + pathChange + "}\nchange | prepare\n", 1, false},
		{"last pipeline stage may affect later call", def + "change() { " + pathChange + "}\n: | change\nprepare\n", 0, true},
		{"background function does not change caller lookup", def + "change() { " + pathChange + "}\nchange &\nprepare\n", 1, false},
		{"call in a loop uses conservative effects", def + "for item in a b; do\nprepare\n" + pathChange + "done\n", 0, true},
		{"path change after an unconditional return is unreachable", def + "change() { { return 0; }; " + pathChange + "}\nchange\nprepare\n", 1, false},
		{"both branches return before the write", "prepare() {\nif condition; then return; else return 0; fi\n" + write + "}\nprepare\n", 0, false},
		{"elif with final else has no continuing branch", "prepare() {\nif first; then return; elif second; then return; else return; fi\n" + write + "}\nprepare\n", 0, false},
		{"elif without else can continue", "prepare() {\nif first; then return; elif second; then return; fi\n" + write + "}\nprepare\n", 1, false},
		{"conditional all-returning compound can be skipped", "prepare() {\ncondition && if other; then return; else return; fi\n" + write + "}\nprepare\n", 1, false},
		{"returning branch cannot change later write in function", "prepare() {\nif condition; then\n" + pathChange + "return\nfi\n" + write + "}\nprepare\n", 1, false},
		{"returning branch can change caller lookup", def + "change() { if condition; then\n" + pathChange + "return\nfi; }\nchange\nprepare\n", 0, true},
		{"returning branch preserves unchanged function bindings", def + "check() { if condition; then return; fi; }\ncheck\nprepare\n", 1, false},
		{"all returning branches contribute effects to caller", def + "change() { if condition; then\n" + pathChange + "return\nelse return; fi; }\nchange\nprepare\n", 0, true},
		{"subshell return does not end enclosing function", "prepare() {\n( if condition; then return; else return; fi )\n" + write + "}\nprepare\n", 1, false},
		{"same write recovered once", def + "prepare\nprepare\n", 1, false},
		{"uncalled writer still analyzed", def, 1, false},
		{"uncalled writer can use a known helper", "check() { :; }\nprepare() {\ncheck\n" + write + "}\n", 1, false},
		{"uncalled writer uses conservative effects", def + pathChange, 0, true},
		{"unresolved later invocation leaves a gap", def + "prepare\neval \"$command\"\n", 1, true},
		{"opaque subshell invocation leaves a gap", def + "prepare\n( eval \"$command\" )\n", 1, true},
		{"conditional redefinition keeps earlier view", def + "prepare\nif :; then prepare() { :; }; fi\nprepare\n", 1, true},
		{"alias with a quoted direct call", def + "alias prepare=':'\n'prepare'\n" + pathChange, 1, false},
		{"ambiguous alias call uses fallback", def + "alias prepare=':'\nprepare\n", 0, true},
		{"unset prevents reusing definition as direct call", def + "unset -f prepare\nprepare\n", 0, true},
		{"recursive call retains earlier write and records a gap", "prepare() {\n" + write + "prepare\n}\nprepare\n", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recoverGeneratedShell(t, tc.text)
			if len(got.Views) != tc.views || (got.Gaps != 0) != tc.limited {
				t.Fatalf("got %d views and gaps %b, want %d views and limited=%t", len(got.Views), got.Gaps, tc.views, tc.limited)
			}
			for _, view := range got.Views {
				if view.Text() != "printf first\n" {
					t.Fatalf("unexpected body %q", view.Text())
				}
			}
		})
	}
}

func TestGeneratedShellFunctionInheritsPipedStdout(t *testing.T) {
	const body = "printf example\n"
	for _, tc := range []struct {
		name, write string
		views       int
		gaps        document.GeneratedShellGaps
	}{
		{"tee shares caller pipe", "tee helper.sh", 0, document.GeneratedShellUnrecovered},
		{"tee redirects stdout away from pipe", "tee helper.sh >/dev/null", 1, 0},
		{"cat redirects stdout away from pipe", "cat >helper.sh", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "prepare() {\n" + tc.write + " <<'END'\n" + body + "END\n}\nprepare |& cat\n"
			got := recoverGeneratedShell(t, text)
			if got.Gaps != tc.gaps || len(got.Views) != tc.views {
				t.Fatalf("unexpected piped function recovery: %+v", got)
			}
		})
	}
}

func TestGeneratedShellResolvesRedefinedFunctionAtEachCall(t *testing.T) {
	const first = "prepare() {\ncat > first.sh <<'END'\nprintf first\nEND\n}\n"
	const second = "prepare() {\ncat > second.sh <<'END'\nprintf second\nEND\n}\n"
	got := recoverGeneratedShell(t, first+"prepare\n"+second+"prepare\nPATH=/custom/bin:$PATH\n")
	if got.Gaps != 0 || len(got.Views) != 2 || got.Views[0].Text() != "printf first\n" || got.Views[1].Text() != "printf second\n" {
		t.Fatalf("unexpected function projections: %+v", got)
	}
}

func TestGeneratedShellUsesFunctionCallSiteBindings(t *testing.T) {
	const write = "cat > \"$out\" <<END\n$first$second example\nEND\n"
	const def = "prepare() {\n" + write + "}\n"
	const firstCall = "out=helper.sh first=printf second=\nprepare\n"
	const secondCall = "out=other.sh first= second=printf\nprepare\n"
	text := def + firstCall + firstCall + secondCall
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || len(got.Views) != 2 {
		t.Fatalf("unexpected function projections: %+v", got)
	}

	want := []string{"$first", "$second"}
	for i, view := range got.Views {
		if view.Text() != "printf example\n" {
			t.Fatalf("unexpected generated body %q", view.Text())
		}
		span, err := view.Original(source.Span{End: len("printf")})
		if err != nil || text[span.Start:span.End] != want[i] {
			t.Fatalf("call %d projected onto %+v, want %q: %v", i, span, want[i], err)
		}
	}
}

func TestGeneratedShellUsesTemporaryFunctionBindings(t *testing.T) {
	const def = "prepare() {\ncat > \"$out\" <<END\n$verb example\nEND\n}\n"
	got := recoverGeneratedShell(t, def+"out=helper.sh verb=printf prepare\n")
	if got.Gaps != 0 || len(got.Views) != 1 || got.Views[0].Text() != "printf example\n" {
		t.Fatalf("unexpected recovery with temporary bindings: %+v", got)
	}
}

func TestGeneratedShellDeduplicatesFunctionExecutionEvidence(t *testing.T) {
	const text = "prepare() {\ncat > helper.sh <<'END'\nprintf example\nEND\nbash helper.sh\n}\nprepare\nprepare\n"
	got := recoverGeneratedShell(t, text)
	if got.Gaps != 0 || got.ExecutionLimited || len(got.Executions) != 1 || len(got.Views) != 1 {
		t.Fatalf("unexpected function execution evidence: %+v", got)
	}
	use := got.Executions[0].Use
	if text[use.Start:use.End] != "bash helper.sh" {
		t.Fatalf("execution mapped to %q", text[use.Start:use.End])
	}
}

func TestGeneratedShellFunctionCallsRespectSharedQuota(t *testing.T) {
	const text = "prepare() {\ncat > helper.sh <<'END'\nprintf first\nEND\n:\n}\nprepare\nprepare\n"
	doc := generatedShellDocument(t, text)
	ctx := analysisbudget.WithLimit(t.Context(), 3)
	got := shell.RecoverGeneratedShellIn(ctx, doc.Units(), document.MaxRegions, document.MaxScanBytes)
	if got.Gaps != document.GeneratedShellUnrecovered || len(got.Views) != 1 || analysisbudget.Used(ctx) != 3 {
		t.Fatalf("unexpected bounded function recovery: %+v, used %d operations", got, analysisbudget.Used(ctx))
	}
}

func TestGeneratedShellRepeatedFunctionWriteDoesNotExhaustRegionCapacity(t *testing.T) {
	const text = "prepare() {\ncat > helper.sh <<'END'\nprintf first\nEND\n}\n" + "prepare\nprepare\n"
	doc := generatedShellDocument(t, text)
	got := shell.RecoverGeneratedShellIn(t.Context(), doc.Units(), 1, len("printf first\n"))
	if got.Gaps != 0 || len(got.Views) != 1 {
		t.Fatalf("identical function write used additional region or bytes: %+v", got)
	}
}

func TestGeneratedShellFunctionRecursionKeepsDistinctPrefixBodies(t *testing.T) {
	const text = "first() {\ncat > first.sh <<'END'\nprintf first\nEND\nsecond\n}\n" +
		"second() {\ncat > second.sh <<'END'\nprintf second\nEND\nfirst\n}\nfirst\n"
	got := recoverGeneratedShell(t, text)
	bodies := make([]string, 0, len(got.Views))
	for _, view := range got.Views {
		bodies = append(bodies, strings.TrimSpace(view.Text()))
	}
	if got.Gaps != document.GeneratedShellUnrecovered || !slices.Equal(bodies, []string{"printf first", "printf second"}) {
		t.Fatalf("unexpected recursive recovery: %v, gaps %b", bodies, got.Gaps)
	}
}
