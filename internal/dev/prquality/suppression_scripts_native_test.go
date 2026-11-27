//go:build !coreonly && cgo

package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestScriptLintSuppressionsInGitDiff(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	gitTest(t, "init", "--quiet")
	gitTest(t, "config", "user.name", "Scout fixture")
	gitTest(t, "config", "user.email", "scout@example.invalid")
	gitTest(t, "config", "commit.gpgsign", "false")
	gitTest(t, "config", "core.hooksPath", filepath.Join(dir, "no-hooks"))

	writeFile(t, "src/main.mjs", "const x = 1;\n")
	writeFile(t, "src/types.mts", "const y: number = 2;\n")
	writeFile(t, "src/view.tsx", "export const View = () => <p>hello</p>;\n")
	writeFile(t, "src/main.py", "import sample  # noqa: F401\n")
	save(t)
	base := gitTest(t, "rev-parse", "HEAD")

	writeFile(t, "src/main.mjs", "/* eslint-disable no-unused-vars */\nconst x = 1;\n")
	writeFile(t, "src/types.mts", "/// @ts-ignore: test fixture\nconst y: number = 2;\n")
	writeFile(t, "src/view.tsx", "/* explanation\n * @ts-ignore */\nexport const View = () => <p>hello</p>;\n")
	writeFile(t, "src/main.py", "\nimport sample  # NoQA: F401, E501\n")
	save(t)

	warnings, err := reviewDiff(t.Context(), base, "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	slices.SortFunc(warnings, func(a, b warning) int { return strings.Compare(a.path, b.path) })
	wants := []struct {
		path, directive string
		line            int
	}{
		{"src/main.mjs", "eslint-disable no-unused-vars", 1},
		{"src/main.py", "# noqa E501", 2},
		{"src/types.mts", "@ts-ignore", 1},
		{"src/view.tsx", "@ts-ignore", 2},
	}
	if len(warnings) != len(wants) {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	for index, want := range wants {
		got := warnings[index]
		if got.path != want.path || got.line != want.line || got.base || got.category != "Lint suppression added" ||
			!strings.Contains(got.detail, `"`+want.directive+`"`) {
			t.Errorf("want %+v, got %+v", want, got)
		}
	}
}

func TestScriptLintSuppressionIgnoresStringsAndInactiveComments(t *testing.T) {
	js := "const literal = '// @ts-ignore';\n" +
		"const template = `text\n/* eslint-disable */\n// @ts-ignore\n`;\n" +
		`const pattern = /\/\* eslint-disable \*\//;` + "\n" +
		"// eslint-disable\n// / @ts-ignore\n/* documentation: @ts-ignore */\n/*\n * @ts-ignore\n */\n"
	py := `doc = r"""
# noqa: F401
"""
value = "# noqa"
# Refer to noqa in the lint guide.
`
	i := newInventory()
	i.readScriptSuppressions(t.Context(), "main.js", suppressionJS, []byte(js))
	i.readScriptSuppressions(t.Context(), "main.py", suppressionPython, []byte(py))
	if warnings := compareInventories(newInventory(), i); len(warnings) != 0 {
		t.Fatalf("examples triggered suppression warnings: %+v", warnings)
	}
}

func TestScriptDirectiveScopeAndStableAnchors(t *testing.T) {
	before := newInventory()
	after := newInventory()
	const base = `/* eslint-disable-next-line
 no-unused-vars, no-console -- old comment
*/
const x=1;
console.log(x);
`
	const head = `
/* eslint-disable-next-line
 no-console, no-unused-vars -- new comment
*/
const x = 1;
console.log(x); // eslint-disable-line no-console
`
	before.readScriptSuppressions(t.Context(), "main.cjs", suppressionJS, []byte(base))
	after.readScriptSuppressions(t.Context(), "main.cjs", suppressionJS, []byte(head))
	if warnings := compareInventories(before, after); len(warnings) != 1 || warnings[0].line != 6 ||
		!strings.Contains(warnings[0].detail, "eslint-disable-line no-console") {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
}

func TestScriptLintSuppressionReportsUnreadableBase(t *testing.T) {
	before, after := newInventory(), newInventory()
	before.readScriptSuppressions(t.Context(), "bad.js", suppressionJS, []byte("const x = ; // eslint-disable-line\n"))
	after.readScriptSuppressions(t.Context(), "bad.js", suppressionJS, []byte("const x = 1; // eslint-disable-line\n"))
	if warnings := compareInventories(before, after); len(warnings) != 1 || warnings[0].category != "Lint suppression check incomplete" || !warnings[0].base {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
}

func TestScriptLintSuppressionIgnoresNarrowedBlanketDirectives(t *testing.T) {
	before, after := newInventory(), newInventory()
	before.readScriptSuppressions(t.Context(), "main.js", suppressionJS, []byte("/* eslint-disable */\nconst x = 1;\n"))
	after.readScriptSuppressions(t.Context(), "main.js", suppressionJS, []byte("/* eslint-disable no-console, no-unused-vars */\nconst x = 1;\n"))
	before.readScriptSuppressions(t.Context(), "main.py", suppressionPython, []byte("import sample  # noqa\n"))
	after.readScriptSuppressions(t.Context(), "main.py", suppressionPython, []byte("import sample  # noqa: F401\n"))
	if warnings := compareInventories(before, after); len(warnings) != 0 {
		t.Fatalf("narrowing a suppression triggered warnings: %+v", warnings)
	}
}
