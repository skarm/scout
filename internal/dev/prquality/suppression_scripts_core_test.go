//go:build coreonly || !cgo

package main

import "testing"

func TestScriptLintSuppressionWithoutNativeParsersIsReported(t *testing.T) {
	i := newInventory()
	i.readScriptSuppressions(t.Context(), "main.js", suppressionJS, []byte("const x = 1;\n"))
	i.readScriptSuppressions(t.Context(), "main.py", suppressionPython, []byte("import sample  # noqa: F401\n"))
	if warnings := compareInventories(newInventory(), i); len(warnings) != 1 || warnings[0].path != "main.py" ||
		warnings[0].category != "Lint suppression check incomplete" {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
}
