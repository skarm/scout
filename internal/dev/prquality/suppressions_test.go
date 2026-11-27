package main

import (
	"slices"
	"strings"
	"testing"
)

func TestReviewFindsAddedGoSuppressionDirectives(t *testing.T) {
	const before = `package sample
var untouched = 1 //nolint:gosec // prior justification
var first = 2 //nolint:revive
var second = 3
var third = 4 // #nosec G101 -- prior justification
var fourth = 5
var fifth = 6
var sixth = 7
`
	const after = `//lint:file-ignore ST1003 example
package sample

var untouched=1 //nolint:gosec // rewritten justification
var first = 2
var second = 3 //nolint:revive
var third = 4 // #nosec G101 G102 -- G404 is only part of the reason
//lint:ignore SA4000 fixture
var fourth = 5
var fifth = 6 /* #nosec G201 */
var sixth = 7 //gosec:disable G202 -- fixture
var text = "//nolint:unused"
// An example of lint:ignore SA9999
`

	base, head := newInventory(), newInventory()
	base.readGoSuppressions("example.go", []byte(before))
	head.readGoSuppressions("example.go", []byte(after))
	warnings := compareInventories(base, head)
	slices.SortFunc(warnings, func(a, b warning) int { return a.line - b.line })
	wants := []struct {
		line      int
		directive string
	}{
		{1, "lint:file-ignore ST1003"},
		{6, "nolint revive"},
		{7, "#nosec G102"},
		{8, "lint:ignore SA4000"},
		{10, "#nosec G201"},
		{11, "gosec:disable G202"},
	}
	if len(warnings) != len(wants) {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}
	for index, want := range wants {
		item := warnings[index]
		if item.category != "Go lint suppression added" || item.base || item.path != "example.go" || item.line != want.line ||
			!strings.Contains(item.detail, `"`+want.directive+`"`) {
			t.Errorf("wanted %+v, got %+v", want, item)
		}
	}
}

func TestReviewReportsBroadenedGoSuppression(t *testing.T) {
	const prefix = "package sample\nvar example = 1 "
	for _, tc := range []struct{ directive, added string }{
		{"//nolint:gosec,revive // two linters", "nolint revive"},
		{"//nolint // blanket suppression", "nolint"},
	} {
		base, head := newInventory(), newInventory()
		base.readGoSuppressions("sample.go", []byte(prefix+"//nolint:gosec\n"))
		head.readGoSuppressions("sample.go", []byte(prefix+tc.directive+"\n"))
		warnings := compareInventories(base, head)
		if len(warnings) != 1 || !strings.Contains(warnings[0].detail, `"`+tc.added+`"`) {
			t.Errorf("unexpected warnings: %+v", warnings)
		}
	}
}

func TestReviewIgnoresNarrowedGoSuppression(t *testing.T) {
	before, after := newInventory(), newInventory()
	before.readGoSuppressions("sample.go", []byte("package sample\nvar n = 1 //nolint\n"))
	after.readGoSuppressions("sample.go", []byte("package sample\nvar n = 1 //nolint:gosec,revive\n"))
	if warnings := compareInventories(before, after); len(warnings) != 0 {
		t.Fatalf("narrowing a suppression triggered warnings: %+v", warnings)
	}
}
