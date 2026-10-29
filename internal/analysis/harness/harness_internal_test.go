// Exercises private implementation details and package fixtures.
package harness

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/skarm/scout/report"
)

func TestNamespaceSelectionPreservesBoundariesAndOrdering(t *testing.T) {
	n := namespace{
		entries: map[string]*entry{},
		names:   []string{"../outside", ".mcp.json", "a", "a-else", "a/b", "a/c", "a0/other", "ab/other", "z"},
	}
	sort.Strings(n.names)
	for _, name := range n.names {
		n.entries[name] = &entry{name: name}
	}
	for _, tc := range []struct {
		name string
		want []string
	}{
		{name: "a", want: []string{"a", "a/b", "a/c"}},
		{name: "a/b", want: []string{"a/b"}},
		{name: "ab", want: []string{"ab/other"}},
		{name: "absent", want: nil},
		{name: ".", want: []string{".mcp.json", "a", "a-else", "a/b", "a/c", "a0/other", "ab/other", "z"}},
	} {
		if got := n.selectNames(tc.name); !reflect.DeepEqual(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
			t.Fatalf("%q: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := n.descendants("."); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestReferencePublicationKeepsBudgetAndTargetGuarantees(t *testing.T) {
	b := builder{
		ctx:        context.Background(),
		r:          report.ComponentGraph{Limits: Limits()},
		references: map[string]bool{},
		issues:     map[string]bool{},
	}
	p := plugin{b: &b, id: "plugin", rootNode: "root"}
	p.reference("", "handler", "resolved", "captured", "target", nil)
	if len(b.r.References) != 0 {
		t.Fatal("orphan reference published")
	}
	p.reference("component", "handler", "resolved", "captured", "", nil)
	p.reference("component", "handler", "resolved", "captured", "", nil)
	if len(b.r.References) != 1 || b.r.References[0].Status != "unresolved" || b.r.References[0].Reason != "component_graph_budget_exceeded" {
		t.Fatal(b.r.References)
	}
	source := &report.SourceRef{Path: "config", ByteStart: 1, ByteEnd: 3}
	p.reference("component", "handler", "resolved", "captured", "target", source)
	if len(b.r.References) != 2 || b.r.References[1].TargetID != "target" {
		t.Fatal(b.r.References)
	}
	b.r.Limits.References = 2
	p.reference("component", "remote", "unresolved", "external", "", source)
	if len(b.r.References) != 2 {
		t.Fatal("reference cap exceeded")
	}
	found := false
	for _, issue := range b.r.Issues {
		if issue.Code == "plugin_reference_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal(b.r.Issues)
	}
}
