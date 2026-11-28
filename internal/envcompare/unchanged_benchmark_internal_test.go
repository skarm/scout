package envcompare

import (
	"fmt"
	"testing"

	"github.com/skarm/scout/internal/capture/envsnapshot"
)

func BenchmarkUnchangedRootDetails(b *testing.B) {
	entries := make([]envsnapshot.Entry, 2048)
	for i := range entries {
		entries[i] = envsnapshot.Entry{Path: fmt.Sprintf("entry-%04d.txt", i), SHA256: "78dc3091c25e4603a3cbcc7993c9d26edd341f92a78ad88003e68a9a8ef542776"}
	}

	before := envsnapshot.Snapshot{Roots: []envsnapshot.Root{{ID: "main", Source: "/previous", Directory: true, Entries: entries}}}
	after := envsnapshot.Snapshot{Roots: []envsnapshot.Root{{ID: "main", Source: "/candidate", Directory: true, Entries: entries}}}
	result := Comparison{Roots: []environmentRootChange{{ID: "main", Change: "unchanged"}}}

	b.ReportAllocs()
	for b.Loop() {
		result.describeContent(before, after, false)
	}

	root := result.Roots[0]
	if root.BeforePath != "/previous" || root.AfterPath != "/candidate" || len(root.Content) != 0 {
		b.Fatal("unchanged root details differ")
	}
}
