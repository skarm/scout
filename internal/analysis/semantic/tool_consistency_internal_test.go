package semantic

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/review"
)

func TestScopeIndexKeepsNamespacesBoundariesAndStableTieOrder(t *testing.T) {
	makeScope := func(file, namespace, root string) toolScope {
		return toolScope{
			file:      artifact.NewFile(file, nil, false),
			address:   toolAddress{namespace: namespace},
			root:      root,
			described: true,
		}
	}
	scopes := []toolScope{
		makeScope("later", "left", "pkg"),
		makeScope("first", "left", "pkg"),
		makeScope("nested", "left", "pkg/nested"),
		makeScope("right", "right", "pkg"),
		makeScope("root", "left", "."),
	}
	index := indexToolScopes(scopes)
	for _, tc := range []struct{ namespace, name, want string }{
		{namespace: "left", name: "pkg/run.py", want: "first"},
		{namespace: "left", name: "pkg/nested/sub/run.py", want: "nested"},
		{namespace: "right", name: "pkg/nested/run.py", want: "right"},
		{namespace: "left", name: "pkg-sibling/run.py", want: "root"},
		{namespace: "absent", name: "pkg/run.py", want: ""},
		{namespace: "left", name: "run.py", want: "root"},
	} {
		scope := containingToolScope(toolAddress{namespace: tc.namespace, name: tc.name}, index)
		got := ""
		if scope != nil {
			got = scope.file.Metadata().Path
		}
		if got != tc.want {
			t.Fatalf("%s/%s selected %q, want %q", tc.namespace, tc.name, got, tc.want)
		}
	}
}

func TestCodeConsistencyCancellationIsVisibleBeforeAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decl := artifact.NewFile("SKILL.md", []byte("---\ndescription: Local text\n---\n"), false)
	code := artifact.NewFile("handler.py", []byte("print('inert')"), false)
	p := planner{ctx: ctx, options: review.DefaultOptions(), files: map[string]artifact.File{"handler.py": code}}
	index := indexToolScopes([]toolScope{{
		file:      decl,
		address:   toolAddress{namespace: "snapshot"},
		root:      ".",
		described: true,
	}})
	p.planCodeConsistency("handler.py", toolAddress{namespace: "snapshot", name: "handler.py"}, index)
	if len(p.works) != 0 || len(p.gaps) != 1 || p.gaps[0].Code != "tool_consistency_planning_cancelled" || p.gaps[0].Path != "handler.py" {
		t.Fatalf("cancelled scoped planning disappeared or admitted a request: %+v %+v", p.works, p.gaps)
	}
}

func BenchmarkToolScopePlanningUnrelatedCode(b *testing.B) {
	for _, count := range []int{512, 1024, 2048} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			p := planner{ctx: context.Background(), options: review.DefaultOptions(), files: map[string]artifact.File{}}
			for i := range count {
				name := fmt.Sprintf("package-%04d/SKILL.md", i)
				p.files[name] = artifact.NewFile(name, []byte("---\ndescription: Only local text\n---\n"), false)
				name = fmt.Sprintf("unrelated-%04d/run.py", i)
				p.files[name] = artifact.NewFile(name, []byte("print('inert')"), false)
			}
			b.ResetTimer()
			for range b.N {
				p.planToolConsistency()
				if len(p.works) != 0 || len(p.gaps) != 0 {
					b.Fatal("benchmark unexpectedly admitted review work")
				}
			}
		})
	}
}
