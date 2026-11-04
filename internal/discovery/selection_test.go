package discovery_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/skarm/scout/internal/discovery"
)

func TestSelectionNarrowsRootsWithoutHidingInventory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(root, "skills", "first"), filepath.Join(root, "skills", "second")
	original := discovery.Snapshot{Complete: false, Targets: []string{root}, Components: []discovery.Component{
		{Kind: "skill", Path: first}, {Kind: "skill", Path: second}, {Kind: "mcp-server", Path: filepath.Join(root, "mcp.json")},
	}, Issues: []discovery.Issue{{Code: "fixture-gap"}}, Limitations: []string{"original limitation"}}
	selected, err := discovery.Select(context.Background(), original, discovery.Filters{Kinds: []string{"skill"}, ExcludePaths: []string{second}})
	if err != nil || !reflect.DeepEqual(selected.Targets, []string{first}) || selected.Complete || !reflect.DeepEqual(selected.Components, original.Components) || !reflect.DeepEqual(selected.Issues, original.Issues) || selected.Selection == nil {
		t.Fatalf("selection widened scope or hid evidence: %+v %v", selected, err)
	}
	if len(original.Limitations) != 1 || !reflect.DeepEqual(original.Targets, []string{root}) {
		t.Fatal("selection mutated its source inventory")
	}
	for _, include := range []string{first, filepath.Join(first, "references")} {
		selected, err := discovery.Select(context.Background(), original, discovery.Filters{IncludePaths: []string{include}})
		if err != nil || !reflect.DeepEqual(selected.Targets, []string{include}) {
			t.Fatalf("include intersection failed: %+v %v", selected.Targets, err)
		}
	}
	selected, err = discovery.Select(context.Background(), original, discovery.Filters{IncludePaths: []string{t.TempDir()}})
	if err != nil || len(selected.Targets) != 0 {
		t.Fatal("path selection expanded discovered roots")
	}
}

func TestSelectionRejectsInvalidFiltersAndCancellation(t *testing.T) {
	snapshot := discovery.Snapshot{Targets: []string{t.TempDir()}}
	for _, filters := range []discovery.Filters{{Kinds: []string{"unknown"}}, {IncludePaths: []string{""}}, {ExcludePaths: []string{"invalid\x00path"}}, {Kinds: make([]string, 33)}} {
		if _, err := discovery.Select(context.Background(), snapshot, filters); err == nil {
			t.Fatal("invalid filter accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discovery.Select(ctx, snapshot, discovery.Filters{Kinds: []string{"skill"}}); err == nil {
		t.Fatal("cancelled selection accepted")
	}
}

func TestSelectionPathAliasesFollowFilesystemSemantics(t *testing.T) {
	for _, names := range [][2]string{{"Skill", "SKILL"}, {"caf\u00e9", "cafe\u0301"}} {
		t.Run(names[0], func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root, alias := filepath.Join(base, names[0]), filepath.Join(base, names[1])
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			original, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			other, err := os.Stat(alias)
			same := err == nil && os.SameFile(original, other)
			if os.IsNotExist(err) {
				if err := os.Mkdir(alias, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			snapshot := discovery.Snapshot{Targets: []string{root}}
			for _, excluded := range []string{alias, filepath.Join(alias, "not-yet-created")} {
				selected, err := discovery.Select(t.Context(), snapshot, discovery.Filters{ExcludePaths: []string{excluded}})
				if err != nil || (len(selected.Targets) == 0) != same {
					t.Fatalf("filesystem alias=%t exclusion=%q targets=%v error=%v", same, excluded, selected.Targets, err)
				}
			}
			for _, included := range []string{alias, filepath.Join(alias, "not-yet-created")} {
				selected, err := discovery.Select(t.Context(), snapshot, discovery.Filters{IncludePaths: []string{included}})
				if err != nil || (len(selected.Targets) == 1) != same {
					t.Fatalf("filesystem alias=%t inclusion=%q targets=%v error=%v", same, included, selected.Targets, err)
				}
			}
		})
	}
}

func TestSelectionResolvesExistingAncestorsOfMissingFilters(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	link := filepath.Join(root, "alias")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	selected, err := discovery.Select(t.Context(), discovery.Snapshot{Targets: []string{root}}, discovery.Filters{IncludePaths: []string{filepath.Join(link, "missing")}})
	if err != nil || len(selected.Targets) != 0 {
		t.Fatalf("missing path hid a symlink outside discovery: targets=%v error=%v", selected.Targets, err)
	}
	cycle := filepath.Join(root, "cycle")
	if err := os.Symlink("cycle", cycle); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(outside, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{cycle, dangling, filepath.Join(dangling, "child")} {
		for _, filters := range []discovery.Filters{{IncludePaths: []string{name}}, {ExcludePaths: []string{name}}} {
			if _, err := discovery.Select(t.Context(), discovery.Snapshot{Targets: []string{root}}, filters); err == nil {
				t.Fatalf("unresolvable path filter was silently ignored: %s", name)
			}
		}
	}
}
