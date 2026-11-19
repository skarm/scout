//nolint:testpackage // Exercises scope copying through the internal traversal and its operation budget.
package shell

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestShellFunctionScopesRespectBudget(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		functions, variables int
		quota                uint64
		limited              bool
	}{
		{"growing function table", 64, 0, 128, true},
		{"copy variables", 1, 32, 8, true},
		{"sufficient budget", 64, 32, 10000, false},
		{"local traversal ceiling", 512, 0, 1 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := analysisbudget.WithLimit(t.Context(), tc.quota)
			state := newShellState()
			for i := range tc.variables {
				state.vars[fmt.Sprintf("v%d", i)] = shellValue{text: "sample", known: true}
			}
			file := localFunctions(tc.functions)
			walk := shellWalk{ctx: ctx}
			walk.list(file, state)
			if (walk.err != nil) != tc.limited {
				t.Fatalf("functions retained=%d, operations=%d, err=%v", len(state.functions), walk.operations, walk.err)
			}
			if !tc.limited && len(state.functions) != tc.functions {
				t.Fatal("lost function definitions with sufficient budget")
			}
			if tc.functions > 1 && tc.limited && (len(state.functions) == 0 || len(state.functions) == tc.functions) {
				t.Fatalf("incomplete traversal retained %d of %d definitions", len(state.functions), tc.functions)
			}
		})
	}
}

func TestCancelledShellScopeTraversalPreservesParent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	state := newShellState()
	state.vars["original"] = shellValue{text: "unchanged", known: true}
	file := &shellsyntax.File{Statements: []*shellsyntax.Statement{{Commands: []*shellsyntax.Command{{FunctionName: "pending", FunctionBody: &shellsyntax.File{}}}}}}
	walk := shellWalk{ctx: ctx}
	walk.list(file, state)
	if !errors.Is(walk.err, context.Canceled) || len(state.functions) != 0 || state.vars["original"].text != "unchanged" {
		t.Fatalf("cancelled walk mutated state: %+v, %v", state, walk.err)
	}
}

func localFunctions(count int) *shellsyntax.File {
	file := &shellsyntax.File{}
	for i := range count {
		command := &shellsyntax.Command{FunctionName: fmt.Sprintf("local%d", i), FunctionBody: &shellsyntax.File{}}
		file.Statements = append(file.Statements, &shellsyntax.Statement{Commands: []*shellsyntax.Command{command}})
	}
	return file
}

func TestSourceWalkerScopesRespectBudget(t *testing.T) {
	for _, quota := range []uint64{128, 8192} {
		ctx := analysisbudget.WithLimit(t.Context(), quota)
		w := shellSourceWalker{ctx: ctx, variables: map[string]string{}, functions: map[string]*shellsyntax.File{}}
		w.walk(localFunctions(64), 0)
		if w.truncated != (quota == 128) || (len(w.functions) == 64) == w.truncated {
			t.Fatalf("quota=%d, functions=%d, truncated=%v", quota, len(w.functions), w.truncated)
		}
	}
}

func TestSourceBranchBudgetKeepsParent(t *testing.T) {
	for _, quota := range []uint64{8, 512} {
		w := shellSourceWalker{ctx: analysisbudget.WithLimit(t.Context(), quota), variables: map[string]string{}, functions: map[string]*shellsyntax.File{}}
		for i := range 32 {
			w.variables[fmt.Sprintf("v%d", i)] = "original"
		}
		w.alternatives([]*shellsyntax.File{localFunctions(1), localFunctions(1)}, 0)
		if w.truncated != (quota == 8) || len(w.variables) != 32 || w.variables["v31"] != "original" {
			t.Fatalf("quota=%d, variables=%d, truncated=%v", quota, len(w.variables), w.truncated)
		}
	}
}

func TestSourceScopeLimitRetainsEarlierDeclaration(t *testing.T) {
	var script strings.Builder
	const first = "npm config set registry https://first.invalid"
	const last = "npm config set registry https://last.invalid"
	fmt.Fprintln(&script, first)
	for i := range 64 {
		fmt.Fprintf(&script, "local%d() { :; }\n", i)
	}
	fmt.Fprintln(&script, last)
	text := script.String()
	file := document.Prepare(t.Context(), artifact.NewFile("setup.sh", []byte(text), false))
	for _, quota := range []uint64{256, 8192, 256} {
		var found []string
		limited := SourceDeclarations(analysisbudget.WithLimit(t.Context(), quota), file, func(span source.Span) {
			found = append(found, text[span.Start:span.End])
		}, nil)
		want := []string{first}
		if quota == 8192 {
			want = append(want, last)
		}
		if limited != (quota == 256) || !slices.Equal(found, want) {
			t.Fatalf("quota=%d limited=%t declarations=%q", quota, limited, found)
		}
	}
}
