package shell

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func Collect(ctx context.Context, doc document.File, facts *check.FileLanguageFacts) {
	outputs := map[string]*check.Facts{}

	for _, id := range []string{ruleSH001, ruleSH002, ruleSH003, ruleSH004} {
		if output := facts.Rules[id]; output != nil {
			outputs[id] = output
		}
	}

	if len(outputs) > 0 {
		walkShellFacts(ctx, doc, outputs, executionShellTree)
	}

	if output := facts.Rules[ruleNVSC2]; output != nil {
		// The declaration projection accepts broader syntax than execution-flow rules.
		walkShellFacts(ctx, doc, map[string]*check.Facts{ruleSH001: output}, declarationShellTree)
	}
}

// ObserveDownload reuses the bounded execution-flow walker for mapped prose candidates.
// Operations is the cumulative count across candidates in this preparation pass.
func observeDownload(ctx context.Context, tree *shellsyntax.File, view source.View, limit, operations int) (result, int, error) {
	w := shellWalk{ctx: ctx, kind: ruleSH001, limit: limit, view: view, operations: operations}
	w.list(tree, newShellState())

	return w.result, w.operations, errors.Join(w.err, w.gap)
}

func executionShellTree(tree parse.ShellTree) *shellsyntax.File { return tree.Tree }

func declarationShellTree(tree parse.ShellTree) *shellsyntax.File {
	if tree.Declarations != nil {
		return tree.Declarations
	}

	return tree.Tree
}

func walkShellFacts(ctx context.Context, doc document.File, outputs map[string]*check.Facts, selectTree func(parse.ShellTree) *shellsyntax.File) {
	walk := shellWalk{ctx: ctx, outputs: outputs}

	for _, unit := range doc.Units() {
		tree, ok := unit.Tree.(parse.ShellTree)
		if !ok {
			continue
		}

		root := selectTree(tree)
		if root == nil {
			continue
		}

		walk.view = unit.View
		walk.list(root, newShellState())

		if walk.err != nil {
			break
		}
	}

	for _, output := range outputs {
		output.Finish(errors.Join(walk.err, walk.gap, ctx.Err()), false)
	}
}
