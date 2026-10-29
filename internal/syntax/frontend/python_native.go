//go:build !coreonly && cgo

package frontend

import (
	"context"
	"time"

	"github.com/skarm/scout/internal/syntax/treeparse"

	sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

type pythonCapture struct {
	ctx         context.Context
	size, count int
}

func pythonAvailable() bool { return true }

func parsePython(ctx context.Context, text string) (*Node, error) {
	parser := treeparse.NewParser()
	defer parser.Close()

	deadline, err := configurePythonParser(ctx, parser)
	if err != nil {
		return nil, err
	}

	tree := treeparse.Parse(ctx, parser, []byte(text), deadline)
	if tree == nil {
		return nil, &Failure{Category: "deadline"}
	}
	defer tree.Close()

	if ctx.Err() != nil {
		return nil, &Failure{Category: "deadline"}
	}

	root := tree.RootNode()
	if root == nil || root.HasError() {
		return nil, &Failure{Category: codeInvalid}
	}

	capture := pythonCapture{ctx: ctx, size: len(text)}

	syntax, err := capture.node(root, 0, "")
	if err != nil {
		return nil, err
	}

	return normalizePython(ctx, text, syntax)
}

func (p *pythonCapture) node(n *treeparse.Node, depth int, field string) (*pythonSyntax, error) {
	p.count++
	if p.count > maxNodes || depth > MaxDepth {
		return nil, &Failure{Category: "limit"}
	}

	if p.ctx.Err() != nil {
		return nil, &Failure{Category: "deadline"}
	}

	if !validPythonCST(n, p.size) {
		return nil, &Failure{Category: "invalid_tree"}
	}

	out := &pythonSyntax{
		Kind:  n.Kind(),
		Start: int(n.StartByte()),
		End:   int(n.EndByte()),
		Field: field,
		Named: n.IsNamed(),
	}
	for i := uint(0); i < n.ChildCount(); i++ {
		child, err := p.node(n.Child(i), depth+1, n.FieldNameForChild(uint32(i)))
		if err != nil {
			return nil, err
		}

		out.Children = append(out.Children, child)
	}

	return out, nil
}

func validPythonCST(n *treeparse.Node, size int) bool {
	return n != nil && !n.IsError() && !n.IsMissing() && n.EndByte() <= uint(size) && n.StartByte() <= n.EndByte()
}

func configurePythonParser(ctx context.Context, parser *treeparse.Parser) (time.Time, error) {
	if err := parser.SetLanguage(sitter.NewLanguage(python.Language())); err != nil {
		return time.Time{}, &Failure{Category: "grammar_abi"}
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Time{}, &Failure{Category: "deadline"}
	}

	if time.Until(deadline) < time.Microsecond {
		return time.Time{}, &Failure{Category: "deadline"}
	}

	return deadline, nil
}
