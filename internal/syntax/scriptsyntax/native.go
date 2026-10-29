//go:build !coreonly && cgo

package scriptsyntax

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/treeparse"

	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

type capture struct {
	ctx         context.Context
	size, count int
}

func Available() bool { return true }

func parse(ctx context.Context, lang, text string) (Tree, error) {
	if len(text) > MaxBytes || !utf8.ValidString(text) {
		return Tree{}, errors.New("script input limit or encoding")
	}

	parser := treeparse.NewParser()
	defer parser.Close()

	grammar := javascript.Language()
	if lang == language.TypeScript {
		grammar = typescript.LanguageTypescript()
	}

	if err := parser.SetLanguage(sitter.NewLanguage(grammar)); err != nil {
		return Tree{}, errors.New("script grammar ABI")
	}

	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	tree := treeparse.Parse(ctx, parser, []byte(text), deadline)
	if tree != nil && tree.RootNode().HasError() && lang == language.TypeScript {
		tree.Close()
		parser.Reset()

		if err := parser.SetLanguage(sitter.NewLanguage(typescript.LanguageTSX())); err != nil {
			return Tree{}, err
		}

		tree = treeparse.Parse(ctx, parser, []byte(text), deadline)
	}

	if tree == nil {
		return Tree{}, errors.New("script parser timeout")
	}
	defer tree.Close()

	capture := capture{ctx: ctx, size: len(text)}

	root, err := capture.node(tree.RootNode(), 0, "")
	if err == nil && tree.RootNode().HasError() {
		err = errors.New("script syntax error")
	}

	return Tree{Root: root}, err
}

func (p *capture) node(n *treeparse.Node, depth int, field string) (*Node, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}

	p.count++
	if n == nil || depth > maxDepth || p.count > maxNodes || n.EndByte() > uint(p.size) {
		return nil, errors.New("script tree limit")
	}

	out := &Node{
		Kind:    n.Kind(),
		Field:   field,
		Start:   int(n.StartByte()),
		End:     int(n.EndByte()),
		Invalid: n.IsError() || n.IsMissing(),
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
