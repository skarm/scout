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

const nativeParseTimeout = time.Second

type capture struct {
	ctx         context.Context
	size, count int
	text        string
}

func Available() bool { return true }

func parse(ctx context.Context, lang, text string) (Tree, error) {
	if err := ctx.Err(); err != nil {
		return Tree{}, err
	}

	if len(text) > MaxBytes {
		return Tree{}, ErrLimit
	}

	if !utf8.ValidString(text) {
		return Tree{}, errors.New("invalid script encoding")
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

	deadline := time.Now().Add(nativeParseTimeout)
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
		if err := ctx.Err(); err != nil {
			return Tree{}, err
		}

		return Tree{}, ErrLimit
	}
	defer tree.Close()

	capture := capture{ctx: ctx, size: len(text), text: text}

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
	if depth > maxDepth || p.count > maxNodes {
		return nil, ErrLimit
	}

	if n == nil {
		return nil, errors.New("invalid script tree")
	}

	start, end := n.StartByte(), n.EndByte()
	if start > end || end > uint(p.size) {
		return nil, errors.New("invalid script tree")
	}

	out := &Node{
		Kind:    n.Kind(),
		Field:   field,
		Start:   int(start),
		End:     int(end),
		Invalid: n.IsError() || n.IsMissing(),
	}
	if _, err := IdentifierText(out.Kind, p.text[out.Start:out.End]); err != nil {
		return nil, err
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
