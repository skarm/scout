//go:build !coreonly && cgo

package main

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/treeparse"

	sitter "github.com/tree-sitter/go-tree-sitter"
	javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

const (
	maxSuppressionSourceBytes = 1 << 20
	maxSuppressionNodes       = 65536
	suppressionParseTimeout   = time.Second
	maxSuppressionDepth       = 256
)

func scanScriptSuppressionSyntax(ctx context.Context, lang string, data []byte) (suppressionSyntax, error) {
	if len(data) > maxSuppressionSourceBytes {
		return suppressionSyntax{}, errors.New("lint directive analysis exceeded the source size limit")
	}

	if !utf8.Valid(data) {
		return suppressionSyntax{}, errors.New("lint directive analysis requires UTF-8 source")
	}

	parser := treeparse.NewParser()
	defer parser.Close()

	grammar := javascript.Language()

	switch lang {
	case suppressionTS:
		grammar = typescript.LanguageTypescript()
	case suppressionTSX:
		grammar = typescript.LanguageTSX()
	case suppressionPython:
		grammar = python.Language()
	}

	if err := parser.SetLanguage(sitter.NewLanguage(grammar)); err != nil {
		return suppressionSyntax{}, err
	}

	deadline := time.Now().Add(suppressionParseTimeout)

	tree := treeparse.Parse(ctx, parser, data, deadline)
	if tree == nil {
		return suppressionSyntax{}, errors.New("lint directive parser stopped before completing")
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.HasError() {
		return suppressionSyntax{}, errors.New("syntax errors prevent reliable lint directive analysis")
	}

	var syntax suppressionSyntax

	budget := maxSuppressionNodes
	if !syntax.walk(ctx, root, uint(len(data)), 0, &budget) {
		return suppressionSyntax{}, errors.New("lint directive syntax traversal did not complete")
	}

	return syntax, nil
}

func (s *suppressionSyntax) walk(ctx context.Context, node *treeparse.Node, size uint, depth int, budget *int) bool {
	if node == nil || ctx.Err() != nil || *budget == 0 || depth > maxSuppressionDepth {
		return false
	}

	*budget--

	span := sourceSpan{node.StartByte(), node.EndByte()}
	if span.start > span.end || span.end > size {
		return false
	}

	if node.Kind() == "comment" {
		if span.start < span.end {
			s.comments = append(s.comments, span)
		}

		return true
	}

	count := node.ChildCount()
	if count == 0 && span.start < span.end {
		s.tokens = append(s.tokens, span)
	}

	for child := range count {
		if !s.walk(ctx, node.Child(child), size, depth+1, budget) {
			return false
		}
	}

	return true
}
