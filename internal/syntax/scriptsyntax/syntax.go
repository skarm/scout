// Package scriptsyntax captures bounded JavaScript/TypeScript syntax into
// Go-owned trees. It never executes JavaScript, resolves imports or runs Node.
package scriptsyntax

import (
	"context"
	"errors"
)

const (
	MaxBytes = 256 << 10
	maxNodes = 16384
	maxDepth = 64
)

// ErrLimit means the parser exceeded its byte, time or syntax-tree budget.
var ErrLimit = errors.New("script parser limit")

type Node struct {
	Kind, Field string
	Start, End  int
	Invalid     bool
	Children    []*Node
}

type Tree struct {
	Root *Node
}

func (n *Node) Child(field string) *Node {
	if n != nil {
		for _, c := range n.Children {
			if c.Field == field {
				return c
			}
		}
	}

	return nil
}

func Parse(ctx context.Context, language, text string) (Tree, error) {
	return parse(ctx, language, text)
}
