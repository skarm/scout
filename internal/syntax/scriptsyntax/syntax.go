// Package scriptsyntax captures bounded JavaScript/TypeScript syntax into
// Go-owned trees. It never executes JavaScript, resolves imports or runs Node.
package scriptsyntax

import "context"

const (
	MaxBytes = 256 << 10
	maxNodes = 16384
	maxDepth = 64
)

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
