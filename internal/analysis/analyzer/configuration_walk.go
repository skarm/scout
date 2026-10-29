package analyzer

import (
	"context"
	"iter"
	"slices"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type configurationOrder uint8

const (
	configurationForward configurationOrder = iota
	configurationReverse
)

type configurationNode struct {
	node  *jsonconfig.Node
	depth int
}

// Prepared configuration trees use a bounded depth-first traversal with stable
// member order. Yielding before expansion lets consumers stop at their own
// finding/operation boundary without walking an unvisited subtree.
func configurationNodes(ctx context.Context, root *jsonconfig.Node, maxDepth int, order configurationOrder) iter.Seq[configurationNode] {
	return func(yield func(configurationNode) bool) {
		stack := []configurationNode{{node: root}}
		for len(stack) > 0 {
			if ctx.Err() != nil {
				return
			}

			entry := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			if entry.node == nil {
				continue
			}

			if !yield(entry) {
				return
			}

			if entry.depth > maxDepth {
				continue
			}

			start := len(stack)
			for _, member := range entry.node.Members {
				stack = append(stack, configurationNode{node: member.Value, depth: entry.depth + 1})
			}

			for _, element := range entry.node.Elements {
				stack = append(stack, configurationNode{node: element, depth: entry.depth + 1})
			}

			if order == configurationForward {
				slices.Reverse(stack[start:])
			}
		}
	}
}

func configStringNodes(ctx context.Context, root *jsonconfig.Node) iter.Seq[*jsonconfig.Node] {
	return func(yield func(*jsonconfig.Node) bool) {
		for entry := range configurationNodes(ctx, root, 64, configurationReverse) {
			if entry.node.Kind == jsonconfig.KindString && !yield(entry.node) {
				return
			}
		}
	}
}
