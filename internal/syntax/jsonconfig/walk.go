package jsonconfig

import (
	"context"
	"iter"
	"slices"
)

type WalkOrder uint8

const (
	SourceOrder WalkOrder = iota
	ReverseSourceOrder
)

type WalkEntry struct {
	Node  *Node
	Depth int
}

// Walk visits nodes depth-first in the selected order. It yields a node before
// expanding children, including the first level beyond maxDepth so consumers
// can detect the depth boundary. Cancellation stops the walk.
func Walk(ctx context.Context, root *Node, maxDepth int, order WalkOrder) iter.Seq[WalkEntry] {
	return func(yield func(WalkEntry) bool) {
		stack := []WalkEntry{{Node: root}}
		for len(stack) > 0 {
			if ctx.Err() != nil {
				return
			}

			entry := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			if entry.Node == nil {
				continue
			}

			if !yield(entry) {
				return
			}

			if entry.Depth > maxDepth {
				continue
			}

			start := len(stack)
			for _, member := range entry.Node.Members {
				stack = append(stack, WalkEntry{Node: member.Value, Depth: entry.Depth + 1})
			}

			for _, element := range entry.Node.Elements {
				stack = append(stack, WalkEntry{Node: element, Depth: entry.Depth + 1})
			}

			if order == SourceOrder {
				slices.Reverse(stack[start:])
			}
		}
	}
}
