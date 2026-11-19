package harness

import "maps"

// Frames share outer binding cells. A declaration creates a new cell; an
// assignment invalidates the existing cell, including references in closures.
// Copying a function into another binding still preserves that function value.
func (b nodeHookBindings) bind(name string, value nodeHookValue) { b[name] = &value }

func (b nodeHookBindings) value(name string) nodeHookValue {
	if value := b[name]; value != nil {
		return *value
	}

	return nodeHookValue{}
}

func (b nodeHookBindings) invalidate(name string) {
	if value := b[name]; value != nil {
		*value = nodeHookValue{}
	} else {
		b.bind(name, nodeHookValue{})
	}
}

// Unknown alternatives need independent cells, including environments captured
// by functions declared before the branch. The queue handles cyclic closures
// without recursive copying; every binding visit uses the existing work budget.
func (w *nodeHookWalk) forkBindings(bindings nodeHookBindings) (nodeHookBindings, map[*nodeHookValue]*nodeHookValue) {
	type frame struct{ from, to *nodeHookBindings }

	cells := make(map[*nodeHookValue]*nodeHookValue)
	scopes := make(map[*nodeHookBindings]*nodeHookBindings)

	var pending []frame

	cloneScope := func(scope *nodeHookBindings) *nodeHookBindings {
		if scope == nil {
			return nil
		}

		if clone := scopes[scope]; clone != nil {
			return clone
		}

		clone := make(nodeHookBindings, len(*scope))
		scopes[scope] = &clone
		pending = append(pending, frame{scope, &clone})

		return &clone
	}
	root := cloneScope(&bindings)

	for i := 0; i < len(pending); i++ {
		current := pending[i]
		for name, value := range *current.from {
			if !w.plugin.b.step() {
				return *root, cells
			}

			clone := cells[value]
			if clone == nil {
				copied := *value
				clone = &copied
				cells[value] = clone
				clone.scope = cloneScope(value.scope)
			}

			(*current.to)[name] = clone
		}
	}

	return *root, cells
}

func mergeNodeHookCells(cells map[*nodeHookValue]*nodeHookValue) {
	for original, branch := range cells {
		if branch.kind == nodeHookUnknown {
			*original = nodeHookValue{}
		}
	}
}

// A shallow frame retains shared outer cells; admission must precede copying
// the namespace so a failed call cannot publish a partial environment.
func (w *nodeHookWalk) cloneBindings(bindings nodeHookBindings) (nodeHookBindings, bool) {
	if !w.plugin.b.spend(len(bindings)) {
		return nil, false
	}

	return maps.Clone(bindings), true
}

func (w *nodeHookWalk) mergeCells(left, right map[*nodeHookValue]*nodeHookValue) {
	if !w.plugin.b.spend(len(left) + len(right)) {
		return
	}

	mergeNodeHookCells(left)
	mergeNodeHookCells(right)
}
