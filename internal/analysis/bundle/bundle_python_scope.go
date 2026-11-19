package bundle

import (
	"errors"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// A write anywhere in a Python function makes the name local throughout that
// function, unless explicitly declared global/nonlocal. Nested bodies own their
// bindings; definition expressions are still evaluated in the enclosing scope.
func (b *bundleAnalysis) pythonFunctionLocals(nodes []*frontend.Node, names map[string]bool) {
	outer := map[string]bool{}
	b.pythonLocalBindings(nodes, names, outer, 0)

	for name := range outer {
		delete(names, name)
	}
}

func (b *bundleAnalysis) pythonLocalBindings(nodes []*frontend.Node, names, outer map[string]bool, depth int) {
	if depth > maxBundleProjectionDepth {
		b.err = errors.New("python local binding depth limit")
		return
	}

	for _, n := range nodes {
		if n == nil {
			continue
		}

		if !b.step() {
			return
		}

		switch n.Kind() {
		case frontend.FunctionDef, frontend.AsyncFunctionDef, frontend.ClassDef, frontend.Lambda:
			if name := n.String(frontend.FieldName); name != "" {
				names[name] = true
			}

			b.pythonLocalBindings([]*frontend.Node{n.Child(frontend.Args), n.Child(frontend.Returns)}, names, outer, depth+1)

			for _, field := range []frontend.FieldKind{frontend.DecoratorList, frontend.Bases, frontend.Keywords} {
				b.pythonLocalBindings(n.List(field), names, outer, depth+1)
			}

			continue
		case frontend.Global, frontend.Nonlocal:
			declared, _ := n.Field(frontend.Names).Strings()
			for _, name := range declared {
				outer[name] = true
			}
		case frontend.Import, frontend.ImportFrom:
			for _, alias := range n.List(frontend.Names) {
				name, _ := pythonImportBinding(n, alias)
				names[name] = true
			}
		case frontend.Assign, frontend.Delete:
			for _, target := range n.List(frontend.Targets) {
				b.pythonLocalTarget(target, names, depth+1)
			}
		case frontend.AnnAssign, frontend.AugAssign, frontend.NamedExpr, frontend.For, frontend.AsyncFor:
			b.pythonLocalTarget(n.Child(frontend.Target), names, depth+1)
		case frontend.WithItem:
			b.pythonLocalTarget(n.Child(frontend.OptionalVars), names, depth+1)
		case frontend.ExceptHandler:
			if name := n.String(frontend.FieldName); name != "" {
				names[name] = true
			}
		}

		b.pythonLocalBindings(n.Children(), names, outer, depth+1)
	}
}

func (b *bundleAnalysis) pythonLocalTarget(n *frontend.Node, names map[string]bool, depth int) {
	if n == nil || !b.step() {
		return
	}

	if depth > maxBundleProjectionDepth {
		b.err = errors.New("python local target depth limit")
		return
	}

	switch n.Kind() {
	case frontend.Name:
		names[n.String(frontend.ID)] = true
	case frontend.Tuple, frontend.List:
		for _, child := range n.List(frontend.Elts) {
			b.pythonLocalTarget(child, names, depth+1)
		}
	case frontend.Starred:
		b.pythonLocalTarget(n.Child(frontend.FieldValue), names, depth+1)
	}
}
