// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"maps"

	"github.com/skarm/scout/internal/syntax/frontend"
)

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyEvaluatedExpressions map[frontend.NodeKind]pyExpression

type pyExpression func(*pyWalker, *frontend.Node, *pyState, int) pyValue

//nolint:gochecknoinits // Registered methods recurse through this table; a variable initializer creates an initialization cycle.
func init() {
	pyEvaluatedExpressions = map[frontend.NodeKind]pyExpression{
		frontend.UnsupportedExpression: (*pyWalker).unknownExpr,
		frontend.UnsupportedStatement:  (*pyWalker).unknownExpr,
		frontend.BoolOp:                (*pyWalker).booleanExpr,
		frontend.IfExp:                 (*pyWalker).conditionalExpr,
		frontend.Attribute:             (*pyWalker).attributeExpr,
		frontend.Subscript:             (*pyWalker).subscriptExpr,
		frontend.Call:                  (*pyWalker).callExpression,
		frontend.NamedExpr:             (*pyWalker).namedExpr,
		frontend.Lambda:                (*pyWalker).lambdaExpr,
	}
}

func (w *pyWalker) expr(n *frontend.Node, s *pyState, depth int) pyValue {
	if n == nil || !w.charge(depth) {
		return pyValue{}
	}

	switch n.Kind() {
	case frontend.Constant:
		v, ok := nodeLiteral(n)
		return literalValue(v, ok, pyTruth(n, s, 0))
	case frontend.Name:
		if v, ok := s.lookup(n.String(frontend.ID)); ok {
			return pyContents(v)
		}

		return namedValue(s.resolve(n.String(frontend.ID)))
	case frontend.Tuple, frontend.List:
		return w.sequenceExpr(n, s, depth)
	case frontend.Dict:
		return w.dictionaryExpr(n, s, depth)
	case frontend.ListComp, frontend.SetComp, frontend.DictComp, frontend.GeneratorExp:
		return w.comprehensionExpr(n, s, depth)
	default:
		return w.evaluatedExpr(n, s, depth)
	}
}

func (w *pyWalker) evaluatedExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	if evaluate := pyEvaluatedExpressions[n.Kind()]; evaluate != nil {
		return evaluate(w, n, s, depth)
	}

	return w.transformedExpr(n, s, depth)
}

func (w *pyWalker) unknownExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	// Retain visible observations without committing speculative child effects.
	child := s.fork()
	for _, x := range n.Children() {
		w.expr(x, child, depth+1)
	}

	return pyValue{}
}

func (w *pyWalker) namedExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	v := w.expr(n.Child(frontend.FieldValue), s, depth+1)
	w.assign(n.Child(frontend.Target), v, s, n)

	return v
}

func (w *pyWalker) transformedExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	children := n.Children()

	vs := make([]pyValue, 0, len(children))
	for _, child := range children {
		vs = append(vs, w.expr(child, s, depth+1))
	}

	v := transformed(joinPy(vs...), n)
	v.truth = pyTruth(n, s, 0)

	return v
}

func (w *pyWalker) sequenceExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	items := n.List(frontend.Elts)
	values := make([]pyValue, 0, min(len(items), 64))

	complete := len(items) <= 64
	for _, item := range items {
		v := w.expr(item, s, depth+1)
		if len(values) < 64 {
			values = append(values, v)
		}

		complete = complete && item.Kind() != frontend.Starred
	}

	v := transformed(joinPy(values...), n)

	v.truth = pyTruth(n, s, 0)
	if complete {
		v.meaning = &pySequence{items: values}
	} else {
		w.limited = true
	}

	return v
}

func (w *pyWalker) dictionaryExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	keys, values := n.List(frontend.Keys), n.List(frontend.Values)
	entries := map[string]pyValue{}
	vs := make([]pyValue, 0)

	complete := len(keys) <= 64 && len(keys) == len(values)
	for i, key := range keys {
		if i >= len(values) {
			break
		}

		w.expr(key, s, depth+1)
		v := w.expr(values[i], s, depth+1)

		vs = append(vs, v)
		if key == nil && v.mapping() != nil {
			maps.Copy(entries, v.mapping().entries)
		} else if k, ok := nodeLiteral(key); ok {
			entries[k] = v
		} else {
			complete = false
		}

		if len(entries) > 64 {
			complete = false
		}
	}

	v := transformed(joinPy(vs...), n)
	if complete {
		v.meaning = &pyMapping{entries: entries}
		v = pyContents(v)
	} else {
		w.limited = true
	}

	return v
}

func (w *pyWalker) comprehensionExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	child := s.fork()
	for _, g := range n.List(frontend.Generators) {
		// The first iterable is read before binding the comprehension target.
		iter := w.expr(g.Child(frontend.Iter), child, depth+1)
		w.assign(g.Child(frontend.Target), iter, child, g)

		for _, condition := range g.List(frontend.Ifs) {
			if w.expr(condition, child, depth+1).truth == 1 {
				return pyValue{}
			}
		}
	}

	if n.Kind() == frontend.DictComp {
		return transformed(joinPy(w.expr(n.Child(frontend.Key), child, depth+1), w.expr(n.Child(frontend.FieldValue), child, depth+1)), n)
	}

	return transformed(w.expr(n.Child(frontend.Elt), child, depth+1), n)
}

func (w *pyWalker) booleanExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	values := n.List(frontend.Values)
	if len(values) == 0 {
		return pyValue{}
	}

	v := w.expr(values[0], s, depth+1)
	for _, item := range values[1:] {
		if n.String(frontend.Op) == "And" && v.truth == 1 || n.String(frontend.Op) == "Or" && v.truth == 2 {
			return v
		}

		if v.truth == 0 {
			branch := s.fork()
			next := w.expr(item, branch, depth+1)
			mergePyBranches(s, s, branch)

			v = mergePyValue(v, next)
		} else {
			v = w.expr(item, s, depth+1)
		}
	}

	return v
}

func (w *pyWalker) conditionalExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	test := w.expr(n.Child(frontend.Test), s, depth+1)
	if test.truth == 2 {
		return w.expr(n.Child(frontend.Body), s, depth+1)
	}

	if test.truth == 1 {
		return w.expr(n.Child(frontend.Orelse), s, depth+1)
	}

	a, b := s.fork(), s.fork()
	x, y := w.expr(n.Child(frontend.Body), a, depth+1), w.expr(n.Child(frontend.Orelse), b, depth+1)
	mergePyBranches(s, a, b)

	return mergePyValue(x, y)
}

func (w *pyWalker) attributeExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	v := w.expr(n.Child(frontend.FieldValue), s, depth+1)

	name := v.symbol()
	if name != "" {
		name = canonicalSymbolName(name + "." + n.String(frontend.Attr))
	}

	if name == "os.environ" {
		v := origin("environment", n)
		v.meaning = pySymbol(name)

		return v
	}

	if member, ok := pyMember(v, n.String(frontend.Attr), s); ok {
		return member
	}
	// Preserve an already observed container's identity when the attribute has no
	// resolvable symbol. This retains the existing conservative alias behavior;
	// it does not infer the runtime meaning of that attribute.
	if name == "" {
		switch v.meaning.(type) {
		case *pyMapping, *pySequence, pyLiteral, *pySuper:
			return v
		}
	}

	v.meaning = pySymbol(name)

	return v
}

func (w *pyWalker) subscriptExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	v := w.expr(n.Child(frontend.FieldValue), s, depth+1)
	index := w.expr(n.Child(frontend.Slice), s, depth+1)

	key, known := reflectionKey(index, n.Child(frontend.Slice))
	if base := moduleDictionarySymbol(v.symbol()); base != "" {
		if known {
			if pyDangerousAttribute(key) {
				w.emit(ruleAST9, n, nil)
			}

			return namedValue(base + "." + key)
		}

		w.emit(ruleAST7, n, nil)

		return pyValue{}
	}

	if known && v.mapping() != nil {
		return transformed(pyContents(v.mapping().entries[key]), n)
	}

	switch v.meaning.(type) {
	case pySymbol, pyLiteral:
		v.meaning = nil
	}

	return v
}

func (w *pyWalker) lambdaExpr(n *frontend.Node, s *pyState, depth int) pyValue {
	f := w.defineFunction(n, s, depth+1)
	child := s.fork().scope()
	w.bindArgs(n.Child(frontend.Args), child)

	maps.Copy(child.names, child.defaultsFor(f))

	w.expr(n.Child(frontend.Body), child, depth+1)
	// Defining a function does not evaluate its body or return its value.
	// Inspect the body for independent observations, not caller taint.
	return functionValue(f)
}
