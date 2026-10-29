// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"maps"
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

func (w *pyWalker) block(nodes []*frontend.Node, s *pyState, depth int) {
	for _, n := range nodes {
		if n == nil || !w.charge(depth) {
			return
		}

		if !w.bindingStatement(n, s, depth) {
			return
		}
	}
}

func (w *pyWalker) bindingStatement(n *frontend.Node, s *pyState, depth int) bool {
	switch n.Kind() {
	case frontend.Global, frontend.Nonlocal:
		// Declarations were collected for the entire function before binding.
	case frontend.UnsupportedStatement:
		child := s.fork()
		w.block(n.List(frontend.Body), child, depth+1)

		for name := range s.names {
			s.names[name] = pyValue{}
		}

		s.blockedBuiltins = true
	case frontend.Import:
		for _, a := range n.List(frontend.Names) {
			name := a.String(frontend.FieldName)

			key := a.String(frontend.Asname)
			if key == "" {
				key = strings.Split(name, ".")[0]
				name = key
			}

			s.set(key, namedValue(name))
		}
	case frontend.ImportFrom:
		w.importFrom(n, s)
	default:
		return w.assignmentStatement(n, s, depth)
	}

	return true
}

func (w *pyWalker) assignmentStatement(n *frontend.Node, s *pyState, depth int) bool {
	switch n.Kind() {
	case frontend.Assign:
		v := w.expr(n.Child(frontend.FieldValue), s, depth+1)
		for _, t := range n.List(frontend.Targets) {
			w.assign(t, v, s, n)
		}
	case frontend.AnnAssign:
		w.expr(n.Child(frontend.Annotation), s.fork(), depth+1)
		v := w.expr(n.Child(frontend.FieldValue), s, depth+1)
		w.assign(n.Child(frontend.Target), v, s, n)
	case frontend.AugAssign:
		v := joinPy(w.expr(n.Child(frontend.Target), s, depth+1), w.expr(n.Child(frontend.FieldValue), s, depth+1))
		w.assign(n.Child(frontend.Target), v, s, n)
	case frontend.FunctionDef, frontend.AsyncFunctionDef:
		w.functionStatement(n, s, depth)
	case frontend.ClassDef:
		w.classStatement(n, s, depth)
	default:
		return w.controlStatement(n, s, depth)
	}

	return true
}

func (w *pyWalker) importFrom(n *frontend.Node, s *pyState) {
	levelValue, ok := n.Field(frontend.Level).Integer()
	if !ok || int64(int(levelValue)) != levelValue {
		w.limited = true
		return
	}

	level := int(levelValue)

	for _, a := range n.List(frontend.Names) {
		name := a.String(frontend.FieldName)

		key := a.String(frontend.Asname)
		if key == "" {
			key = name
		}

		if name == "*" {
			s.blockedBuiltins = true
			for k := range s.names {
				s.names[k] = pyValue{}
			}

			continue
		}

		if level != 0 {
			s.set(key, pyValue{})
		} else {
			s.set(key, namedValue(n.String(frontend.FieldModule)+"."+name))
		}
	}
}

func (w *pyWalker) functionStatement(n *frontend.Node, s *pyState, depth int) {
	args := n.Child(frontend.Args)
	function := w.defineFunction(n, s, depth+1)
	s.set(n.String(frontend.FieldName), functionValue(function))

	for _, tp := range n.List(frontend.TypeParams) {
		w.expr(tp, s.fork(), depth+1)
	}

	child := s.fork().scope()
	w.prebind(n.List(frontend.Body), child)
	w.bindArgs(args, child)

	maps.Copy(child.names, child.defaultsFor(function))

	w.frames = append(w.frames, &pyFrame{})
	w.block(n.List(frontend.Body), child, depth+1)
	w.frames = w.frames[:len(w.frames)-1]
}

func (w *pyWalker) classStatement(n *frontend.Node, s *pyState, depth int) {
	for _, d := range n.List(frontend.DecoratorList) {
		w.expr(d, s, depth+1)
	}

	baseNodes := n.List(frontend.Bases)

	bases := make([]pyValue, 0, len(baseNodes))
	for _, b := range baseNodes {
		bases = append(bases, w.expr(b, s, depth+1))
	}

	for _, k := range n.List(frontend.Keywords) {
		w.expr(k.Child(frontend.FieldValue), s, depth+1)
	}

	for _, tp := range n.List(frontend.TypeParams) {
		w.expr(tp, s.fork(), depth+1)
	}

	w.defineClass(n, s, depth+1, bases)
}

func (w *pyWalker) controlStatement(n *frontend.Node, s *pyState, depth int) bool {
	switch n.Kind() {
	case frontend.Return:
		v := w.expr(n.Child(frontend.FieldValue), s, depth+1)
		if len(w.frames) > 0 {
			frame := w.frames[len(w.frames)-1]
			frame.values = append(frame.values, v)
		}

		return false
	case frontend.If:
		w.expr(n.Child(frontend.Test), s, depth+1)
		a, b := s.fork(), s.fork()
		w.block(n.List(frontend.Body), a, depth+1)
		w.block(n.List(frontend.Orelse), b, depth+1)
		mergePyBranches(s, a, b)
	case frontend.With, frontend.AsyncWith:
		w.withStatement(n, s, depth)

	case frontend.For, frontend.AsyncFor, frontend.While:
		w.loopStatement(n, s, depth)

	case frontend.Try, frontend.TryStar:
		w.tryStatement(n, s, depth)
	case frontend.Delete:
		for _, t := range n.List(frontend.Targets) {
			w.assign(t, pyValue{}, s, n)
		}
	default:
		w.expr(n, s, depth+1)
	}

	return true
}

func (w *pyWalker) tryStatement(n *frontend.Node, s *pyState, depth int) {
	a := s.fork()
	w.block(n.List(frontend.Body), a, depth+1)
	w.block(n.List(frontend.Orelse), a, depth+1)
	merged := a

	for _, h := range n.List(frontend.Handlers) {
		b := s.fork()
		if h.String(frontend.FieldName) != "" {
			b.names[h.String(frontend.FieldName)] = pyValue{}
		}

		w.block(h.List(frontend.Body), b, depth+1)
		merged = mergePy(merged, b, map[pyValuePair]pyValue{})
	}

	mergePyBranches(s, s, merged)
	w.block(n.List(frontend.Finalbody), s, depth+1)
}

func (w *pyWalker) loopStatement(n *frontend.Node, s *pyState, depth int) {
	w.expr(n.Child(frontend.Iter), s, depth+1)
	w.expr(n.Child(frontend.Test), s, depth+1)
	a := s.fork()
	w.assign(n.Child(frontend.Target), pyValue{}, a, n)
	w.block(n.List(frontend.Body), a, depth+1)
	// Explore a second possible iteration so loop-carried sources can
	// reach earlier sinks. The parser still reports limited loop semantics.
	w.block(n.List(frontend.Body), a, depth+1)
	mergePyBranches(s, s, a)
	w.block(n.List(frontend.Orelse), s, depth+1)
}

func (w *pyWalker) withStatement(n *frontend.Node, s *pyState, depth int) {
	for _, i := range n.List(frontend.Items) {
		v := w.expr(i.Child(frontend.ContextExpr), s, depth+1)
		w.assign(i.Child(frontend.OptionalVars), v, s, i.Child(frontend.ContextExpr))
	}

	w.block(n.List(frontend.Body), s, depth+1)
}
