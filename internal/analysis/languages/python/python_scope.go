// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"maps"
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

type (
	pyMapping struct{ entries map[string]pyValue }
	// Class/function identities are immutable. Their reachable mutable values
	// belong to an exploration, shared by real scopes and copied by forks.
	pyObjectStore struct {
		classes  map[*pyClass]map[string]pyValue
		defaults map[*pyFunction]map[string]pyValue
	}
	pyState struct {
		names           map[string]pyValue
		blockedBuiltins bool
		parent, global  *pyState
		locals          map[string]bool
		declarations    map[string]string
		forks           map[*pyState]*pyState
		objects         *pyObjectStore
	}
)

func newPyState() *pyState {
	s := &pyState{
		names:        map[string]pyValue{},
		locals:       map[string]bool{},
		declarations: map[string]string{},
		objects: &pyObjectStore{
			classes:  map[*pyClass]map[string]pyValue{},
			defaults: map[*pyFunction]map[string]pyValue{},
		},
	}
	s.global = s

	return s
}

func (s *pyState) clone() *pyState {
	r := newPyState()
	r.blockedBuiltins = s.blockedBuiltins

	r.parent, r.global, r.forks, r.objects = s.parent, s.global, s.forks, s.objects
	maps.Copy(r.locals, s.locals)

	maps.Copy(r.declarations, s.declarations)

	maps.Copy(r.names, s.names)

	return r
}

func (s *pyState) scope() *pyState {
	r := newPyState()
	r.parent, r.global, r.forks, r.objects = s, s.global, s.forks, s.objects
	r.blockedBuiltins = s.blockedBuiltins

	return r
}

func (s *pyState) defaultsFor(function *pyFunction) map[string]pyValue {
	if defaults, ok := s.objects.defaults[function]; ok {
		return defaults
	}

	return function.defaults
}

func (s *pyState) owner(name string) *pyState {
	if s.declarations[name] == "global" {
		return s.global
	}

	if s.declarations[name] == "nonlocal" {
		for p := s.parent; p != nil && p.parent != nil; p = p.parent {
			if p.locals[name] && p.declarations[name] == "" {
				return p
			}
		}
	}

	if s.parent != nil && !s.locals[name] {
		return s.parent.owner(name)
	}

	return s
}

func (s *pyState) lookup(name string) (pyValue, bool) {
	v, ok := s.owner(name).names[name]
	return v, ok
}

func (s *pyState) set(name string, v pyValue) {
	if s.declarations[name] == "" {
		s.locals[name] = true
	}

	s.owner(name).names[name] = v
}

func (s *pyState) resolve(name string) string {
	if v, ok := s.lookup(name); ok {
		return v.symbol()
	}

	if s.blockedBuiltins || s.owner(name).blockedBuiltins {
		return ""
	}

	switch name {
	case "exec", "eval", "compile", "__import__", "getattr", "vars", "input", "open", "str", "bytes", "bytearray", "repr", "dict", "list", "tuple", "set", "len", "print", "staticmethod", "classmethod", "object", "super":
		return name
	}

	return ""
}

func (s *pyState) prebindName(name string) {
	if s.declarations[name] == "" {
		s.set(name, pyValue{})
	}
}

func (w *pyWalker) assign(target *frontend.Node, v pyValue, s *pyState, statement *frontend.Node) {
	if target == nil {
		return
	}

	switch target.Kind() {
	case frontend.Name:
		s.set(target.String(frontend.ID), transformed(v, statement))
	case frontend.Attribute:
		w.assignAttribute(target, v, s, statement)
	case frontend.Subscript:
		w.assignSubscript(target, v, s, statement)
	case frontend.Tuple, frontend.List:
		w.assignSequence(target, v, s, statement)
	default:
		return
	}
}

func (w *pyWalker) assignAttribute(target *frontend.Node, v pyValue, s *pyState, statement *frontend.Node) {
	base := w.expr(target.Child(frontend.FieldValue), s, 0)
	if instance := base.instance(); instance != nil {
		instance.fields[target.String(frontend.Attr)] = transformed(v, statement)
	}

	if class := base.class(); class != nil {
		attrs := s.objects.classes[class]
		if attrs == nil {
			attrs = maps.Clone(class.attrs)
			s.objects.classes[class] = attrs
		}

		attrs[target.String(frontend.Attr)] = transformed(v, statement)
	}
}

func (w *pyWalker) assignSubscript(target *frontend.Node, v pyValue, s *pyState, statement *frontend.Node) {
	base := w.expr(target.Child(frontend.FieldValue), s, 0)

	index := w.expr(target.Child(frontend.Slice), s, 0)
	if mapping := base.mapping(); mapping != nil {
		if key, ok := reflectionKey(index, target.Child(frontend.Slice)); ok && len(mapping.entries) < 64 {
			mapping.entries[key] = transformed(v, statement)
		} else {
			w.limited = true
		}
	}
}

func (w *pyWalker) assignSequence(target *frontend.Node, v pyValue, s *pyState, statement *frontend.Node) {
	items := target.List(frontend.Elts)
	for i, n := range items {
		item := pyValue{}
		if len(items) == len(v.elements()) && len(items) <= 64 {
			item = v.elements()[i]
		} else {
			w.limited = true
		}

		w.assign(n, item, s, statement)
	}
}

func (w *pyWalker) definitionAnnotations(args, returns *frontend.Node, s *pyState, depth int) {
	if args != nil {
		for _, key := range []frontend.FieldKind{frontend.Posonlyargs, frontend.Args, frontend.KWOnlyargs} {
			for _, a := range args.List(key) {
				w.expr(a.Child(frontend.Annotation), s.fork(), depth+1)
			}
		}

		for _, key := range []frontend.FieldKind{frontend.Vararg, frontend.Kwarg} {
			w.expr(args.Child(key).Child(frontend.Annotation), s.fork(), depth+1)
		}
	}

	w.expr(returns, s.fork(), depth+1)
}

func (w *pyWalker) bindArgs(args *frontend.Node, s *pyState) {
	if args == nil {
		return
	}

	for _, k := range []frontend.FieldKind{frontend.Posonlyargs, frontend.Args, frontend.KWOnlyargs} {
		for _, arg := range args.List(k) {
			s.set(arg.String(frontend.FieldArg), pyValue{})
		}
	}

	for _, k := range []frontend.FieldKind{frontend.Vararg, frontend.Kwarg} {
		if n := args.Child(k); n != nil {
			s.set(n.String(frontend.FieldArg), pyValue{})
		}
	}
}

// Python local declarations shadow outer bindings throughout their scope, even
// before their first assignment. This prevents treating a local exec as builtins.exec.
func (w *pyWalker) prebind(nodes []*frontend.Node, s *pyState) {
	w.prebindDeclarations(nodes, s)
	w.prebindNames(nodes, s)
}

func (w *pyWalker) prebindDeclarations(nodes []*frontend.Node, s *pyState) {
	for _, n := range nodes {
		if n == nil || pyDefinesScope(n) {
			continue
		}

		w.prebindDeclaration(n, s)

		for _, body := range pyScopeBodies(n) {
			w.prebindDeclarations(body, s)
		}
	}
}

func (w *pyWalker) prebindDeclaration(n *frontend.Node, s *pyState) {
	if n.Kind() != frontend.Global && n.Kind() != frontend.Nonlocal {
		return
	}

	names, ok := n.Field(frontend.Names).Strings()
	if !ok {
		w.limited = true
		return
	}

	for _, name := range names {
		s.declarations[name] = strings.ToLower(n.Kind().String())
	}
}

func (w *pyWalker) prebindNames(nodes []*frontend.Node, s *pyState) {
	for _, n := range nodes {
		if n == nil {
			continue
		}

		if pyDefinesScope(n) {
			s.prebindName(n.String(frontend.FieldName))
			continue
		}

		w.prebindStatement(n, s)

		for _, body := range pyScopeBodies(n) {
			w.prebindNames(body, s)
		}
	}
}

func (w *pyWalker) prebindStatement(n *frontend.Node, s *pyState) {
	switch n.Kind() {
	case frontend.Assign:
		for _, v := range n.List(frontend.Targets) {
			w.prebindTarget(v, s)
		}
	case frontend.AnnAssign, frontend.AugAssign, frontend.For, frontend.AsyncFor:
		w.prebindTarget(n.Child(frontend.Target), s)
	case frontend.Import, frontend.ImportFrom:
		for _, alias := range n.List(frontend.Names) {
			s.prebindName(pyAliasName(alias))
		}
	default:
		return
	}
}

func (w *pyWalker) prebindTarget(n *frontend.Node, s *pyState) {
	if n == nil {
		return
	}

	if n.Kind() == frontend.Name {
		if s.declarations[n.String(frontend.ID)] == "" {
			s.set(n.String(frontend.ID), pyValue{})
		}

		return
	}

	if n.Kind() == frontend.Tuple || n.Kind() == frontend.List {
		for _, x := range n.List(frontend.Elts) {
			w.prebindTarget(x, s)
		}
	}
}

func pyDefinesScope(n *frontend.Node) bool {
	switch n.Kind() {
	case frontend.FunctionDef, frontend.AsyncFunctionDef, frontend.ClassDef:
		return true
	default:
		return false
	}
}

func pyScopeBodies(n *frontend.Node) [][]*frontend.Node {
	handlers := n.List(frontend.Handlers)
	bodies := make([][]*frontend.Node, 0, 3+len(handlers))

	bodies = append(bodies, n.List(frontend.Body), n.List(frontend.Orelse), n.List(frontend.Finalbody))
	for _, h := range handlers {
		bodies = append(bodies, h.List(frontend.Body))
	}

	return bodies
}

func pyAliasName(alias *frontend.Node) string {
	if name := alias.String(frontend.Asname); name != "" {
		return name
	}

	return strings.Split(alias.String(frontend.FieldName), ".")[0]
}

func mergePy(a, b *pyState, memo map[pyValuePair]pyValue) *pyState {
	r := a.clone()

	r.blockedBuiltins = a.blockedBuiltins || b.blockedBuiltins
	for k, x := range a.names {
		y, ok := b.names[k]
		if !ok {
			y = pyValue{}
		}

		z := mergePyValueMemo(x, y, 0, memo)
		r.names[k] = z
	}

	for k, y := range b.names {
		if _, ok := r.names[k]; !ok {
			r.names[k] = mergePyValueMemo(pyValue{}, y, 0, memo)
		}
	}

	r.objects = mergeObjectStores(a.objects, b.objects, memo)

	return r
}
