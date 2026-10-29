// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded same-file call/method propagation, based on SkillSpector
// behavioral_taint_tracking. This is static inference, never Python execution.

package python

import (
	"maps"
	"slices"
	"sort"

	"github.com/skarm/scout/internal/syntax/frontend"
)

type pyFunction struct {
	node     *frontend.Node
	lexical  *pyState
	defaults map[string]pyValue
	kind     string
	dynamic  bool
	owner    *pyClass
}
type pyClass struct {
	attrs map[string]pyValue
	mro   []*pyClass
}
type pyInstance struct {
	typ    *pyClass
	fields map[string]pyValue
}

type pyFrame struct {
	values   []pyValue
	owner    *pyClass
	receiver pyValue
}
type pySuper struct {
	owner    *pyClass
	receiver pyValue
}

func (instance *pyInstance) class() *pyClass { return instance.typ }

func (w *pyWalker) defineFunction(n *frontend.Node, s *pyState, depth int) *pyFunction {
	f := &pyFunction{node: n, lexical: s, defaults: map[string]pyValue{}}
	for _, d := range n.List(frontend.DecoratorList) {
		name := w.expr(d, s, depth).symbol()
		if name == "staticmethod" || name == "classmethod" {
			f.kind = name
		} else {
			f.dynamic = true
		}
	}

	w.captureDefaults(f, s, depth)
	w.definitionAnnotations(n.Child(frontend.Args), n.Child(frontend.Returns), s, depth)
	s.objects.defaults[f] = f.defaults

	return f
}

func (w *pyWalker) captureDefaults(f *pyFunction, s *pyState, depth int) {
	n := f.node

	args := n.Child(frontend.Args)
	if args == nil {
		return
	}

	pos := append(append([]*frontend.Node{}, args.List(frontend.Posonlyargs)...), args.List(frontend.Args)...)

	defaults := args.List(frontend.Defaults)
	for i, d := range defaults {
		value := w.expr(d, s, depth+1)

		j := len(pos) - len(defaults) + i
		if j >= 0 {
			f.defaults[pos[j].String(frontend.FieldArg)] = value
		}
	}

	kw := args.List(frontend.KWOnlyargs)
	for i, d := range args.List(frontend.KWDefaults) {
		value := w.expr(d, s, depth+1)
		if d != nil && i < len(kw) {
			f.defaults[kw[i].String(frontend.FieldArg)] = value
		}
	}
}

func (w *pyWalker) invoke(value pyValue, call *frontend.Node, pos []pyValue, kw map[string]pyValue, caller *pyState, depth int) pyValue {
	f := value.function()
	if f == nil || !w.charge(depth) {
		return pyValue{}
	}

	if value.callable().bindingUnknown {
		w.limited = true
		return pyValue{}
	}

	if !w.beginInvocation(f) {
		return pyValue{}
	}

	w.active[f] = true
	defer delete(w.active, f)

	lexical := f.lexical
	if mapped := caller.forks[lexical]; mapped != nil {
		lexical = mapped
	}

	s := lexical.scope()
	w.prebind(f.node.List(frontend.Body), s)
	args := f.node.Child(frontend.Args)
	w.bindArgs(args, s)

	if value.bound() != nil {
		pos = append([]pyValue{*value.bound()}, pos...)
	}

	maps.Copy(s.names, caller.defaultsFor(f))
	w.bindInvocation(f, call, args, pos, kw, s)

	frame := invocationFrame(f, value, pos)

	w.frames = append(w.frames, frame)
	if f.node.Kind() == frontend.Lambda {
		frame.values = append(frame.values, w.expr(f.node.Child(frontend.Body), s, depth+1))
	} else {
		w.block(f.node.List(frontend.Body), s, depth+1)
	}

	w.frames = w.frames[:len(w.frames)-1]
	if len(frame.values) == 1 {
		return transformed(frame.values[0], call)
	}

	return transformed(joinPy(frame.values...), call)
}

func (w *pyWalker) bindInvocation(f *pyFunction, call, args *frontend.Node, pos []pyValue, kw map[string]pyValue, s *pyState) {
	used := map[string]bool{}

	keywordNames := make([]string, 0, len(kw))
	for key := range kw {
		keywordNames = append(keywordNames, key)
	}

	sort.Strings(keywordNames)

	if args != nil {
		posonly := map[string]bool{}
		for _, p := range args.List(frontend.Posonlyargs) {
			posonly[p.String(frontend.FieldArg)] = true
		}

		parameters := append(append([]*frontend.Node{}, args.List(frontend.Posonlyargs)...), args.List(frontend.Args)...)
		for i, p := range parameters {
			if i < len(pos) {
				key := p.String(frontend.FieldArg)
				s.names[key] = transformed(pos[i], call)
				used[key] = true
			}
		}

		for _, key := range keywordNames {
			w.bindKeyword(args, key, kw[key], used, posonly, s, call)
		}

		w.bindVariadicAndDefaults(f, call, args, pos, kw, s, used, posonly, parameters, keywordNames)
	}
}

func (w *pyWalker) bindKeyword(args *frontend.Node, key string, v pyValue, used, posonly map[string]bool, s *pyState, call *frontend.Node) {
	if used[key] && !posonly[key] {
		w.limited = true
		return
	}

	matched := false

	for _, p := range append(append([]*frontend.Node{}, args.List(frontend.Args)...), args.List(frontend.KWOnlyargs)...) {
		if p.String(frontend.FieldArg) == key {
			s.names[key] = transformed(v, call)
			used[key] = true
			matched = true

			break
		}
	}

	if !matched && args.Child(frontend.Kwarg) == nil {
		w.limited = true
	}
}

func (w *pyWalker) bindVariadicAndDefaults(f *pyFunction, call, args *frontend.Node, pos []pyValue, kw map[string]pyValue, s *pyState, used, posonly map[string]bool, parameters []*frontend.Node, keywordNames []string) {
	for _, p := range append(parameters, args.List(frontend.KWOnlyargs)...) {
		key := p.String(frontend.FieldArg)
		if !used[key] {
			if _, ok := f.defaults[key]; !ok {
				w.limited = true
			}
		}
	}

	if extra := args.Child(frontend.Vararg); extra != nil {
		tail := pos[min(len(pos), len(parameters)):]
		v := transformed(joinPy(tail...), call)
		v.meaning = &pySequence{items: append([]pyValue{}, tail...)}
		s.names[extra.String(frontend.FieldArg)] = v
	} else if len(pos) > len(parameters) {
		w.limited = true
	}

	w.bindVariadicKeywords(call, args, kw, s, used, posonly, keywordNames)
}

func (w *pyWalker) bindVariadicKeywords(call, args *frontend.Node, kw map[string]pyValue, s *pyState, used, posonly map[string]bool, keywordNames []string) {
	if extra := args.Child(frontend.Kwarg); extra != nil {
		vs := make([]pyValue, 0)
		entries := map[string]pyValue{}

		for _, key := range keywordNames {
			v := kw[key]
			if !used[key] || posonly[key] {
				vs = append(vs, v)
				entries[key] = v
			}
		}

		v := transformed(joinPy(vs...), call)
		v.meaning = &pyMapping{entries: entries}
		s.names[extra.String(frontend.FieldArg)] = v
	}
}

func (w *pyWalker) defineClass(n *frontend.Node, s *pyState, depth int, values []pyValue) {
	c := &pyClass{attrs: map[string]pyValue{}}
	bases := make([]*pyClass, 0)

	for _, v := range values {
		if v.class() != nil {
			bases = append(bases, v.class())
		} else if v.symbol() != "object" {
			w.limited = true
		}
	}

	c.mro = pyMRO(c, bases)
	if c.mro == nil {
		w.limited = true
		c.mro = []*pyClass{c}
	}

	s.names[n.String(frontend.FieldName)] = classValue(c)
	// Class attributes live in a separate namespace. Methods capture the outer
	// lexical scope, not arbitrary class-local names as Python function globals.
	local := s.scope()
	w.block(n.List(frontend.Body), local, depth+1)
	bindClassAttributes(c, n, local, s)
	w.inspectClassMethods(c, n, s, depth)
}

func (w *pyWalker) inspectClassMethods(c *pyClass, n *frontend.Node, s *pyState, depth int) {
	// Inspect potential method capabilities in an isolated receiver. A method
	// need not be called by the module to contain an observable source/sink.
	receiver := instanceValue(&pyInstance{typ: c, fields: map[string]pyValue{}})
	if init, ok := pyMember(receiver, "__init__", s); ok && init.function() != nil {
		w.invoke(init, n, nil, nil, s.fork(), depth+1)
	}

	keys := make([]string, 0, len(c.attrs))
	for key := range c.attrs {
		if key != "__init__" && key != "__new__" {
			keys = append(keys, key)
		}
	}

	sort.Strings(keys)

	for _, key := range keys {
		isolated := s.fork()
		isolated.names["__scout_receiver__"] = receiver

		isolated = isolated.fork()
		if method, ok := pyMember(isolated.names["__scout_receiver__"], key, isolated); ok && method.function() != nil {
			w.invoke(method, n, nil, nil, isolated, depth+1)
		}
	}
}

func (w *pyWalker) beginInvocation(f *pyFunction) bool {
	w.calls++
	if w.active == nil {
		w.active = map[*pyFunction]bool{}
	}

	if f.dynamic || w.active[f] || len(w.frames) > 16 || w.calls > 4096 {
		w.limited = true
		return false
	}

	return true
}

func bindClassAttributes(c *pyClass, n *frontend.Node, local, s *pyState) {
	for _, item := range n.List(frontend.Body) {
		switch item.Kind() {
		case frontend.FunctionDef, frontend.AsyncFunctionDef:
			c.bindMethod(item.String(frontend.FieldName), local, s)
		case frontend.Assign:
			c.bindTargets(item.List(frontend.Targets), local)
		case frontend.AnnAssign:
			if item.Child(frontend.FieldValue) != nil {
				c.bindTargets([]*frontend.Node{item.Child(frontend.Target)}, local)
			}
		default:
			// Other statements do not declare class attributes here.
			continue
		}
	}
}

func (c *pyClass) bindMethod(name string, local, s *pyState) {
	v := local.names[name]
	if f := v.function(); f != nil {
		f.lexical = s
		f.owner = c
	}

	c.attrs[name] = v
}

func (c *pyClass) bindTargets(targets []*frontend.Node, local *pyState) {
	for _, target := range targets {
		if target != nil && target.Kind() == frontend.Name {
			key := target.String(frontend.ID)
			c.attrs[key] = local.names[key]
		}
	}
}

func (c *pyClass) attribute(name string, after *pyClass, state *pyState) (pyValue, bool) {
	start := 0
	if after != nil {
		start = slices.Index(c.mro, after) + 1
		if start == 0 {
			return pyValue{}, false
		}
	}

	for _, base := range c.mro[start:] {
		attrs := state.objects.classes[base]
		if attrs == nil {
			attrs = base.attrs
		}

		if v, ok := attrs[name]; ok {
			return v, true
		}
	}

	return pyValue{}, false
}

func pyMember(base pyValue, name string, state *pyState) (pyValue, bool) {
	var after *pyClass
	if super := base.super(); super != nil {
		after = super.owner
		base = super.receiver
	}

	class := base.class()
	if instance := base.instance(); instance != nil {
		if v, ok := instance.fields[name]; ok {
			return v, true
		}

		class = instance.class()
	}

	if class == nil {
		return pyValue{}, false
	}

	v, ok := class.attribute(name, after, state)

	return v.bindMember(base, class), ok
}

func (v pyValue) bindMember(base pyValue, class *pyClass) pyValue {
	f := v.function()
	if f == nil {
		return v
	}

	if f.kind == "classmethod" {
		return v.bind(classValue(class))
	}

	if f.kind != "staticmethod" && base.instance() != nil {
		return v.bind(base)
	}

	return v
}

func pyMRO(c *pyClass, bases []*pyClass) []*pyClass {
	if len(bases) > 32 {
		return nil
	}

	seqs := make([][]*pyClass, 0)
	for _, b := range bases {
		seqs = append(seqs, append([]*pyClass(nil), b.mro...))
	}

	seqs = append(seqs, append([]*pyClass(nil), bases...))

	out := []*pyClass{c}
	for len(out) < 128 {
		candidate, remaining := nextMROHead(seqs)

		if !remaining {
			return out
		}

		if candidate == nil {
			return nil
		}

		out = append(out, candidate)
		dropMROHead(seqs, candidate)
	}

	return nil
}

func validMROHead(head *pyClass, seqs [][]*pyClass) bool {
	for _, other := range seqs {
		if len(other) == 0 {
			continue
		}

		if slices.Contains(other[1:], head) {
			return false
		}
	}

	return true
}

func invocationFrame(f *pyFunction, value pyValue, pos []pyValue) *pyFrame {
	frame := &pyFrame{owner: f.owner}
	if value.bound() != nil {
		frame.receiver = *value.bound()
	} else if f.owner != nil && len(pos) > 0 {
		frame.receiver = pos[0]
	}

	return frame
}

func nextMROHead(seqs [][]*pyClass) (*pyClass, bool) {
	remaining := false

	for _, seq := range seqs {
		if len(seq) == 0 {
			continue
		}

		remaining = true

		if validMROHead(seq[0], seqs) {
			return seq[0], true
		}
	}

	return nil, remaining
}

func dropMROHead(seqs [][]*pyClass, candidate *pyClass) {
	for i, seq := range seqs {
		if len(seq) > 0 && seq[0] == candidate {
			seqs[i] = seq[1:]
		}
	}
}
