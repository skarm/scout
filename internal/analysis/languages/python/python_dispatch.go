// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

// pyCall is prepared once in Python evaluation order. Each later phase sees the
// same syntax, evaluated arguments and callable, rather than an error-prone list
// of positional parameters whose values happen to have the same Go type.
type pyCall struct {
	node, function     *frontend.Node
	name               string
	args               []*frontend.Node
	values, positional []pyValue
	keywords           map[string]pyValue
	callable, receiver pyValue
	effects            pyValue
}

func (w *pyWalker) callExpression(n *frontend.Node, s *pyState, depth int) pyValue {
	call := pyCall{node: n, function: n.Child(frontend.Func), args: n.List(frontend.Args)}
	call.callable = w.expr(call.function, s, depth+1)
	call.name = canonicalSymbolName(call.callable.symbol())

	if w.chainCalls == nil {
		w.chainCalls = map[*frontend.Node]bool{}
	}

	w.chainCalls[n] = pyNestedSourceName(call.name)
	if call.function != nil && call.function.Kind() == frontend.Attribute {
		call.receiver = call.callable
	}

	call.values, call.positional, call.keywords = w.callArguments(n, s, depth)
	call.effects = joinPy(call.values...)

	if value, handled := w.resolveCallable(call, s, depth); handled {
		return value
	}

	if value, handled := w.observeBuiltinCall(call); handled {
		return value
	}

	call.effects = w.observeCallEffects(call)

	return w.callResult(call)
}

func (w *pyWalker) callArguments(n *frontend.Node, s *pyState, depth int) ([]pyValue, []pyValue, map[string]pyValue) {
	args := n.List(frontend.Args)
	vals := make([]pyValue, 0)
	positional := make([]pyValue, 0)
	keywords := map[string]pyValue{}

	for _, a := range args {
		if a.Kind() == frontend.Starred {
			v := w.expr(a.Child(frontend.FieldValue), s, depth+1)

			vals = append(vals, v)
			if v.elements() != nil {
				positional = append(positional, v.elements()...)
			} else {
				w.limited = true
			}

			continue
		}

		v := w.expr(a, s, depth+1)
		vals = append(vals, v)
		positional = append(positional, v)
	}

	for _, k := range n.List(frontend.Keywords) {
		value := k.Child(frontend.FieldValue)
		v := w.expr(value, s, depth+1)

		vals = append(vals, v)
		if k.String(frontend.FieldArg) == "" {
			if v.mapping() != nil {
				for key, item := range v.mapping().entries {
					keywords[key] = pyContents(item)
				}
			} else {
				w.limited = true
			}
		} else {
			keywords[k.String(frontend.FieldArg)] = v
		}
	}

	return vals, positional, keywords
}

func (w *pyWalker) resolveCallable(call pyCall, s *pyState, depth int) (pyValue, bool) {
	if value, ok := w.reflectiveCallable(call); ok {
		return value, true
	}

	if call.name == "super" {
		return w.superCall(call.positional), true
	}

	if call.callable.function() != nil {
		return w.invoke(call.callable, call.node, call.positional, call.keywords, s, depth+1), true
	}

	if call.callable.class() != nil {
		return w.constructInstance(call, s, depth), true
	}

	return pyValue{}, false
}

func (w *pyWalker) reflectiveCallable(call pyCall) (pyValue, bool) {
	object, key := dictionaryCall(call.node)
	if object == nil {
		return pyValue{}, false
	}

	base := moduleDictionarySymbol(strings.TrimSuffix(call.callable.symbol(), "."+call.function.String(frontend.Attr)))
	if base == "" {
		return pyValue{}, false
	}

	if len(call.positional) == 0 {
		return pyValue{}, false
	}

	if key, ok := reflectionKey(call.positional[0], key); ok {
		if pyDangerousAttribute(key) {
			w.emit(ruleAST9, call.node, nil)
		}

		return namedValue(base + "." + key), true
	}

	w.emit(ruleAST7, call.node, nil)

	return pyValue{}, true
}

func (w *pyWalker) superCall(positional []pyValue) pyValue {
	if len(positional) == 2 && positional[0].class() != nil {
		return superValue(positional[0].class(), positional[1])
	}

	if len(positional) == 0 && len(w.frames) > 0 {
		frame := w.frames[len(w.frames)-1]
		if frame.owner != nil {
			return superValue(frame.owner, frame.receiver)
		}
	}

	w.limited = true

	return pyValue{}
}

func (w *pyWalker) constructInstance(call pyCall, s *pyState, depth int) pyValue {
	class := call.callable.class()
	if constructor, ok := pyMember(call.callable, "__new__", s); ok && constructor.function() != nil {
		w.invoke(constructor, call.node, append([]pyValue{classValue(class)}, call.positional...), call.keywords, s, depth+1)
	}

	instance := instanceValue(&pyInstance{typ: class, fields: map[string]pyValue{}})
	if init, ok := pyMember(instance, "__init__", s); ok && init.function() != nil {
		w.invoke(init, call.node, call.positional, call.keywords, s, depth+1)
	}

	return instance
}
