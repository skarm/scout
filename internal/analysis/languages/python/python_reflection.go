// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Bounded reflective module dictionary/string handling adapted from SkillSpector.

package python

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

func moduleDictionarySymbol(name string) string {
	for _, base := range []string{"os", "builtins"} {
		if name == base+".__dict__" || base == "builtins" && name == "__dict__" {
			return base
		}
	}

	return ""
}

func pyDangerousAttribute(key string) bool {
	switch key {
	case "exec", "eval", "system", "popen", "__import__":
		return true
	}

	return false
}

func pyDictionaryRead(name string) bool {
	return name == "get" || name == "pop" || name == "setdefault"
}

func reflectionKey(value pyValue, syntax *frontend.Node) (string, bool) {
	if key, known := value.literal(); known {
		return key, true
	}
	// The fallback folds only literal string joins. It never reads state,
	// evaluates a call, or coerces byte strings into attribute names.
	return pyReflectiveString(syntax, 0)
}

func pyReflectiveString(n *frontend.Node, depth int) (string, bool) {
	if n == nil || depth > 16 {
		return "", false
	}

	if v, ok := nodeLiteral(n); ok {
		return v, true
	}

	separator, ok := pyJoinSeparator(n)
	if !ok {
		return "", false
	}

	return pyReflectiveJoin(n.List(frontend.Args)[0], separator, depth)
}

func pyReflectiveJoin(arg *frontend.Node, separator string, depth int) (string, bool) {
	if arg.Kind() != frontend.List && arg.Kind() != frontend.Tuple {
		return "", false
	}

	nodes := arg.List(frontend.Elts)
	if len(nodes) > 32 {
		return "", false
	}

	parts := make([]string, 0, len(nodes))
	size := 0

	for _, node := range nodes {
		p, ok := pyReflectiveString(node, depth+1)
		if !ok {
			return "", false
		}

		size += len(p)
		if len(parts) > 0 {
			size += len(separator)
		}

		if size > 10 {
			return "", false
		}

		parts = append(parts, p)
	}

	return strings.Join(parts, separator), true
}

func pyJoinSeparator(n *frontend.Node) (string, bool) {
	if n.Kind() != frontend.Call || len(n.List(frontend.Args)) != 1 {
		return "", false
	}

	fn := n.Child(frontend.Func)
	if fn == nil || fn.Kind() != frontend.Attribute || fn.String(frontend.Attr) != "join" {
		return "", false
	}

	separator, ok := nodeLiteral(fn.Child(frontend.FieldValue))
	if !ok || len(separator) > 10 {
		return "", false
	}

	return separator, true
}
