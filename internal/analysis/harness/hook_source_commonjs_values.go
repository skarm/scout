package harness

import (
	"maps"
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

func (w *nodeHookWalk) value(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) nodeHookValue {
	if n == nil || n.Invalid || depth >= maxHookSourceDepth+2 || !w.plugin.b.step() {
		return nodeHookValue{}
	}

	switch n.Kind {
	case "identifier":
		name := m.text(n)

		value, bound := bindings[name]
		if !bound && name == "__dirname" {
			return nodeHookValue{kind: nodeHookPath, text: path.Dir("/" + m.rel)}
		}

		return value
	case "string":
		raw := m.text(n)
		if len(raw) >= 2 && !strings.ContainsRune(raw[1:len(raw)-1], '\\') {
			return nodeHookValue{kind: nodeHookText, text: raw[1 : len(raw)-1]}
		}
	case "template_string":
		return w.template(m, n, bindings, depth)
	case "subscript_expression":
		_, shadowed := bindings["process"]
		if !shadowed && w.firstArg.known && m.text(n.Child("object")) == "process.argv" && m.text(n.Child("index")) == "2" {
			return nodeHookValue{kind: nodeHookText, text: w.firstArg.value}
		}
	case "call_expression":
		return w.callValue(m, n, bindings, depth)
	}

	return nodeHookValue{}
}

func (w *nodeHookWalk) template(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) nodeHookValue {
	var out strings.Builder

	for _, child := range n.Children {
		switch child.Kind {
		case "`":
		case "string_fragment":
			out.WriteString(m.text(child))
		case "template_substitution":
			if len(child.Children) != 3 {
				return nodeHookValue{}
			}

			part := w.value(m, child.Children[1], bindings, depth+1)
			if part.kind != nodeHookText {
				return nodeHookValue{}
			}

			out.WriteString(part.text)
		default:
			return nodeHookValue{}
		}

		if out.Len() > maxHookSourceValue {
			return nodeHookValue{}
		}
	}

	return nodeHookValue{kind: nodeHookText, text: out.String()}
}

func (w *nodeHookWalk) callValue(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) nodeHookValue {
	fn := n.Child("function")
	args := nodeHookChildren(n.Child("arguments"))

	if fn == nil || len(args) == 0 || len(args) > 8 {
		return nodeHookValue{}
	}

	switch {
	case fn.Kind == "identifier" && len(args) == 1:
		name := m.text(fn)
		value := w.value(m, args[0], bindings, depth+1)

		callee, bound := bindings[name]
		if !bound && name == "require" {
			return w.requireValue(m, value)
		}

		if callee.kind == nodeHookFunction && value.kind == nodeHookText {
			return w.pathReturn(m, callee, value, depth+1)
		}
	case w.moduleMember(m, fn, bindings, "path", "join"):
		base := w.value(m, args[0], bindings, depth+1)
		if base.kind != nodeHookPath {
			return nodeHookValue{}
		}

		for _, arg := range args[1:] {
			suffix := w.value(m, arg, bindings, depth+1)
			if suffix.kind != nodeHookText {
				return nodeHookValue{}
			}

			base.text = nodeHookJoin(base.text, suffix.text)
			if base.text == "" {
				return nodeHookValue{}
			}
		}

		return base
	}

	return nodeHookValue{}
}

func (w *nodeHookWalk) requireValue(m nodeHookModule, value nodeHookValue) nodeHookValue {
	if value.kind == nodeHookPath {
		return nodeHookValue{kind: nodeHookModuleValue, text: value.text}
	}

	if value.kind != nodeHookText {
		return nodeHookValue{}
	}

	switch text := strings.TrimPrefix(value.text, "node:"); text {
	case "fs", "path":
		return nodeHookValue{kind: nodeHookModuleValue, text: text}
	}

	if strings.HasPrefix(value.text, "./") || strings.HasPrefix(value.text, "../") {
		joined := nodeHookJoin(path.Dir("/"+m.rel), value.text)
		if joined != "" {
			return nodeHookValue{kind: nodeHookModuleValue, text: joined}
		}
	}

	return nodeHookValue{}
}

func nodeHookJoin(base, suffix string) string {
	if !strings.HasPrefix(base, "/") || strings.HasPrefix(suffix, "/") || strings.ContainsAny(suffix, "\x00\\") {
		return ""
	}

	for part := range strings.SplitSeq(suffix, "/") {
		switch part {
		case "", ".":
		case "..":
			if base == "/" {
				return ""
			}

			base = path.Dir(base)
		default:
			base = path.Join(base, part)
		}
	}

	return base
}

func (w *nodeHookWalk) moduleMember(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, module, name string) bool {
	if !nodeHookKind(n, "member_expression") || m.text(n.Child("property")) != name {
		return false
	}

	binding := bindings[m.text(n.Child("object"))]

	return binding.kind == nodeHookModuleValue && binding.export == "" && binding.text == module
}

// A path resolver can return a constant path when the capture supplies the
// file tested by its first matching existsSync guard.
func (w *nodeHookWalk) pathReturn(m nodeHookModule, callee nodeHookValue, arg nodeHookValue, depth int) nodeHookValue {
	if depth >= maxHookSourceDepth+1 || callee.fn == nil {
		return nodeHookValue{}
	}

	parameters := nodeHookChildren(callee.fn.Child("parameters"))

	body := callee.fn.Child("body")
	if len(parameters) != 1 || !nodeHookKind(parameters[0], "identifier") || body == nil {
		return nodeHookValue{}
	}

	bindings := maps.Clone(callee.scope)
	bindings[m.text(parameters[0])] = arg
	w.predeclare(m, body, bindings)

	for _, n := range nodeHookChildren(body) {
		if !w.plugin.b.step() {
			break
		}

		if n.Kind == "lexical_declaration" && m.text(n.Child("kind")) == "const" {
			w.declare(m, n, bindings, depth)
			continue
		}

		condition := nodeHookOnly(n.Child("condition"))
		consequence := n.Child("consequence")

		alternative := n.Child("alternative")
		if n.Kind != "if_statement" || !nodeHookKind(condition, "call_expression") || alternative != nil ||
			!w.moduleMember(m, condition.Child("function"), bindings, "fs", "existsSync") {
			break
		}

		if nodeHookKind(consequence, "statement_block") {
			consequence = nodeHookOnly(consequence)
		}

		test := nodeHookOnly(condition.Child("arguments"))

		result := nodeHookOnly(consequence)
		if !nodeHookKind(consequence, "return_statement") || !nodeHookKind(result, "identifier") ||
			!nodeHookKind(test, "identifier") || m.text(test) != m.text(result) {
			break
		}

		resolved := bindings[m.text(result)]
		if resolved.kind != nodeHookPath {
			break
		}

		rel := strings.TrimPrefix(resolved.text, "/")
		if candidate := w.plugin.entry(rel); candidate != nil && candidate.doc != nil {
			return resolved
		}
	}

	return nodeHookValue{}
}
