package hooktrace

import (
	"path"
	"strings"

	"github.com/skarm/scout/internal/syntax/scriptsyntax"
)

const (
	maxCommonJSCallArguments = 8
)

func (w *nodeHookWalk) value(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) nodeHookValue {
	if n == nil || n.Invalid || depth >= maxHookSourceDepth+2 || !w.trace.work.Spend(1) {
		return nodeHookValue{}
	}

	switch n.Kind {
	case scriptsyntax.KindIdentifier:
		name := m.text(n)

		_, bound := bindings[name]
		if !bound && name == "__dirname" {
			return nodeHookValue{kind: nodeHookPath, text: path.Dir("/" + m.rel)}
		}

		return bindings.value(name)
	case scriptsyntax.KindString:
		raw := m.text(n)
		if len(raw) >= 2 && !strings.ContainsRune(raw[1:len(raw)-1], '\\') {
			return nodeHookValue{kind: nodeHookText, text: raw[1 : len(raw)-1]}
		}
	case scriptsyntax.KindTemplateString:
		return w.template(m, n, bindings, depth)
	case scriptsyntax.KindSubscriptExpression:
		_, shadowed := bindings["process"]
		if !shadowed && w.firstArg.known && m.namedMember(n.Child(scriptsyntax.FieldObject), "process", "argv") && m.text(n.Child(scriptsyntax.FieldIndex)) == "2" {
			return nodeHookValue{kind: nodeHookText, text: w.firstArg.value}
		}
	case scriptsyntax.KindCallExpression:
		return w.callValue(m, n, bindings, depth)
	}

	return nodeHookValue{}
}

func (w *nodeHookWalk) template(m nodeHookModule, n *scriptsyntax.Node, bindings nodeHookBindings, depth int) nodeHookValue {
	var out strings.Builder

	for _, child := range n.Children {
		switch child.Kind {
		case scriptsyntax.KindBacktick:
		case scriptsyntax.KindStringFragment:
			out.WriteString(m.text(child))
		case scriptsyntax.KindTemplateSubstitution:
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
	fn := n.Child(scriptsyntax.FieldFunction)
	args := nodeHookChildren(n.Child(scriptsyntax.FieldArguments))

	if fn == nil || len(args) == 0 || len(args) > maxCommonJSCallArguments {
		return nodeHookValue{}
	}

	switch {
	case fn.Kind == scriptsyntax.KindIdentifier && len(args) == 1:
		name := m.text(fn)
		value := w.value(m, args[0], bindings, depth+1)

		_, bound := bindings[name]

		callee := bindings.value(name)
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
	if !nodeHookKind(n, scriptsyntax.KindMemberExpression) || m.text(n.Child(scriptsyntax.FieldProperty)) != name {
		return false
	}

	binding := bindings.value(m.text(n.Child(scriptsyntax.FieldObject)))

	return binding.kind == nodeHookModuleValue && binding.export == "" && binding.text == module
}

// A path resolver can return a constant path when the capture supplies the
// file tested by its first matching existsSync guard.
func (w *nodeHookWalk) pathReturn(m nodeHookModule, callee nodeHookValue, arg nodeHookValue, depth int) nodeHookValue {
	if depth >= maxHookSourceDepth+1 || callee.fn == nil {
		return nodeHookValue{}
	}

	parameters := nodeHookChildren(callee.fn.Child(scriptsyntax.FieldParameters))

	body := callee.fn.Child(scriptsyntax.FieldBody)
	if len(parameters) != 1 || !nodeHookKind(parameters[0], scriptsyntax.KindIdentifier) || body == nil {
		return nodeHookValue{}
	}

	bindings, ok := w.cloneBindings(*callee.scope)
	if !ok {
		return nodeHookValue{}
	}

	bindings.bind(m.text(parameters[0]), arg)

	if !w.predeclare(m, body, bindings) {
		return nodeHookValue{}
	}

	for _, n := range nodeHookChildren(body) {
		if !w.trace.work.Spend(1) {
			break
		}

		if n.Kind == scriptsyntax.KindLexicalDeclaration && m.text(n.Child(scriptsyntax.FieldKind)) == "const" {
			w.declare(m, n, bindings, depth)
			continue
		}

		condition := nodeHookOnly(n.Child(scriptsyntax.FieldCondition))
		consequence := n.Child(scriptsyntax.FieldConsequence)

		alternative := n.Child(scriptsyntax.FieldAlternative)
		if n.Kind != scriptsyntax.KindIfStatement || !nodeHookKind(condition, scriptsyntax.KindCallExpression) || alternative != nil ||
			!w.moduleMember(m, condition.Child(scriptsyntax.FieldFunction), bindings, "fs", "existsSync") {
			break
		}

		if nodeHookKind(consequence, scriptsyntax.KindStatementBlock) {
			consequence = nodeHookOnly(consequence)
		}

		test := nodeHookOnly(condition.Child(scriptsyntax.FieldArguments))

		result := nodeHookOnly(consequence)
		if !nodeHookKind(consequence, scriptsyntax.KindReturnStatement) || !nodeHookKind(result, scriptsyntax.KindIdentifier) ||
			!nodeHookKind(test, scriptsyntax.KindIdentifier) || m.text(test) != m.text(result) {
			break
		}

		resolved := bindings.value(m.text(result))
		if resolved.kind != nodeHookPath {
			break
		}

		rel := strings.TrimPrefix(resolved.text, "/")
		if candidate := w.scope.LookupFile(rel); candidate != nil && candidate.Doc != nil {
			return resolved
		}
	}

	return nodeHookValue{}
}
