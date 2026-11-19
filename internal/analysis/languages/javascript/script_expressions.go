package javascript

import (
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
)

func scriptLiteral(text string) (string, bool) {
	if len(text) < 2 || len(text) > maxStringBytes || (text[0] != '\'' && text[0] != '"') || text[len(text)-1] != text[0] {
		return "", false
	}

	body := text[1 : len(text)-1]

	var value strings.Builder

	for len(body) > 0 {
		if strings.HasPrefix(body, `\/`) {
			value.WriteByte('/')

			body = body[2:]

			continue
		}

		if strings.HasPrefix(body, "\\\n") {
			body = body[2:]
			continue
		}

		r, _, tail, err := strconv.UnquoteChar(body, text[0])
		if err != nil {
			return "", false
		}

		value.WriteRune(r)

		body = tail
	}

	return value.String(), true
}

func (w *scriptWalk) expr(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	if n == nil || !w.charge(depth) {
		return scriptValue{}
	}

	switch n.Kind {
	case scriptsyntax.KindIdentifier, scriptsyntax.KindShorthandPropertyIdentifier:
		if v, ok := s.get(w.text(n)); ok {
			return v
		}

		return scriptValue{name: w.text(n)}
	case scriptsyntax.KindString:
		text, ok := scriptLiteral(w.text(n))
		return scriptValue{text: text, known: ok, stringValue: true}
	case scriptsyntax.KindNumber, scriptsyntax.KindTrue, scriptsyntax.KindFalse, scriptsyntax.KindNull:
		return scriptValue{text: w.text(n), known: true, valueType: scriptNonString, primitive: true}
	case scriptsyntax.KindAwaitExpression:
		return w.await(n, s, depth)
	case scriptsyntax.KindAsExpression, scriptsyntax.KindSatisfiesExpression, scriptsyntax.KindNonNullExpression, scriptsyntax.KindParenthesizedExpression:
		return w.expr(scriptInnerExpression(n), s, depth+1)
	case scriptsyntax.KindMemberExpression, scriptsyntax.KindSubscriptExpression:
		return w.member(n, s, depth)
	case scriptsyntax.KindCallExpression, scriptsyntax.KindNewExpression:
		return w.call(n, s, depth)
	case scriptsyntax.KindAssignmentExpression, scriptsyntax.KindAugmentedAssignmentExpression, scriptsyntax.KindUpdateExpression, scriptsyntax.KindUnaryExpression:
		return w.scalarExpression(n, s, depth)

	case scriptsyntax.KindBinaryExpression:
		return w.binary(n, s, depth)
	case scriptsyntax.KindTemplateString:
		return w.template(n, s, depth)
	case scriptsyntax.KindArrowFunction, scriptsyntax.KindFunctionExpression, scriptsyntax.KindGeneratorFunction:
		w.function(n, s, depth+1)
		return scriptValue{}
	case scriptsyntax.KindStatementBlock:
		w.statement(n, s, depth+1)
		return scriptValue{}
	case scriptsyntax.KindForStatement, scriptsyntax.KindForInStatement, scriptsyntax.KindWhileStatement, scriptsyntax.KindDoStatement, scriptsyntax.KindSwitchStatement, scriptsyntax.KindTryStatement, scriptsyntax.KindWithStatement:
		w.limited = true
	case scriptsyntax.KindPair:
		return w.pair(n, s, depth)
	}

	var out scriptValue

	for _, c := range n.Children {
		v := w.expr(c, s, depth+1)
		if out.secret == nil {
			out.secret = v.secret
		}

		out.dynamic = out.dynamic || v.dynamic

		out.shell = out.shell || v.shell
		if v.text != "" && out.text == "" {
			out.text = v.text
		}
	}

	if n.Kind == scriptsyntax.KindObject || n.Kind == scriptsyntax.KindArray {
		out.valueType = scriptNonString
	}

	return out
}

func (w *scriptWalk) member(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	if n == nil {
		return scriptValue{}
	}

	object := w.expr(n.Child(scriptsyntax.FieldObject), s, depth+1)

	property := w.text(n.Child(scriptsyntax.FieldProperty))
	if index := n.Child(scriptsyntax.FieldIndex); index != nil {
		v := w.expr(index, s, depth+1)
		if !v.known {
			return scriptValue{}
		}

		property = v.text
	}

	if object.name == "" || property == "" {
		if object.valueType == scriptResponse && property == "text" {
			return scriptValue{name: "Response.text"}
		}

		return scriptValue{secret: object.secret}
	}

	out := scriptValue{name: object.name + "." + property, secret: object.secret}
	if object.name == "process.env" && literals.SensitiveName(property) {
		out.secret = n
	}

	return out
}

func combineScript(a, b scriptValue, concatenate bool) scriptValue {
	out := scriptValue{secret: a.secret, dynamic: a.dynamic || b.dynamic}
	if out.secret == nil {
		out.secret = b.secret
	}

	if concatenate {
		out.stringValue = a.stringValue || b.stringValue
		fits := len(a.text)+len(b.text) <= maxStringBytes
		out.known = a.known && b.known && fits

		out.dynamic = out.dynamic || !out.known
		if fits {
			out.text = a.text + b.text
		}
	}

	return out
}

func (w *scriptWalk) template(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	out := scriptValue{known: true, stringValue: true}
	textLimited := false

	for _, c := range n.Children {
		switch c.Kind {
		case scriptsyntax.KindBacktick:
		case scriptsyntax.KindStringFragment:
			if textLimited {
				continue
			}

			fragment := w.text(c)
			if len(out.text)+len(fragment) <= maxStringBytes {
				out.text += fragment
			} else {
				textLimited = true
				out.text, out.known, out.dynamic = "", false, true
			}
		case scriptsyntax.KindTemplateSubstitution:
			out.known = false
			out.dynamic = true

			for _, e := range c.Children {
				v := w.expr(e, s, depth+1)
				if out.secret == nil {
					out.secret = v.secret
				}
			}
		default:
			// Escapes need template-specific decoding before this string is known.
			textLimited = true
			out.text, out.known, out.dynamic = "", false, true
		}
	}

	return out
}

func (w *scriptWalk) call(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	fun := n.Child(scriptsyntax.FieldFunction)
	if fun == nil {
		fun = n.Child(scriptsyntax.FieldConstructor)
	}

	name := w.expr(fun, s, depth+1).name

	args := w.callArguments(n.Child(scriptsyntax.FieldArguments), s, depth)

	if name == "require" && len(args) == 1 && args[0].known {
		return scriptValue{name: strings.TrimPrefix(args[0].text, "node:")}
	}

	if name == "os.homedir" {
		return scriptValue{text: "~", known: true}
	}

	if name == "path.join" || name == "path.posix.join" {
		return scriptJoin(args)
	}

	if scriptShellCall(name, args) {
		if scriptExecCommandText(name, args) {
			w.emit(ruleJS001, n, nil, check.ShellCommandText)
		} else {
			w.emit(ruleJS001, n, nil)
		}
	}

	if scriptCodeCall(name, args) {
		w.emit(ruleJS002, n, nil)
	}

	if scriptFileRead(name, args) {
		w.emit(ruleJS005, n, nil)
		return scriptValue{secret: n}
	}

	if value, network := w.networkCall(name, args, n); network {
		return value
	}

	if scriptQueryMethod(name) && len(args) > 0 && args[0].dynamic && sqlsyntax.QueryPrefix(args[0].text) {
		w.emit(ruleJS004, n, args[0].secret)
	}

	switch name {
	case "Response.text":
		return scriptValue{valueType: scriptPromiseText}
	case "JSON.stringify", "String", "Buffer.from", "encodeURIComponent", "encodeURI", "btoa":
		if len(args) > 0 {
			value := args[0]
			value.valueType = scriptUnknown

			value.stringValue = true

			value.primitive = false
			if name == "JSON.stringify" {
				value.text = ""
				value.known = false
			}

			if name == "Buffer.from" {
				value.stringValue = false
				value.valueType = scriptNonString
			}

			return value
		}
	}

	return scriptValue{}
}

func scriptExecCommandText(name string, args []scriptValue) bool {
	return (name == "child_process.exec" || name == "child_process.execSync") &&
		len(args) > 0 && (!args[0].known || strings.TrimSpace(args[0].text) != "") && args[0].valueType != scriptNonString
}

func scriptShellCall(name string, args []scriptValue) bool {
	method, ok := strings.CutPrefix(name, "child_process.")
	if !ok {
		return false
	}

	if method == "exec" || method == "execSync" {
		return true
	}

	switch method {
	case "spawn", "spawnSync", "execFile", "execFileSync":
		for _, v := range args {
			if v.shell {
				return true
			}
		}

		if len(args) > 0 && args[0].known && literals.IsShell(args[0].text) {
			return true
		}
	}

	return false
}

func scriptCodeCall(name string, args []scriptValue) bool {
	switch name {
	case "eval", "globalThis.eval":
		return len(args) > 0 && args[0].valueType == scriptUnknown
	case "Function", "globalThis.Function", "vm.runInContext", "vm.runInNewContext", "vm.runInThisContext", "vm.Script", "vm.compileFunction":
		return true
	case "setTimeout", "setInterval":
		return len(args) > 0 && args[0].stringValue
	}

	return false
}

func (w *scriptWalk) await(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	value := w.expr(scriptInnerExpression(n), s, depth+1)

	switch value.valueType {
	case scriptPromiseResponse:
		value.valueType = scriptResponse
	case scriptPromiseText:
		value.valueType = scriptUnknown
		value.stringValue = true
	default:
		return value
	}

	return value
}

func scriptNetwork(name string) bool {
	if name == "fetch" || name == "globalThis.fetch" {
		return true
	}

	for _, prefix := range []string{"axios.", "http.", "https.", "undici."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return name == "axios"
}

func scriptQueryMethod(name string) bool {
	_, method, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}

	switch method {
	case "query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe":
		return true
	}

	return false
}

func (w *scriptWalk) assignment(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	left := w.scalarTarget(n.Child(scriptsyntax.FieldLeft), depth)

	var previous scriptValue

	if n.Kind == scriptsyntax.KindAugmentedAssignmentExpression || left != nil && (left.Kind == scriptsyntax.KindMemberExpression || left.Kind == scriptsyntax.KindSubscriptExpression) {
		previous = w.expr(left, s, depth+1)
	}

	operator := w.text(n.Child(scriptsyntax.FieldOperator))

	logical := operator == scriptsyntax.OpOrAssign || operator == scriptsyntax.OpAndAssign || operator == scriptsyntax.OpNullishAssign
	if logical {
		assign, known := scriptAssignmentCondition(previous, operator)
		if !known {
			return w.conditionalAssignment(n, s, previous, depth)
		}

		if !assign {
			return previous
		}
	}

	value := w.expr(n.Child(scriptsyntax.FieldRight), s, depth+1)
	if n.Kind == scriptsyntax.KindAugmentedAssignmentExpression && !logical {
		value = scriptCompound(previous, value, operator)
	}

	w.bind(left, value, s, false)

	if previous.name == "process.env.NODE_TLS_REJECT_UNAUTHORIZED" && value.known && value.text == "0" {
		w.emit(ruleJS006, n, nil)
	}

	return value
}

func (w *scriptWalk) pair(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	value := w.expr(n.Child(scriptsyntax.FieldValue), s, depth+1)

	key := w.text(n.Child(scriptsyntax.FieldKey))
	if decoded, ok := scriptLiteral(key); ok {
		key = decoded
	}

	if key == "rejectUnauthorized" && value.known && value.text == "false" {
		w.emit(ruleJS006, n, nil)
	}

	if key == "shell" && value.known && value.text == "true" {
		value.shell = true
	}

	return value
}

func (w *scriptWalk) callArguments(arguments *scriptsyntax.Node, s *scriptScope, depth int) []scriptValue {
	if arguments == nil {
		return nil
	}

	var values []scriptValue

	for _, child := range arguments.Children {
		if child.Kind != scriptsyntax.KindOpenParen && child.Kind != scriptsyntax.KindCloseParen && child.Kind != scriptsyntax.KindComma && child.Kind != scriptsyntax.KindComment {
			values = append(values, w.expr(child, s, depth+1))
		}
	}

	return values
}

func scriptFileRead(name string, args []scriptValue) bool {
	if !strings.HasPrefix(name, "fs.") && !strings.HasPrefix(name, "fs/promises.") {
		return false
	}

	_, method, _ := strings.Cut(name, ".")
	switch method {
	case "readFile", "readFileSync", "createReadStream", "promises.readFile":
		return len(args) > 0 && args[0].known && literals.SensitivePath(args[0].text)
	}

	return false
}

func scriptJoin(args []scriptValue) scriptValue {
	out := scriptValue{known: true, stringValue: true}

	for i, value := range args {
		if i > 0 {
			out.text += "/"
		}

		out.text += value.text

		out.known = out.known && value.known
		if len(out.text) > maxStringBytes {
			return scriptValue{}
		}
	}

	return out
}

func (w *scriptWalk) networkCall(name string, args []scriptValue, n *scriptsyntax.Node) (scriptValue, bool) {
	if !scriptNetwork(name) {
		return scriptValue{}, false
	}

	for _, value := range args {
		if value.secret != nil {
			w.emit(ruleJS003, n, value.secret)
			break
		}
	}

	if name == "fetch" || name == "globalThis.fetch" {
		return scriptValue{valueType: scriptPromiseResponse}, true
	}

	return scriptValue{valueType: scriptNonString}, true
}
