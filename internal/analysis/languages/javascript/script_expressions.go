package javascript

import (
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
)

func scriptLiteral(text string) (string, bool) {
	if len(text) < 2 || len(text) > 16384 || (text[0] != '\'' && text[0] != '"') || text[len(text)-1] != text[0] {
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
	case "identifier", "shorthand_property_identifier":
		if v, ok := s.get(w.text(n)); ok {
			return v
		}

		return scriptValue{name: w.text(n)}
	case "string":
		text, ok := scriptLiteral(w.text(n))
		return scriptValue{text: text, known: ok, stringValue: true}
	case "number", "true", "false", "null":
		return scriptValue{text: w.text(n), known: true, valueType: scriptNonString}
	case "await_expression":
		return w.await(n, s, depth)
	case "as_expression", "satisfies_expression", "non_null_expression", "parenthesized_expression":
		for _, c := range n.Children {
			if c.Kind != "(" && c.Kind != ")" && c.Kind != "await" {
				return w.expr(c, s, depth+1)
			}
		}
	case "member_expression", "subscript_expression":
		return w.member(n, s, depth)
	case "call_expression", "new_expression":
		return w.call(n, s, depth)
	case "assignment_expression", "augmented_assignment_expression":
		return w.assignment(n, s, depth)

	case "binary_expression":
		a, b := w.expr(n.Child("left"), s, depth+1), w.expr(n.Child("right"), s, depth+1)
		return combineScript(a, b, w.text(n.Child("operator")) == "+")
	case "template_string":
		return w.template(n, s, depth)
	case "arrow_function", "function_expression", "generator_function":
		w.function(n, s, depth+1)
		return scriptValue{}
	case "statement_block":
		w.statement(n, s, depth+1)
		return scriptValue{}
	case "for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "try_statement", "with_statement":
		w.limited = true
	case "pair":
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

	if n.Kind == "object" || n.Kind == "array" {
		out.valueType = scriptNonString
	}

	return out
}

func (w *scriptWalk) member(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	if n == nil {
		return scriptValue{}
	}

	object := w.expr(n.Child("object"), s, depth+1)

	property := w.text(n.Child("property"))
	if index := n.Child("index"); index != nil {
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
		out.known = a.known && b.known

		out.dynamic = out.dynamic || !out.known
		if len(a.text)+len(b.text) <= 16384 {
			out.text = a.text + b.text
		}
	}

	return out
}

func (w *scriptWalk) template(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	out := scriptValue{known: true, stringValue: true}

	for _, c := range n.Children {
		if c.Kind == "string_fragment" {
			if len(out.text)+len(w.text(c)) <= 16384 {
				out.text += w.text(c)
			}

			continue
		}

		if c.Kind == "template_substitution" {
			out.known = false
			out.dynamic = true

			for _, e := range c.Children {
				v := w.expr(e, s, depth+1)
				if out.secret == nil {
					out.secret = v.secret
				}
			}
		}
	}

	return out
}

func (w *scriptWalk) call(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	fun := n.Child("function")
	if fun == nil {
		fun = n.Child("constructor")
	}

	name := w.expr(fun, s, depth+1).name

	args := w.callArguments(n.Child("arguments"), s, depth)

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
		w.emit(ruleJS001, n, nil)
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
	var value scriptValue

	for _, child := range n.Children {
		if child.Kind != "await" {
			value = w.expr(child, s, depth+1)
			break
		}
	}

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
	value := w.expr(n.Child("right"), s, depth+1)

	left := n.Child("left")
	if n.Kind == "augmented_assignment_expression" {
		value = combineScript(w.expr(left, s, depth+1), value, true)
	}

	w.bind(left, value, s, false)

	if left != nil && w.member(left, s, depth+1).name == "process.env.NODE_TLS_REJECT_UNAUTHORIZED" && value.known && value.text == "0" {
		w.emit(ruleJS006, n, nil)
	}

	return value
}

func (w *scriptWalk) pair(n *scriptsyntax.Node, s *scriptScope, depth int) scriptValue {
	value := w.expr(n.Child("value"), s, depth+1)

	key := w.text(n.Child("key"))
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
		if child.Kind != "(" && child.Kind != ")" && child.Kind != "," {
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
		if len(out.text) > 16384 {
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
