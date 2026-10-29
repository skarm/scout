// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"strings"

	"github.com/skarm/scout/internal/syntax/frontend"
)

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyBuiltinRules = map[string]string{"exec": ruleAST1, "eval": ruleAST2, "__import__": ruleAST3, "compile": ruleAST6}

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyFileWrites = map[string]bool{
	"pathlib.Path.write_text":  true,
	"pathlib.Path.write_bytes": true,
	"file-write.write":         true,
}

//nolint:gochecknoglobals // Read-only language and command classification shared by scans.
var pySourceCalls = map[string]string{
	"os.getenv":               "environment",
	"os.environ.get":          "environment",
	"input":                   "input",
	"sys.stdin.read":          "input",
	"sys.stdin.readline":      "input",
	"pathlib.Path.read_text":  "file",
	"pathlib.Path.read_bytes": "file",
}

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyFileReads = map[string]bool{"file-read.read": true, "file-read.readline": true, "file-read.readlines": true}

func (w *pyWalker) observeBuiltinCall(call pyCall) (pyValue, bool) {
	if id := pyBuiltinRules[call.name]; id != "" {
		w.emit(id, call.node, nil)
	}

	if call.name == "getattr" {
		return w.observeGetattr(call)
	}

	return pyValue{}, false
}

func (w *pyWalker) observeGetattr(call pyCall) (pyValue, bool) {
	if len(call.positional) < 2 {
		return pyValue{}, false
	}

	var syntax *frontend.Node
	if len(call.args) > 1 {
		syntax = call.args[1]
	}

	key, ok := reflectionKey(call.positional[1], syntax)
	if !ok {
		w.emit(ruleAST7, call.node, nil)
		return pyValue{}, false
	}

	if pyDangerousAttribute(key) {
		w.emit(ruleAST9, call.node, nil)
	}

	if base := call.positional[0].symbol(); base != "" {
		return namedValue(base + "." + key), true
	}

	return pyValue{}, false
}

func (w *pyWalker) observeCallEffects(call pyCall) pyValue {
	name, n, all := call.name, call.node, call.effects
	w.observeExecution(call)

	if w.unsafeDeserialization(call) {
		w.emit(ruleAST10, n, nil)
		w.flow(n, all, "deserialization")
	}

	if pyNetwork(name) {
		if name == "urllib.request.urlopen" {
			all = joinPy(all, call.receiver)
		}

		w.flow(n, all, "network")
	}

	if pyHTTPBody(call) {
		w.emit(ruleE1, n, nil)
	}

	if pyFileWrites[name] {
		w.flow(n, all, "file")
	}

	return all
}

func (w *pyWalker) observeExecution(call pyCall) {
	name, n, args := call.name, call.node, call.args
	if name == "exec" || name == "eval" {
		if len(args) > 0 && w.nestedSource(args[0], 0) {
			w.emit(ruleAST8, n, nil)
		}
	}

	w.observeProcess(call)

	if pyExec(name) {
		w.flow(n, call.effects, "exec")

		if pythonOutputArgument(name, n) {
			w.emit(ruleOH1, n, nil)
		}
	}
}

func (w *pyWalker) observeProcess(call pyCall) {
	name, n := call.name, call.node
	if strings.HasPrefix(name, "subprocess.") {
		if pyExec(name) && call.keywords["shell"].truth == 2 {
			w.emit(ruleTM1, n, nil)
		}

		switch strings.TrimPrefix(name, "subprocess.") {
		case "call", "run", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput":
			w.emit(ruleAST4, n, nil)
		}
	}

	if pyOSExecution(name) {
		w.emit(ruleAST5, n, nil)
	}
}

func (w *pyWalker) callResult(call pyCall) pyValue {
	name, n, vals, all := call.name, call.node, call.values, call.effects
	switch name {
	case "vars":
		return w.varsResult(call)

	case "urllib.request.build_opener", "urllib.request.OpenerDirector":
		v := joinPy(vals...)
		for _, arg := range vals {
			v = joinPy(v, pyHandlerOrigins(arg, 0, map[*pyInstance]bool{}))
		}

		v.meaning = pySymbol("urllib.request.OpenerDirector")

		return v
	case "urllib.request.Request":
		v := transformed(all, n)
		v.meaning = pySymbol("urllib.request.Request")

		return v
	case "open":
		return w.pythonOpenResult(call)
	default:
		if kind := pySourceCalls[name]; kind != "" {
			return origin(kind, n)
		}

		if pyNamedConstructors[name] != "" {
			return namedValue(name)
		}
	}

	return w.wrapperResult(call)
}

func (w *pyWalker) pythonOpenResult(call pyCall) pyValue {
	mode := "r"

	if value, supplied := call.argument("mode", 1); supplied {
		var known bool

		mode, known = value.literal()
		if !known {
			w.limited = true
			return pyValue{}
		}
	}

	if strings.ContainsAny(mode, "wax+") {
		return namedValue("file-write")
	}

	v := origin("file", call.node)
	v.meaning = pySymbol("file-read")

	return v
}

func (w *pyWalker) wrapperResult(call pyCall) pyValue {
	name, n := call.name, call.node
	all, receiver, fn := call.effects, call.receiver, call.function

	if pyIncoming(name) {
		return origin("network", n)
	}

	if pyFileReads[name] {
		receiver.meaning = pySymbol("")
		return transformed(receiver, n)
	}

	switch name {
	case "str", "bytes", "bytearray", "repr", "dict", "list", "tuple", "set", "json.dumps", "urllib.parse.urlencode", "base64.b64encode", "base64.b64decode", "base64.decodebytes", "codecs.decode", "marshal.loads":
		return transformed(all, n)
	}

	if value, ok := pythonAttributeResult(fn, receiver, all, n); ok {
		return value
	}

	return pythonImportResult(call)
}

func (w *pyWalker) varsResult(call pyCall) pyValue {
	if len(call.positional) == 1 {
		module := call.positional[0].symbol()
		if module == "os" || module == "builtins" {
			return namedValue(module + ".__dict__")
		}
	}

	return w.wrapperResult(call)
}

func pyOSExecution(name string) bool {
	tail, ok := strings.CutPrefix(name, "os.")
	if !ok {
		return false
	}

	return tail == "system" || tail == "popen" || strings.HasPrefix(tail, "exec") || strings.HasPrefix(tail, "spawn") || tail == "posix_spawn" || tail == "posix_spawnp"
}

func pythonImportResult(call pyCall) pyValue {
	if call.name == "__import__" || call.name == "importlib.import_module" {
		module, _ := call.argument("name", 0)
		if name, known := module.literal(); known {
			return namedValue(name)
		}
	}

	return pyValue{}
}

func pyExec(n string) bool {
	switch n {
	case "exec", "eval", "compile", "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_output", "subprocess.check_call", "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput":
		return true
	}

	return false
}

// A parsed outgoing HTTP body is an observable transmission construct even
// without a tainted source. Resolve imports/aliases/shadowing just as TT does.
func pyHTTPBody(call pyCall) bool {
	if !pyNetwork(call.name) {
		return false
	}

	for _, keyword := range []string{"data", "json", "content", "files"} {
		if _, present := call.keywords[keyword]; present {
			return true
		}
	}

	return (strings.HasSuffix(call.name, ".post") || strings.HasSuffix(call.name, ".put") || strings.HasSuffix(call.name, ".patch")) && len(call.positional) > 1
}

func pyNetwork(n string) bool {
	switch n {
	case "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "urllib.request.urlopen", "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto":
		return true
	}

	return false
}

func pyIncoming(n string) bool {
	return strings.HasPrefix(n, "requests.") && pyNetwork(n) || strings.HasPrefix(n, "httpx.") && pyNetwork(n) || n == "urllib.request.urlopen" || n == "urllib.request.urlretrieve" || n == "socket.socket.recv" || n == "socket.socket.recvfrom"
}

func pythonAttributeResult(fn *frontend.Node, receiver, all pyValue, n *frontend.Node) (pyValue, bool) {
	if fn != nil && fn.Kind() == frontend.Attribute {
		switch fn.String(frontend.Attr) {
		case "read", "readline", "readlines", "json":
			if len(receiver.origins) > 0 {
				return transformed(receiver, n), true
			}
		case "encode", "decode", "strip", "format", "replace", "join", "split", "rsplit", "splitlines":
			v := joinPy(receiver, all)
			return transformed(v, n), true
		}
	}

	return pyValue{}, false
}
