package bundle

import (
	"errors"
	"maps"
	"path"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

type bundleValue struct {
	secret, remote *report.SourceRef
	function       *bundleFunction
	module         *bundleProgram
	name, text     string
	refs           []report.SourceRef
	items          []bundleValue
	known          bool
	remoteKind     uint8 // 1=response object; 2=body bytes/text; 3=body reader method
}

func (b *bundleAnalysis) inspectProgram(p *bundleProgram) {
	b.initializeProgram(p)

	keys := make([]string, 0, len(p.functions))
	for key := range p.functions {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		b.callFunction(p.functions[key], nil, 0)
	}
}

func (b *bundleAnalysis) initializeProgram(p *bundleProgram) {
	if p.initialized || p.initializing {
		return
	}

	p.initializing = true
	p.globals = map[string]bundleValue{}
	b.evalBlock(p, p.body, p.globals, 0)
	p.initializing = false
	p.initialized = true
}

func (b *bundleAnalysis) refNode(p *bundleProgram, n *bundleNode) report.SourceRef {
	return b.reference(p.file, n.span.Start, n.span.End)
}

func (b *bundleAnalysis) localModule(p *bundleProgram, imp bundleImport) *bundleProgram {
	if !imp.local {
		return nil
	}

	rel := imp.module

	var candidates []string

	if p.language == language.Python {
		level := 0
		for strings.HasPrefix(rel, ".") {
			level++
			rel = strings.TrimPrefix(rel, ".")
		}

		rel = strings.ReplaceAll(rel, ".", "/")
		if level > 1 {
			rel = strings.Repeat("../", level-1) + rel
		}

		candidates = []string{rel + ".py", path.Join(rel, "__init__.py")}
	} else {
		candidates = []string{rel}
		if path.Ext(rel) == "" {
			for _, ext := range []string{".js", ".ts", ".mjs", ".mts", ".tsx", ".jsx"} {
				candidates = append(candidates, rel+ext)
			}
		}
	}

	var found *bundleProgram

	for _, candidate := range candidates {
		if d := b.resolveLocal(p.file, candidate); d != nil {
			if target := b.programs[d.Artifact().Metadata().Path]; target != nil {
				if found != nil && found != target {
					b.gap = errors.New("ambiguous captured local module")
					return nil
				}

				found = target
			}
		}
	}

	return found
}

func (b *bundleAnalysis) name(p *bundleProgram, name string, env map[string]bundleValue) bundleValue {
	if v, ok := env[name]; ok {
		return v
	}

	if imp, ok := p.imports[name]; ok {
		if target := b.localModule(p, imp); target != nil {
			if imp.symbol != "" {
				if fn := target.functions[imp.symbol]; fn != nil && fn.exported {
					return bundleValue{function: fn}
				}

				b.gap = errors.New("captured local export is unresolved")

				return bundleValue{}
			}

			return bundleValue{module: target}
		}

		if strings.HasPrefix(imp.module, ".") {
			b.gap = errors.New("local module reference is unresolved")
			return bundleValue{}
		}

		v := bundleValue{name: imp.module}
		if imp.symbol != "" {
			v.name += "." + imp.symbol
		}

		return v
	}

	if fn := p.functions[name]; fn != nil {
		return bundleValue{function: fn}
	}

	if p.language == language.Go {
		if fn := b.goFunction(p, name); fn != nil {
			return bundleValue{function: fn}
		}
	}

	return bundleValue{name: name}
}

func mergeBundleValue(a, c bundleValue) bundleValue {
	if a.secret == nil {
		a.secret = c.secret
	}

	if a.remote == nil {
		a.remote = c.remote
		a.remoteKind = c.remoteKind
	}

	for _, ref := range c.refs {
		seen := false
		for _, r := range a.refs {
			seen = seen || r == ref
		}

		if !seen && len(a.refs) < 6 {
			a.refs = append(a.refs, ref)
		}
	}

	return a
}

func (b *bundleAnalysis) evalBlock(p *bundleProgram, nodes []*bundleNode, env map[string]bundleValue, depth int) bundleValue {
	var out bundleValue

	for _, n := range nodes {
		if n == nil {
			continue
		}

		v := b.eval(p, n, env, depth+1)
		if n.kind == nodeReturn {
			return v
		}
		// A return nested in an aggregate block is evaluated conservatively.
		if n.kind == nodeAggregate {
			out = mergeBundleValue(out, v)
		}
	}

	return out
}

func (b *bundleAnalysis) eval(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	if n == nil || !b.step() {
		return bundleValue{}
	}

	if depth > 64 {
		b.gap = errors.New("bundle expression depth limit")
		return bundleValue{}
	}

	child := func(i int) bundleValue {
		if i >= len(n.children) {
			return bundleValue{}
		}

		return b.eval(p, n.children[i], env, depth+1)
	}

	switch n.kind {
	case nodeName:
		return b.name(p, n.name, env)
	case nodeLiteral:
		return bundleValue{text: n.text, known: n.known}
	case nodeAssign:
		v := child(0)

		if n.name != "" {
			if len(env) >= 1024 {
				b.gap = errors.New("bundle binding limit")
			} else {
				env[n.name] = v
			}
		}

		return v
	case nodeMember, nodeIndex:
		return b.evalMember(p, n, env, depth)
	case nodeCall:
		return b.evalCall(p, n, env, depth+1)
	case nodeConcat:
		a, c := child(0), child(1)
		v := mergeBundleValue(a, c)

		v.known = a.known && c.known && len(a.text)+len(c.text) <= 4096
		if v.known {
			v.text = a.text + c.text
		}

		v.name = ""

		return v
	case nodeBranch:
		local := map[string]bundleValue{}
		maps.Copy(local, env)

		var v bundleValue
		for _, c := range n.children {
			v = mergeBundleValue(v, b.eval(p, c, local, depth+1))
		}
		// Facts from either branch may survive, but a local overwrite cannot
		// erase the other branch's secret provenance.
		for name, value := range local {
			env[name] = mergeBundleValue(env[name], value)
		}

		return v
	default:
		var v bundleValue

		for _, c := range n.children {
			x := b.eval(p, c, env, depth+1)

			v = mergeBundleValue(v, x)
			if n.kind == nodeArray {
				v.items = append(v.items, x)
			}
		}

		return v
	}
}

func (b *bundleAnalysis) callFunction(fn *bundleFunction, args []bundleValue, depth int) bundleValue {
	if fn == nil {
		return bundleValue{}
	}

	if b.active[fn] || len(b.active) >= 8 || depth > 48 {
		b.gap = errors.New("bundle call graph depth or recursion limit")
		return bundleValue{}
	}

	b.active[fn] = true
	defer delete(b.active, fn)

	env := map[string]bundleValue{}

	b.initializeProgram(fn.program)

	maps.Copy(env, fn.program.globals)

	for i, name := range fn.params {
		if i < len(args) {
			env[name] = args[i]
		} else {
			env[name] = bundleValue{}
		}
	}

	v := b.evalBlock(fn.program, fn.body, env, depth+1)

	return v
}

func (b *bundleAnalysis) evalCall(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	if len(n.children) == 0 {
		return bundleValue{}
	}

	callee := b.eval(p, n.children[0], env, depth+1)

	var args []bundleValue
	for _, c := range n.children[1:] {
		args = append(args, b.eval(p, c, env, depth+1))
	}

	ref := b.refNode(p, n)
	if callee.function != nil {
		v := b.callFunction(callee.function, args, depth+1)
		if (v.secret != nil || v.remote != nil) && len(v.refs) < 6 {
			v.refs = append(v.refs, ref)
		}

		return v
	}

	name := callee.name
	if name == "require" && len(args) == 1 && args[0].known {
		imp := bundleImport{
			module: strings.TrimPrefix(args[0].text, "node:"),
			local:  strings.HasPrefix(args[0].text, "."),
		}
		if target := b.localModule(p, imp); target != nil {
			return bundleValue{module: target}
		}

		if imp.local {
			b.gap = errors.New("commonjs local module is unresolved")
			return bundleValue{}
		}

		return bundleValue{name: imp.module}
	}

	if bundleEnvironment(name) && len(args) > 0 && args[0].known && literals.SensitiveName(args[0].text) {
		b.secret(p.file, ref)
		return bundleValue{secret: &ref}
	}

	if bundleFileRead(name) && len(args) > 0 && args[0].known && literals.SensitivePath(args[0].text) {
		b.secret(p.file, ref)
		return bundleValue{secret: &ref}
	}

	if index, ok := bundleNetwork(name); ok {
		value := ""
		if index < len(args) && args[index].known {
			value = args[index].text
		}

		b.endpoint(p.file, value, ref)

		for _, v := range args {
			if v.secret != nil {
				b.crossFlow(ref, *v.secret, v.refs)
			}
		}

		return bundleValue{remote: &ref, remoteKind: 1}
	}

	return b.callOutput(callee, args, ref)
}

func (b *bundleAnalysis) crossFlow(sink, origin report.SourceRef, via []report.SourceRef) {
	cross := sink.Path != origin.Path
	for _, r := range via {
		cross = cross || r.Path != sink.Path
	}

	if !cross {
		return
	}

	refs := make([]report.SourceRef, 0, 1+len(via))
	refs = append(refs, origin)
	refs = append(refs, via...)
	b.emit(ruleCrossFile, sink, refs...)
}

func bundleEnvironment(name string) bool {
	switch name {
	case "os.getenv", "os.environ.get", "os.Getenv", "os.LookupEnv":
		return true
	}

	return false
}

func bundleFileRead(name string) bool {
	switch name {
	case "open", "pathlib.Path", "Path", "os.ReadFile", "io/ioutil.ReadFile", "fs.readFileSync", "fs.readFile", "fs.promises.readFile", "fs/promises.readFile":
		return true
	}

	return false
}

func bundleNetwork(name string) (int, bool) {
	switch name {
	case "fetch", "globalThis.fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete", "http.get", "http.request", "https.get", "https.request", "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "httpx.get", "httpx.post", "urllib.request.urlopen", "urllib.request.Request", "net/http.Get", "net/http.Post", "net/http.PostForm":
		return 0, true
	case "requests.request", "httpx.request", "net/http.NewRequest", "net/http.NewRequestWithContext":
		if name == "net/http.NewRequestWithContext" {
			return 2, true
		}

		return 1, true
	}

	return 0, false
}

func bundleExecution(name string) bool {
	switch name {
	case "eval", "exec", "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "child_process.exec", "child_process.execSync", "child_process.spawn", "child_process.execFile", "vm.runInNewContext", "vm.runInThisContext", "os/exec.Command":
		return true
	}

	return false
}

func bundlePureWrapper(name string) bool {
	switch name {
	case "str", "bytes", "bytearray", "string", "[]byte", "strings.NewReader", "strings.NewReplacer", "strings.TrimSpace", "io.ReadAll", "io/ioutil.ReadAll", "JSON.stringify", "json.dumps", "json.loads", "Buffer.from", "base64.b64decode", "base64.b64encode", "atob", "btoa", "encodeURIComponent":
		return true
	}

	return false
}

func (b *bundleAnalysis) evalMember(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	child := func(i int) bundleValue {
		if i >= len(n.children) {
			return bundleValue{}
		}

		return b.eval(p, n.children[i], env, depth+1)
	}
	v := child(0)

	property := n.name
	if n.kind == nodeIndex {
		key := child(1)
		if !key.known {
			return bundleValue{}
		}

		property = key.text
	}

	if v.module != nil {
		if fn := v.module.functions[property]; fn != nil && fn.exported {
			return bundleValue{function: fn}
		}

		b.gap = errors.New("captured local member is unresolved")

		return bundleValue{}
	}

	if v.remote != nil {
		switch property {
		case "text", "json":
			if p.language == language.Python && property == "text" {
				v.remoteKind = 2
			} else {
				v.remoteKind = 3
			}
		case "content", "body", "Body":
			v.remoteKind = 2
		case "read", "read_text", "read_bytes", "encode", "decode":
			v.remoteKind = 3
		default:
			v.remote = nil
			v.remoteKind = 0
		}

		if v.name == "" {
			v.name = "$response"
		}
	}

	v.name = strings.TrimPrefix(v.name+"."+property, ".")
	if (v.name == "process.env."+property || v.name == "os.environ."+property) && literals.SensitiveName(property) {
		ref := b.refNode(p, n)
		v.secret = &ref
		b.secret(p.file, ref)
	}

	return v
}

func (b *bundleAnalysis) goFunction(p *bundleProgram, name string) *bundleFunction {
	var found *bundleFunction

	for _, other := range b.programs {
		if other.file == p.file || other.language != language.Go || other.pkg != p.pkg || !b.sameScope(p.file, other.file) || path.Dir(b.addresses[p.file].Name) != path.Dir(b.addresses[other.file].Name) {
			continue
		}

		if fn := other.functions[name]; fn != nil {
			if found != nil {
				return nil
			}

			found = fn
		}
	}

	if found != nil {
		return found
	}

	return nil
}

func (b *bundleAnalysis) callOutput(callee bundleValue, args []bundleValue, ref report.SourceRef) bundleValue {
	name := callee.name
	if bundleExecution(name) {
		for _, v := range executionInputs(name, args) {
			if v.remote != nil && v.remoteKind == 2 {
				b.crossFlow(ref, *v.remote, v.refs)
			}
		}
	}

	if bundlePureWrapper(name) {
		v := bundleValue{}
		for _, a := range args {
			v = mergeBundleValue(v, a)
		}

		return v
	}

	for _, method := range []string{".read", ".read_text", ".read_bytes", ".text", ".json", ".encode", ".decode"} {
		if strings.HasSuffix(name, method) && (callee.remote != nil || callee.secret != nil) {
			callee.remoteKind = 2
			return callee
		}
	}

	return bundleValue{}
}

// A remote data argument to echo is not downloaded code. Process APIs need an
// untrusted executable operand or a selected interpreter's code-input flag.
func executionInputs(name string, args []bundleValue) []bundleValue {
	if len(args) == 0 {
		return nil
	}

	process := name == "os/exec.Command" || strings.HasPrefix(name, "subprocess.") || name == "child_process.spawn" || name == "child_process.execFile"
	if !process {
		return args[:1]
	}

	if args[0].remote != nil && len(args[0].items) == 0 {
		return args[:1]
	}

	argv := args
	if len(args[0].items) > 0 {
		argv = args[0].items
	} else if len(args) > 1 && len(args[1].items) > 0 {
		argv = append([]bundleValue{args[0]}, args[1].items...)
	}

	if len(argv) < 3 || !argv[0].known || !argv[1].known {
		return nil
	}

	program, flag := path.Base(argv[0].text), argv[1].text
	if literals.IsShell(program) && strings.HasPrefix(flag, "-") && strings.Contains(flag, "c") && !strings.ContainsAny(flag, "nD") {
		return argv[2:3]
	}

	if (program == "python" || program == "python3") && flag == "-c" || (program == "node" || program == "nodejs") && (flag == "-e" || flag == "--eval") {
		return argv[2:3]
	}

	return nil
}
