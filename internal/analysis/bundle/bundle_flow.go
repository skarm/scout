package bundle

import (
	"errors"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

type bundleValue struct {
	secret, remote    *report.SourceRef
	function          *bundleFunction
	module            *bundleProgram
	name, text        string
	refs              []report.SourceRef
	items             []bundleValue
	known             bool
	remoteKind        uint8 // 1=response object; 2=body bytes/text; 3=body reader method
	uncertainFunction bool
	containsFunctions bool
	returned          bool // Control flow within a function; cleared at call boundaries.
	resolver          *bundleResolver
	resolverReceiver  *bundleNode
}

func (v bundleValue) hasCallableIdentity() bool {
	return v.function != nil || v.module != nil || v.resolver != nil || v.containsFunctions || v.uncertainFunction
}

func (v bundleValue) hasSymbolicName() bool {
	return v.name != "" && v.secret == nil && v.remote == nil
}

func (b *bundleAnalysis) inspectProgram(p *bundleProgram) {
	b.initializeProgram(p)

	for _, key := range bundleFunctionNames(p) {
		if b.err != nil {
			return
		}

		b.callFunction(p.functions[key], nil, 0)

		if b.globalWriteStop {
			// A hypothetical standalone invocation must not abort independent
			// module inspection. Its unsupported state still leaves a gap.
			if b.gap == nil {
				b.gap = b.err
			}

			b.err, b.globalWriteStop = nil, false
		}
	}
}

func bundleFunctionNames(p *bundleProgram) []string {
	keys := make([]string, 0, len(p.functions))
	for key := range p.functions {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func (b *bundleAnalysis) initializeProgram(p *bundleProgram) {
	if p.initialized || p.initializing {
		return
	}

	p.initializing = true
	p.globals = map[string]bundleValue{}

	if p.language == language.JavaScript || p.language == language.TypeScript {
		for _, name := range bundleFunctionNames(p) {
			if !strings.HasPrefix(name, "*function@") {
				b.bindValue(p.globals, name, bundleValue{function: p.functions[name]})
			}
		}
	}

	b.evalBlock(p, p.body, p.globals, 0)
	p.initializing = false
	p.initialized = true
	p.failed = b.err != nil
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
		if imp.module == "" {
			b.gap = errors.New("imported module binding is unresolved")
			return bundleValue{}
		}

		if target := b.localModule(p, imp); target != nil {
			if imp.symbol != "" {
				return b.exportValue(target, imp.symbol)
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

	if p.declared[name] {
		// A lexical declaration masks API candidates even before initialization
		// or when its unsupported value could not be projected.
		return bundleValue{}
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

func (b *bundleAnalysis) exportValue(p *bundleProgram, name string) bundleValue {
	if p.language == language.JavaScript || p.language == language.TypeScript {
		if binding, ok := p.exports[name]; ok && !p.initializing {
			b.initializeProgram(p)

			if p.failed {
				b.gap = errors.New("captured module initialization is incomplete")
				return bundleValue{}
			}

			if value, exists := p.globals[binding]; exists {
				return value
			}
		}
	} else if fn := p.functions[name]; fn != nil && fn.exported {
		return bundleValue{function: fn}
	}

	b.gap = errors.New("captured local export or cyclic initialization is unresolved")

	return bundleValue{}
}

func mergeBundleValue(a, c bundleValue) bundleValue {
	a.known = a.known && c.known && a.text == c.text
	if !a.known {
		a.text = ""
	}

	a.containsFunctions = a.containsFunctions || c.containsFunctions

	if a.uncertainFunction || c.uncertainFunction {
		a.uncertainFunction = true
		a.function, a.module, a.name = nil, nil, ""
		a.resolver = nil
		a.resolverReceiver = nil
	}

	if a.secret == nil {
		a.secret = c.secret
	}

	if a.remote == nil {
		a.remote = c.remote
		a.remoteKind = c.remoteKind
	}

	cloned := false

	for _, ref := range c.refs {
		seen := false
		for _, r := range a.refs {
			seen = seen || r == ref
		}

		if !seen && len(a.refs) < 6 {
			if !cloned {
				a.refs = slices.Clone(a.refs)
				cloned = true
			}

			a.refs = append(a.refs, ref)
		}
	}

	return a
}

func (b *bundleAnalysis) evalBlock(p *bundleProgram, nodes []*bundleNode, env map[string]bundleValue, depth int) bundleValue {
	for _, n := range nodes {
		if n == nil {
			continue
		}

		v := b.eval(p, n, env, depth+1)
		if v.returned {
			return v
		}
	}

	return bundleValue{}
}

func (b *bundleAnalysis) eval(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	if n == nil || !b.step() {
		return bundleValue{}
	}

	if depth > 64 {
		b.err = errors.New("bundle expression depth limit")
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
		return b.literalValue(p, n)
	case nodeFunction:
		return bundleValue{function: n.function}
	case nodeAssign, nodeDeclare, nodeMutate:
		return b.evalAssignment(p, n, env, depth)
	case nodeAssignGroup:
		return b.evalAssignmentGroup(p, n, env, depth)
	case nodeMember, nodeIndex:
		return b.evalMember(p, n, env, depth)
	case nodeCall, nodeConstruct:
		return b.evalCall(p, n, env, depth+1)
	case nodeResolver, nodeAddress, nodeWrite:
		return b.evalResolverNode(p, n, env, depth)
	case nodeScope:
		return b.evalScope(p, n, env, depth)
	case nodeSequence:
		var v bundleValue
		for _, c := range n.children {
			v = b.eval(p, c, env, depth+1)
		}

		return v
	case nodeConcat:
		a, c := child(0), child(1)
		v := mergeBundleValue(a, c)

		v.known = a.known && c.known && len(a.text)+len(c.text) <= 4096
		if v.known {
			v.text = a.text + c.text
		}

		v.name = ""

		if a.hasCallableIdentity() || c.hasCallableIdentity() {
			b.gap = errors.New("compound bundle callable or module value is unresolved")
			v.function, v.module, v.items = nil, nil, nil
			v.uncertainFunction = true
			v.resolver = nil
			v.resolverReceiver = nil
		}

		return v
	case nodeBranch:
		return b.evalBranch(p, n, env, depth)
	case nodeReturn, nodeAwait:
		return b.evalValueNode(p, n, env, depth)
	case nodeStatement:
		b.evalBlock(p, n.children, env, depth+1)
		return bundleValue{}
	default:
		return b.evalAggregate(p, n, env, depth)
	}
}

func (b *bundleAnalysis) evalValueNode(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	var v bundleValue
	if len(n.children) == 1 {
		v = b.eval(p, n.children[0], env, depth+1)
	} else {
		for _, child := range n.children {
			v = mergeBundleValue(v, b.eval(p, child, env, depth+1))
		}
	}

	v.returned = n.kind == nodeReturn

	return v
}

func (b *bundleAnalysis) evalAggregate(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	var v bundleValue

	for _, child := range n.children {
		x := b.eval(p, child, env, depth+1)
		if n.kind == nodeAggregate && x.returned {
			return x
		}

		if (n.kind == nodeObject || n.kind == nodeArray) && x.hasCallableIdentity() {
			v.containsFunctions = true
		}

		v = mergeBundleValue(v, x)
		if n.kind == nodeArray {
			v.items = append(v.items, x)
		}
	}

	return v
}

func (b *bundleAnalysis) literalValue(p *bundleProgram, n *bundleNode) bundleValue {
	v := bundleValue{text: n.text, known: n.known}
	if n.credential {
		ref := b.refNode(p, n)
		v.secret = &ref
		b.secret(p.file, ref)
	}

	return v
}

func (b *bundleAnalysis) evalAssignment(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	v := bundleValue{}
	if len(n.children) > 0 {
		v = b.eval(p, n.children[0], env, depth+1)
	}

	return b.assignValue(p, n, env, v)
}

func (b *bundleAnalysis) evalAssignmentGroup(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	// Go evaluates all right-hand expressions before updating any binding.
	values := make([]bundleValue, len(n.children))
	for i, assignment := range n.children {
		if !b.step() {
			return bundleValue{}
		}

		values[i] = b.eval(p, assignment.children[0], env, depth+1)
	}

	for i, assignment := range n.children {
		if !b.step() {
			return bundleValue{}
		}

		b.assignValue(p, assignment, env, values[i])
	}

	return bundleValue{}
}

func (b *bundleAnalysis) assignValue(p *bundleProgram, n *bundleNode, env map[string]bundleValue, v bundleValue) bundleValue {
	if n.globalWrite && b.err == nil {
		// Cross-frame global state is not modeled. Stop this evaluation before
		// another frame can read a stale copied global value.
		b.err = errors.New("script global binding writes are unresolved")
		if p.language == language.Python {
			b.err = errors.New("complex Python binding writes are unresolved")
		}

		b.globalWriteStop = true

		return bundleValue{}
	}

	if n.locals != nil {
		b.gap = errors.New("destructured script binding values are unresolved")
		for name := range n.locals {
			b.bindValue(env, name, bundleValue{uncertainFunction: true})
		}

		return bundleValue{}
	}

	previous, exists := env[n.name]
	if n.rebind && previous.resolver != nil && (v.resolver != previous.resolver || v.name != previous.name) {
		// Go frames currently copy global bindings. A rebinding must stop
		// before a caller can continue with an obsolete resolver value.
		b.err = errors.New("resolver rebinding in Go is unresolved")
		b.globalWriteStop = true

		return bundleValue{}
	}

	if n.kind == nodeDeclare && exists {
		return previous
	}

	if n.kind == nodeMutate {
		v = mergeBundleValue(v, previous)
		if previous.hasCallableIdentity() || v.hasCallableIdentity() {
			b.gap = errors.New("compound bundle function write is unresolved")
			v.uncertainFunction = true
		}

		v.function, v.module, v.name, v.known = nil, nil, "", false
		v.resolver = nil
		v.resolverReceiver = nil
	}

	if env["*conditional*"].known {
		v = b.conditionalAssignment(previous, v, exists)
	}

	if n.name != "" {
		b.bindValue(env, n.name, v)
	}

	return v
}

func (b *bundleAnalysis) conditionalAssignment(previous, v bundleValue, exists bool) bundleValue {
	if previous.secret != nil && v.secret == nil || previous.remote != nil && v.remote == nil {
		// Flattened alternatives cannot establish which overwrite executes.
		b.gap = errors.New("conditional bundle provenance overwrite is unresolved")
	}

	if exists && (!previous.known || !v.known || previous.text != v.text) {
		v.text, v.known = "", false
	}

	if v.hasCallableIdentity() || previous.hasCallableIdentity() ||
		v.name != previous.name && (v.hasSymbolicName() || previous.hasSymbolicName()) {
		b.gap = errors.New("conditional bundle function binding is unresolved")
		v.function, v.module, v.name, v.uncertainFunction = nil, nil, "", true
		v.resolver = nil
		v.resolverReceiver = nil
	}

	return v
}

func (b *bundleAnalysis) evalScope(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	local := map[string]bundleValue{}
	maps.Copy(local, env)

	for name := range n.locals {
		b.bindValue(local, name, bundleValue{})
	}

	v := b.evalBlock(p, n.children, local, depth+1)
	for name, value := range local {
		if !n.locals[name] {
			env[name] = value
		}
	}

	return v
}

func (b *bundleAnalysis) evalBranch(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	local := map[string]bundleValue{}
	maps.Copy(local, env)
	// This source-inaccessible key marks writes in conditional blocks.
	// Function alternatives cannot be represented by one function pointer.
	local["*conditional*"] = bundleValue{known: true}

	var v bundleValue

	for _, c := range n.children {
		x := b.eval(p, c, local, depth+1)
		if x.returned {
			b.gap = errors.New("conditional bundle returns are unresolved")
			local["*conditional-return*"] = bundleValue{known: true}
		}

		if x.hasCallableIdentity() {
			b.gap = errors.New("conditional bundle function value is unresolved")
			x.function, x.module, x.uncertainFunction = nil, nil, true
			x.resolver = nil
			x.resolverReceiver = nil
		}

		v = mergeBundleValue(v, x)
	}
	// Join the observed state with the entry bindings. Unsupported provenance
	// erasures within flattened alternatives already leave an explicit gap.
	for name, value := range local {
		switch name {
		case "*conditional-return*":
			env[name] = value
		case "*conditional*":
		default:
			env[name] = mergeBundleValue(env[name], value)
		}
	}

	return v
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

	if fn.program.failed {
		b.gap = errors.New("captured module initialization is incomplete")
		return bundleValue{}
	}

	maps.Copy(env, fn.program.globals)

	for name := range fn.locals {
		b.bindValue(env, name, bundleValue{uncertainFunction: fn.python != nil})
	}

	if fn.self != "" {
		b.bindValue(env, fn.self, bundleValue{function: fn})
	}

	for i, name := range fn.params {
		if i < len(args) {
			b.bindValue(env, name, args[i])
		} else {
			b.bindValue(env, name, bundleValue{})
		}
	}

	v := b.evalBlock(fn.program, fn.body, env, depth+1)
	if env["*conditional-return*"].known {
		return bundleValue{}
	}

	v.returned = false

	return v
}

func (b *bundleAnalysis) bindValue(env map[string]bundleValue, name string, value bundleValue) {
	if b.err != nil {
		return
	}

	if _, exists := env[name]; !exists && len(env) >= 1024 {
		// Continuing with a rejected shadow/overwrite could resolve a stale
		// function or import instead. Keep earlier observations and stop work.
		b.err = errors.New("bundle binding limit")
		return
	}

	env[name] = value
}

func (b *bundleAnalysis) evalCall(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) bundleValue {
	if len(n.children) == 0 {
		return bundleValue{}
	}

	callee, args := b.evalCallArguments(p, n, env, depth)
	if b.err != nil {
		return bundleValue{}
	}

	ref := b.refNode(p, n)
	if callee.function != nil {
		if n.kind == nodeConstruct {
			b.gap = errors.New("local bundle constructor result is unresolved")
			return bundleValue{}
		}

		args, valid := b.functionArguments(callee.function, n.argumentNames, args)
		if !valid {
			return bundleValue{}
		}

		v := b.callFunction(callee.function, args, depth+1)
		if b.err != nil {
			return bundleValue{}
		}

		if (v.secret != nil || v.remote != nil) && len(v.refs) < 6 {
			v.refs = append(slices.Clone(v.refs), ref)
		}

		return v
	}

	name := callee.name
	if value, ok := b.resolverConstructor(p, n, name, args); ok {
		return value
	}

	if name == "require" && len(args) == 1 && args[0].known {
		return b.requireValue(p, args[0].text)
	}

	if bundleEnvironment(name) && len(args) > 0 && args[0].known && literals.SensitiveName(args[0].text) {
		b.secret(p.file, ref)
		return bundleValue{secret: &ref}
	}

	if bundleFileRead(name) && len(args) > 0 && args[0].known && literals.SensitivePath(args[0].text) {
		b.secret(p.file, ref)
		return bundleValue{secret: &ref}
	}

	if b.dnsCall(p, n, callee, args, ref) {
		// Resolver results are not HTTP response bodies or executable downloads.
		return bundleValue{}
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

// Python keywords retain their parameter identity across captured helper calls.
// Unknown expansions, duplicate assignments and unknown names cannot be flattened
// into positional arguments without inventing a flow.
func (b *bundleAnalysis) functionArguments(fn *bundleFunction, names []string, args []bundleValue) ([]bundleValue, bool) {
	if fn.python == nil {
		return args, true
	}

	if len(fn.params) > 1024 {
		b.err = errors.New("bundle function parameter budget exceeded")
		return nil, false
	}

	parameters := make(map[string]int, len(fn.params))
	for i, name := range fn.params {
		if !b.step() {
			return nil, false
		}

		parameters[name] = i
	}

	bound := make([]bundleValue, len(fn.params))
	assigned := make([]bool, len(fn.params))

	for i, value := range args {
		if !b.step() {
			return nil, false
		}

		index, valid := i, false
		if i >= len(names) {
			valid = false
		} else if names[i] != "" {
			index, valid = parameters[names[i]]
			valid = valid && index >= fn.python.positionalOnly
		} else {
			valid = i < fn.python.positional
		}

		if !valid || index >= len(bound) || assigned[index] {
			b.gap = errors.New("captured Python call arguments are unresolved")
			return nil, false
		}

		bound[index], assigned[index] = value, true
	}

	for i, required := range fn.python.required {
		if required && !assigned[i] {
			b.gap = errors.New("required captured Python call argument is missing")
			return nil, false
		}
	}

	return bound, true
}

func (b *bundleAnalysis) requireValue(p *bundleProgram, specifier string) bundleValue {
	imp := bundleImport{
		module: strings.TrimPrefix(specifier, "node:"),
		local:  strings.HasPrefix(specifier, "."),
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

func (b *bundleAnalysis) evalCallArguments(p *bundleProgram, n *bundleNode, env map[string]bundleValue, depth int) (bundleValue, []bundleValue) {
	callee := b.eval(p, n.children[0], env, depth+1)
	if b.err != nil {
		return bundleValue{}, nil
	}

	var args []bundleValue

	for _, c := range n.children[1:] {
		value := b.eval(p, c, env, depth+1)
		if b.err != nil {
			return bundleValue{}, nil
		}

		args = append(args, value)
	}

	return callee, args
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
	case "str", "bytes", "bytearray", "string", "[]byte", "strings.NewReader", "strings.NewReplacer", "strings.TrimSpace", "io.ReadAll", "io/ioutil.ReadAll", "JSON.stringify", "json.dumps", "json.loads", "Buffer.from", "base64.b64decode", "base64.b64encode", "base64.b32encode", "encoding/hex.EncodeToString", "encoding/base32.StdEncoding.EncodeToString", "encoding/base64.StdEncoding.EncodeToString", "encoding/base64.RawURLEncoding.EncodeToString", "atob", "btoa", "encodeURIComponent":
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
			if v.hasCallableIdentity() {
				b.gap = errors.New("dynamic bundle module or function member is unresolved")
			}

			return bundleValue{}
		}

		property = key.text
	}

	if v.uncertainFunction {
		b.gap = errors.New("uncertain bundle callable or module member is unresolved")
		return bundleValue{uncertainFunction: true}
	}

	if v.module != nil {
		return b.exportValue(v.module, property)
	}

	if v.function != nil {
		b.gap = errors.New("bundle function member is unresolved")
		return bundleValue{}
	}

	if v.containsFunctions {
		b.gap = errors.New("collection bundle function member is unresolved")
		return bundleValue{}
	}

	if value, ok := b.resolverMember(p, v, property, n); ok {
		return value
	}

	if v.name == "" && v.remote == nil {
		if v.secret == nil {
			// An unknown receiver's property is not a rooted global API name.
			return bundleValue{}
		}

		v.name = "$source"
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
	if p.embedded {
		return nil
	}

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
		if name == "Buffer.from" && len(args) > 1 {
			// Encoding/offset/length select how input bytes are interpreted;
			// they are not copied into the returned buffer as secret data.
			args = args[:1]
		}

		v := bundleValue{}
		for _, a := range args {
			v = mergeBundleValue(v, a)
		}

		return v
	}

	if callee.secret != nil || callee.remote != nil && callee.remoteKind == 2 {
		if strings.HasSuffix(name, ".hex") || strings.HasSuffix(name, ".toString") {
			callee.text, callee.known = "", false

			return callee
		}
	}

	for _, method := range []string{".read", ".read_text", ".read_bytes", ".text", ".json", ".encode", ".decode"} {
		if strings.HasSuffix(name, method) && (callee.remote != nil || callee.secret != nil) {
			callee.remoteKind = 2
			callee.text, callee.known = "", false

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
