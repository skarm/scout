package shell

import (
	"context"
	"errors"
	"maps"
	"path"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"

	"github.com/skarm/scout/report"
)

const (
	MaxShellOperations = 65536
	MaxShellBindings   = 256
	MaxShellTraceSteps = 6
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	shellConditionalLinks = map[string]bool{"&&": true, "||": true}
	shellBranchLinks      = map[string]bool{"&&": true, "||": true, "&": true}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var shellRedirects = map[string]shellRedirectSpec{
	"<":   {kind: shellReadFile, fd: "0", input: true},
	"<>":  {kind: shellReadFile, fd: "0", input: true},
	"<<<": {kind: shellHereString, fd: "0", input: true},
	"<<":  {kind: shellHereDocument, fd: "0", input: true},
	"<<-": {
		kind:  shellHereDocument,
		fd:    "0",
		input: true,
	},
	"<&": {kind: shellDuplicateInput, fd: "0", input: true},
	">":  {kind: shellWrite, fd: "1", output: true},
	">>": {kind: shellWrite, fd: "1", output: true},
	">|": {
		kind:   shellWrite,
		fd:     "1",
		output: true,
	},
	">&": {
		kind:   shellWrite,
		fd:     "1",
		output: true,
	},
	"&>":  {kind: shellWrite, anyFD: true, output: true},
	"&>>": {kind: shellWrite, anyFD: true, output: true},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var shellWrappers = map[string]bool{"command": true, "env": true, "sudo": true}

//nolint:gochecknoglobals // Read-only language and command classification shared by scans.
var sudoFlagKinds = map[string]string{"--": "end", "-u": "value", "-g": "value", "-E": "flag", "-n": "flag"}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var shellExecutionLongFlags = map[string]bool{"--noprofile": true, "--norc": true}

type shellCheck struct {
	kind  string
	facts check.LanguageFacts
}

type shellOrigin struct {
	source source.Span
	via    []source.Span
}
type shellValue struct {
	text                 string
	known                bool
	credential, download *shellOrigin
}
type shellState struct {
	vars      map[string]shellValue
	functions map[string]*shellsyntax.File
	files     map[string]*shellOrigin
	cwd       string
	ambient   bool
	mayWrite  bool
}

type shellWalk struct {
	ctx               context.Context
	view              source.View
	kind              string
	limit, operations int
	result            result
	err               error
	gap               error
	activeFunctions   map[*shellsyntax.File]bool
	outputs           map[string]*check.Facts
	observeNetwork    func(string, source.Span)
	observeSecret     func(source.Span)
}

type shellRedirectKind uint8

const (
	shellReadFile shellRedirectKind = iota + 1
	shellHereString
	shellHereDocument
	shellDuplicateInput
	shellWrite
)

type shellRedirectSpec struct {
	fd            string
	kind          shellRedirectKind
	anyFD         bool
	input, output bool
}

type shellExecutionToken uint8

const (
	shellExecutionInvalid shellExecutionToken = iota
	shellExecutionEnd
	shellExecutionSkip
	shellExecutionShort
	shellExecutionOperand
)

type shellExecutionState struct{ stdin, noexec bool }

// cat reads stdin only with no file operands or an explicit "-". File operands
// replace, rather than preserve, the incoming pipeline's data.
type catArgumentKind uint8

const (
	catOperand catArgumentKind = iota
	catEndOptions
	catFlags
	catInvalid
)

func newShellState() *shellState {
	return &shellState{
		vars:      map[string]shellValue{},
		functions: map[string]*shellsyntax.File{},
		ambient:   true,
		files:     map[string]*shellOrigin{},
		cwd:       ".",
	}
}

func (a shellCheck) Rule() report.Rule {
	r := report.Rule{
		ID: a.kind, Version: "2", Method: "shell-subset-ast", Severity: report.Medium,
		Limitation: "Bounded native shell subset, not full POSIX/Bash. Command names are syntactic candidates, not resolved executables. Selected straight-line assignments/stdio and constant words only; no general control flow, functions, aliases, field splitting or external-file semantics. A flow is not proof of execution or malicious intent.",
	}
	switch a.kind {
	case ruleSH001:
		r.Title, r.Category, r.Severity = "Downloaded bytes reach an execution input or file", "remote-execution", report.High
		r.Version = "3"
		r.Limitation += " Selected constant file paths retain conservative may-flow provenance through downloads, redirections and script execution; filesystem state, executable resolution and runtime success are unverified."
	case ruleSH002:
		r.Title, r.Category, r.Severity = "Sensitive data reaches a supported curl request argument", "credential-egress", report.High
	case ruleSH003:
		r.Title, r.Category = "Shell evaluates text or sources a file", "dynamic-execution"
	case ruleSH004:
		r.Title, r.Category = "Shell command reads a sensitive credential path", "credential-access"
	}

	r.Description = r.Title

	return r
}

func (shellCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if t, ok := u.Tree.(parse.ShellTree); ok && t.Tree != nil {
			return true
		}
	}

	return false
}

func (a shellCheck) Find(ctx context.Context, f document.File, limit int) (result, error) {
	if ctx == nil {
		return result{}, errors.New("nil shell analysis context")
	}

	if err := ctx.Err(); err != nil {
		return result{}, err
	}

	if a.facts != nil {
		return a.facts.Result(f, a.kind, limit)
	}

	walk := shellWalk{ctx: ctx, kind: a.kind, limit: limit}

	walk.units(f.Units())

	return walk.result, errors.Join(walk.err, walk.gap, ctx.Err())
}

func (a shellCheck) WithLanguageFacts(facts check.LanguageFacts) analyzer {
	a.facts = facts
	return a
}

func (s *shellState) clone() *shellState {
	n := &shellState{
		vars:      make(map[string]shellValue, len(s.vars)),
		functions: map[string]*shellsyntax.File{},
		ambient:   s.ambient,
		files:     s.files,
		mayWrite:  true,
		cwd:       s.cwd,
	}
	maps.Copy(n.vars, s.vars)

	maps.Copy(n.functions, s.functions)

	return n
}
func (s *shellState) barrier() { clear(s.vars); s.ambient = false }

func (s *shellState) parameter(part shellsyntax.Part) shellValue {
	x, ok := s.vars[part.Text]
	if !ok {
		if part.Text == "HOME" && s.ambient {
			x = shellValue{text: "$HOME", known: true}
		} // symbolic, not a host lookup

		if literals.SensitiveName(part.Text) && s.ambient {
			x.credential = &shellOrigin{source: part.Span}
		}
	}

	return x
}

func (v *shellValue) appendPart(x shellValue) {
	*v = mergeShellValue(*v, x)
	if !x.known || len(x.text) > literals.MaxStaticStringBytes-len(v.text) {
		v.known = false
	} else if v.known {
		v.text += x.text
	}
}

func (a *shellWalk) units(units []document.Unit) {
	for _, u := range units {
		t, ok := u.Tree.(parse.ShellTree)
		if !ok || t.Tree == nil {
			continue
		}

		a.view = u.View
		a.list(t.Tree, newShellState())

		if a.err != nil || a.result.Truncated {
			break
		}
	}
}

func (a *shellWalk) step() bool {
	if a.err != nil || a.result.Truncated {
		return false
	}

	if err := a.ctx.Err(); err != nil {
		a.err = err
		return false
	}

	a.operations++
	if a.operations > MaxShellOperations || !analysisbudget.Consume(a.ctx, 1) {
		a.err = errors.New("shell analysis operation budget exceeded")
		return false
	}

	return true
}

func (a *shellWalk) emit(kind string, s source.Span, origin *shellOrigin) {
	if !a.beginEmission(kind) {
		return
	}

	m, err := a.view.Original(s)
	if err != nil {
		a.err = errors.New("shell source mapping failed")
		return
	}

	match := match{Start: m.Start, End: m.End}

	if origin != nil {
		match.Trace, err = a.sourceTrace(origin, s)
		if err != nil {
			a.err = err
			return
		}
	}

	if a.outputs != nil {
		a.outputs[kind].Add(match)
	} else {
		a.result.Matches = append(a.result.Matches, match)
	}
}

func (a *shellWalk) beginEmission(kind string) bool {
	output := a.outputs[kind]
	if a.outputs != nil {
		if output == nil {
			return false
		}
	} else if kind != a.kind {
		return false
	}

	if !a.step() {
		return false
	}

	if output != nil {
		return !output.Done()
	}

	if len(a.result.Matches) >= a.limit {
		a.result.Truncated = true
		return false
	}

	return true
}

func (a *shellWalk) sourceTrace(origin *shellOrigin, s source.Span) ([]trace, error) {
	var out []trace

	spans := append([]source.Span{origin.source}, origin.via...)

	spans = append(spans, s)
	for i, span := range spans {
		x, e := a.view.Original(span)
		if e != nil {
			return nil, errors.New("shell trace mapping failed")
		}

		role := "transform"
		if i == 0 {
			role = "source"
		} else if i == len(spans)-1 {
			role = "sink"
		}

		out = append(out, trace{Role: role, Start: x.Start, End: x.End})
	}

	return out, nil
}

func (a *shellWalk) via(o *shellOrigin, s source.Span) *shellOrigin {
	if o == nil {
		return nil
	}

	if len(o.via) >= MaxShellTraceSteps {
		a.err = errors.New("shell trace budget exceeded")
		return nil
	}

	n := &shellOrigin{source: o.source, via: append([]source.Span(nil), o.via...)}
	if s.End > s.Start {
		n.via = append(n.via, s)
	}

	return n
}

func (a *shellWalk) word(w *shellsyntax.Word, s *shellState) shellValue {
	if w == nil || !a.step() {
		return shellValue{}
	}

	v := shellValue{known: !w.Expands}
	for _, part := range w.Parts {
		if !a.step() {
			return v
		}

		x := a.wordPart(part, s)
		if x.credential != nil && a.observeSecret != nil {
			a.observeSecret(x.credential.source)
		}

		v.appendPart(x)
	}

	if !v.known {
		v.text = ""
	}

	return v
}

func (a *shellWalk) wordPart(part shellsyntax.Part, s *shellState) shellValue {
	x := shellValue{known: true}

	switch part.Kind {
	case "literal":
		x.text = part.Text
	case "parameter":
		x = s.parameter(part)
	case "substitution":
		x = a.list(part.Tree, s.clone())
		x.known = false
	}
	// Unquoted known expansions can split/glob into multiple arguments.
	// Do not reinterpret a value such as "echo /bin/curl" as one executable.
	if part.Kind != "literal" && !part.Quoted && x.known && strings.ContainsAny(x.text, " \t\n*?[") {
		x.known = false
	}

	return x
}

func (a *shellWalk) bind(s *shellState, b shellsyntax.Assignment) {
	if !a.step() {
		return
	}

	v := a.word(b.Value, s)
	v.credential = a.via(v.credential, b.Span)

	v.download = a.via(v.download, b.Span)
	if _, ok := s.vars[b.Name]; !ok && len(s.vars) >= MaxShellBindings {
		a.err = errors.New("shell binding budget exceeded")
		return
	}

	s.vars[b.Name] = v
}

func (a *shellWalk) list(f *shellsyntax.File, s *shellState) shellValue {
	return a.listInput(f, s, shellValue{})
}

func (a *shellWalk) listInput(f *shellsyntax.File, s *shellState, incoming shellValue) shellValue {
	var out shellValue
	if f == nil {
		return out
	}

	conditional := false

	for _, st := range f.Statements {
		if !a.step() {
			break
		}

		branch := conditional || shellBranchLinks[st.Next]

		previousMayWrite := s.mayWrite
		if branch {
			s.mayWrite = true
			s.barrier()
		}

		input := a.pipeline(st, s, incoming)

		out = mergeShellValue(out, input)

		if branch {
			s.barrier()
		}

		conditional = shellConditionalLinks[st.Next]
		s.mayWrite = previousMayWrite
	}

	return out
}

func (a *shellWalk) pipeline(st *shellsyntax.Statement, s *shellState, incoming shellValue) shellValue {
	input := incoming

	for _, cmd := range st.Commands {
		state := s
		if len(st.Commands) > 1 || st.Next == "&" {
			state = s.clone()
		}

		input = a.command(cmd, state, input)
	}

	return input
}

func (a *shellWalk) command(c *shellsyntax.Command, s *shellState, input shellValue) shellValue {
	if !a.step() {
		return shellValue{}
	}

	if c.FunctionName != "" {
		s.functions[c.FunctionName] = c.FunctionBody
		a.function(c.FunctionBody, s.clone(), shellValue{})

		return shellValue{}
	}

	if c.Group != nil || len(c.Alternatives) > 0 {
		return a.compoundCommand(c, s, input)
	}

	if len(c.Words) == 0 && c.Subshell == nil {
		for _, b := range c.Assignments {
			a.bind(s, b)
		}

		a.redirects(c, s, input)
		a.writeRedirected(c, s, shellValue{})

		return shellValue{}
	}

	return a.simpleCommand(c, s, input)
}

func (a *shellWalk) compoundCommand(c *shellsyntax.Command, s *shellState, input shellValue) shellValue {
	input, redirected := a.redirects(c, s, input)

	out := shellValue{}
	if c.Group != nil {
		out = a.listInput(c.Group, s, input)
	} else {
		a.list(c.Prelude, s)

		for _, branch := range c.Alternatives {
			out = mergeShellValue(out, a.listInput(branch, s.clone(), input))
		}

		s.barrier()
	}

	if redirected {
		return shellValue{}
	}

	return out
}

func (a *shellWalk) simpleCommand(c *shellsyntax.Command, s *shellState, input shellValue) shellValue {
	// Prefix assignments do not change parameter expansion of the command's
	// argument words: TOKEN=x curl --data "$TOKEN" uses the previous TOKEN.
	for _, b := range c.Assignments {
		a.word(b.Value, s)
	}

	values := make([]shellValue, len(c.Words))
	for i, w := range c.Words {
		values[i] = a.word(w, s)
	}

	input, outputRedirect := a.redirects(c, s, input)
	if c.Subshell != nil {
		out := a.list(c.Subshell, s.clone())

		if outputRedirect {
			return shellValue{}
		}

		return out
	}

	name, args, ok := shellInvocation(values)
	if !ok {
		s.barrier()
		return shellValue{}
	}

	if body := s.functions[name]; body != nil {
		return a.function(body, s, input)
	}

	out := a.invokeCommand(c, s, input, name, args)
	a.writeRedirected(c, s, out)

	if outputRedirect {
		return shellValue{}
	}

	return out
}

func (a *shellWalk) invokeCommand(c *shellsyntax.Command, s *shellState, input shellValue, name string, args []shellValue) shellValue {
	var out shellValue

	switch name {
	case "curl":
		request := curlArguments(args)

		if a.observeNetwork != nil {
			observed := false

			for _, v := range request.destinations {
				if v.known && httpURL(v.text) {
					a.observeNetwork(v.text, c.Span)

					observed = true
				}
			}

			if !observed && (!request.valid || request.urls > 0) {
				a.observeNetwork("", c.Span)
			}
		}

		if request.valid && request.remote && request.urls == 1 && len(request.outputs) == 1 {
			a.writeFile(s, request.outputs[0], &shellOrigin{source: c.Span})
		}

		return a.curlCommand(c, input, args)
	case "wget":
		a.observeWget(c, args)

		if target, ok := wgetFile(args); ok {
			a.writeFile(s, shellValue{text: target, known: true}, &shellOrigin{source: c.Span})
		}

		if wgetStdout(args) {
			out.download = &shellOrigin{source: c.Span}
		}
	case "cat":
		return a.catCommand(c, s, input, args)
	case "echo":
		out = mergeShellValues(args)
	case "printf":
		out = printfShellOutput(args)
	case "chmod":
		// Permissions do not change the file's downloaded bytes.
	case "cd":
		a.changeDirectory(s, args)
	case "cp", "mv":
		a.copyFile(s, args, name == "mv")

	default:
		a.executionCommand(c, s, input, name, args)
	}

	return out
}

func printfShellOutput(args []shellValue) shellValue {
	if len(args) > 0 && args[0].known && printfStringFormat(args[0].text) {
		return mergeShellValues(args[1:])
	}

	return shellValue{}
}

func mergeShellValues(values []shellValue) shellValue {
	var out shellValue
	for _, value := range values {
		out = mergeShellValue(out, value)
	}

	return out
}

func (a *shellWalk) curlCommand(c *shellsyntax.Command, input shellValue, args []shellValue) shellValue {
	var out shellValue

	request := curlArguments(args)
	if request.valid && request.remote {
		for _, body := range request.bodies {
			v := a.curlBody(c, body, input)

			if v.credential != nil {
				a.emit(ruleSH002, c.Span, v.credential)
			}
		}

		if request.stdout {
			out.download = &shellOrigin{source: c.Span}
		}
	}

	return out
}

func (a *shellWalk) curlBody(c *shellsyntax.Command, body shellBody, input shellValue) shellValue {
	v := body.value
	if body.file && v.known {
		file := v.text
		if body.at {
			file = strings.TrimPrefix(file, "@")
		}

		if file == "-" {
			v = mergeShellValue(v, input)
		} else if literals.SensitivePath(file) {
			v.credential = &shellOrigin{source: c.Span}
			a.emit(ruleSH004, c.Span, nil)
		}
	}

	return v
}

func (a *shellWalk) catCommand(c *shellsyntax.Command, s *shellState, input shellValue, args []shellValue) shellValue {
	var out shellValue

	files, readsInput, valid := catArguments(args)
	if valid {
		if readsInput {
			out = input
		}

		for _, v := range files {
			out.download = mergeShellValue(out, shellValue{download: s.fileOrigin(v)}).download
			if v.known && literals.SensitivePath(v.text) {
				out.credential = &shellOrigin{source: c.Span}
				a.emit(ruleSH004, c.Span, nil)
			}
		}
	}

	return out
}

func (a *shellWalk) executionCommand(c *shellsyntax.Command, s *shellState, input shellValue, name string, args []shellValue) {
	a.fileExecution(c, s, name, args)

	switch name {
	case "eval":
		a.emit(ruleSH003, c.Span, nil)

		for _, v := range args {
			if v.download != nil {
				a.emit(ruleSH001, c.Span, v.download)
			}
		}

		s.barrier()
	case "source", ".":
		a.emit(ruleSH003, c.Span, nil)
		s.barrier()
	case "sh", "bash", "dash", "zsh", "ksh":
		a.interpreterExecution(c, input, args)
	case "true", "false", ":":
	default:
		s.barrier() // unknown builtins/functions can mutate shell state
	}
}

func (a *shellWalk) interpreterExecution(c *shellsyntax.Command, input shellValue, args []shellValue) {
	commandText, readsInput := shellExecution(args)
	if commandText >= 0 {
		a.emit(ruleSH003, c.Span, nil)

		if args[commandText].download != nil {
			a.emit(ruleSH001, c.Span, args[commandText].download)
		}
	}

	if readsInput && input.download != nil {
		a.emit(ruleSH001, c.Span, input.download)
	}
}

func (a *shellWalk) function(body *shellsyntax.File, s *shellState, input shellValue) shellValue {
	if a.activeFunctions == nil {
		a.activeFunctions = map[*shellsyntax.File]bool{}
	}

	if body == nil || a.activeFunctions[body] || len(a.activeFunctions) >= 16 {
		s.barrier()
		return shellValue{}
	}

	a.activeFunctions[body] = true
	defer delete(a.activeFunctions, body)

	return a.listInput(body, s, input)
}

func (a *shellWalk) redirects(c *shellsyntax.Command, s *shellState, input shellValue) (shellValue, bool) {
	output := false

	for _, redirect := range c.Redirects {
		value := a.word(redirect.Target, s)

		spec := shellRedirects[redirect.Op]
		if spec.kind == shellHereDocument {
			value = a.word(redirect.Body, s)
		}

		if !spec.applies(redirect.FD) {
			continue
		}

		if spec.output {
			output = true
		}

		if spec.input {
			input = a.redirectedInput(spec.kind, value, redirect.Span)
			if spec.kind == shellReadFile {
				input.download = s.fileOrigin(value)
			}
		}
	}

	return input, output
}

func (a *shellWalk) redirectedInput(kind shellRedirectKind, value shellValue, span source.Span) shellValue {
	switch kind {
	case shellReadFile:
		input := shellValue{}
		if value.known && literals.SensitivePath(value.text) {
			input.credential = &shellOrigin{source: span}
			a.emit(ruleSH004, span, nil)
		}

		return input
	case shellHereString, shellHereDocument:
		return value
	default:
		return shellValue{}
	}
}

func mergeShellValue(x, y shellValue) shellValue {
	if x.credential == nil {
		x.credential = y.credential
	}

	if x.download == nil {
		x.download = y.download
	}

	return x
}

func shellInvocation(values []shellValue) (string, []shellValue, bool) {
	for layers := 0; len(values) > 0 && layers < 4; layers++ {
		if !values[0].known || values[0].text == "" {
			return "", nil, false
		}

		name := path.Base(values[0].text)

		values = values[1:]
		if name == "builtin" {
			return shellBuiltin(values)
		}

		if !shellWrappers[name] {
			return name, values, true
		}

		var valid bool

		values, valid = shellWrapperArguments(name, values)
		if !valid {
			return "", nil, false
		}
	}

	return "", nil, false
}

func stripShellDoubleDash(values []shellValue) []shellValue {
	if len(values) > 0 && values[0].known && values[0].text == "--" {
		return values[1:]
	}

	return values
}

func shellWrapperArguments(name string, values []shellValue) ([]shellValue, bool) {
	if name == "sudo" {
		return sudoArguments(values)
	}

	values = stripShellDoubleDash(values)
	if len(values) == 0 {
		return values, true
	}

	if !values[0].known || strings.HasPrefix(values[0].text, "-") {
		return nil, false
	}

	if name == "env" && strings.Contains(values[0].text, "=") {
		return nil, false
	}

	return values, true
}

func shellBuiltin(v []shellValue) (string, []shellValue, bool) {
	v = stripShellDoubleDash(v)

	if len(v) == 0 || !v[0].known {
		return "", nil, false
	}

	switch v[0].text {
	case "eval", "source", ".", "echo", "printf", "true", "false", ":":
		return v[0].text, v[1:], true
	}

	return "", nil, false
}

func sudoArguments(values []shellValue) ([]shellValue, bool) {
	for len(values) > 0 && values[0].known && strings.HasPrefix(values[0].text, "-") {
		kind := sudoFlagKinds[values[0].text]
		values = values[1:]

		switch kind {
		case "end":
			return values, true
		case "value":
			if _, valid := knownShellOperand(values, 0); !valid {
				return nil, false
			}

			values = values[1:]
		case "flag":
		default:
			return nil, false
		}
	}

	return values, true
}

func shellExecution(args []shellValue) (int, bool) {
	state := shellExecutionState{}

	for i, value := range args {
		switch classifyShellExecution(value) {
		case shellExecutionInvalid:
			return -1, false
		case shellExecutionEnd:
			return -1, state.readsInput(i == len(args)-1)
		case shellExecutionSkip:
			continue
		case shellExecutionShort:
			command, valid := state.commandIndex(args, i)
			if !valid {
				return -1, false
			}

			if command >= 0 {
				return command, false
			}
		default:
			return -1, state.readsInput(false)
		}
	}

	return -1, state.readsInput(true)
}

func classifyShellExecution(value shellValue) shellExecutionToken {
	if !value.known {
		return shellExecutionInvalid
	}

	if value.text == "--" {
		return shellExecutionEnd
	}

	if strings.HasPrefix(value.text, "--") {
		if shellExecutionLongFlags[value.text] {
			return shellExecutionSkip
		}

		return shellExecutionInvalid
	}

	if strings.HasPrefix(value.text, "-") && len(value.text) > 1 {
		return shellExecutionShort
	}

	return shellExecutionOperand
}

func (spec shellRedirectSpec) applies(fd string) bool { return spec.anyFD || fd == "" || fd == spec.fd }

func (s *shellExecutionState) readsInput(noOperand bool) bool {
	return !s.noexec && (s.stdin || noOperand)
}

func (s *shellExecutionState) commandIndex(args []shellValue, index int) (int, bool) {
	command, valid := shellExecutionFlags(args[index].text[1:], &s.stdin, &s.noexec)
	if !valid {
		return -1, false
	}

	if !command {
		return -1, true
	}

	if s.noexec || index+1 >= len(args) {
		return -1, false
	}

	return index + 1, true
}

func shellExecutionFlags(flags string, stdin, noexec *bool) (bool, bool) {
	command := false

	for _, flag := range flags {
		switch flag {
		case 'n', 'D':
			*noexec = true
		case 'c':
			command = true
		case 's':
			*stdin = true
		case 'e', 'u', 'f', 'x', 'v', 'l', 'p':
		default:
			return false, false
		}
	}

	return command, true
}

func catArguments(args []shellValue) ([]shellValue, bool, bool) {
	var files []shellValue

	options := true
	for _, value := range args {
		switch classifyCatArgument(value, options) {
		case catEndOptions:
			options = false
		case catFlags:
		case catInvalid:
			return nil, false, false
		default:
			files = append(files, value)
		}
	}

	input := len(files) == 0
	for _, value := range files {
		if value.known && value.text == "-" {
			input = true
		}
	}

	return files, input, true
}

func classifyCatArgument(value shellValue, options bool) catArgumentKind {
	if !value.known || !options {
		return catOperand
	}

	if value.text == "--" {
		return catEndOptions
	}

	if !strings.HasPrefix(value.text, "-") || value.text == "-" {
		return catOperand
	}

	if strings.HasPrefix(value.text, "--") {
		return catInvalid
	}

	for _, flag := range value.text[1:] {
		if !strings.ContainsRune("AbEenstTuv", flag) {
			return catInvalid
		}
	}

	return catFlags
}

func printfStringFormat(s string) bool {
	uses := false

	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}

		i++
		if i == len(s) {
			return false
		}

		switch s[i] {
		case 's':
			uses = true
		case '%':
		default:
			return false
		}
	}

	return uses
}

// knownShellOperand reads one literal argv operand without shifting over an
// unknown expansion or a missing value.
func knownShellOperand(args []shellValue, index int) (shellValue, bool) {
	if index >= len(args) || !args[index].known {
		return shellValue{}, false
	}

	return args[index], true
}
