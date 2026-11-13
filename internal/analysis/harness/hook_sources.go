package harness

import (
	"path"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/hookevent"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	maxHookSourceDepth = 6
	pluginRootValue    = "\x00scout-plugin-root"
	pluginRootMarker   = pluginRootValue + "/"
)

// HookSources holds bounded static paths and their unresolved edges.
type HookSources struct {
	Paths       []HookSourcePath
	Diagnostics []report.Diagnostic
}

type HookSourcePath struct {
	Target  string
	Event   string
	Steps   []report.SourceRef
	Scope   source.Span
	Exclude []source.Span
}

type hookSourceWalk struct {
	plugin          *plugin
	event           string
	active          map[string]bool
	activeFunctions map[hookFunctionKey]bool
	origins         map[string]*document.File
}

func (p *plugin) inspectHookSources(e *entry, hook *jsonconfig.Node, event string) {
	if !hookevent.Known(event) {
		return
	}

	if mode := hook.Get("shell"); mode != nil && mode.String != "bash" && mode.String != "sh" {
		return
	}

	command := hook.Get("command")

	initial := ref(e, command.Span)
	if initial == nil {
		return
	}

	walk := hookSourceWalk{plugin: p, event: event, active: map[string]bool{}, origins: map[string]*document.File{e.meta.Path: e.doc}}
	if args := hook.Get("args"); args != nil {
		walk.argv(e, command, args, *initial)
	}

	for _, unit := range e.doc.Units() {
		if unit.Origin != document.OriginHookShell || unit.Span.Start < hook.Span.Start || unit.Span.End > hook.Span.End {
			continue
		}

		if tree, ok := unit.Tree.(parse.ShellTree); ok {
			walk.commands(e, unit.View, hookSourceTree(tree), hookSourceState{}, nil, true)
		}
	}
}

func (w *hookSourceWalk) argv(e *entry, command, args *jsonconfig.Node, initial report.SourceRef) {
	name, _ := command.Text()
	prefix := "${" + pluginRootParameters[w.plugin.host] + "}/"
	direct := !hookSourceInterpreter(name)
	operand, span := name, command.Span

	if !direct {
		if len(args.Elements) == 0 {
			return
		}

		arg := args.Elements[0]
		if flag, _ := arg.Text(); flag == "--" && len(args.Elements) > 1 {
			arg = args.Elements[1]
		}

		operand, _ = arg.Text()
		span = arg.Span
	}

	if !strings.HasPrefix(operand, prefix) {
		return
	}

	span.Start = min(span.Start, initial.ByteStart)

	span.End = max(span.End, initial.ByteEnd)
	if at := ref(e, span); at != nil {
		initial = *at
	}

	if rel, reason := w.resolveFile(pluginRootMarker+strings.TrimPrefix(operand, prefix), ""); reason == "" {
		w.follow(rel, hookSourceState{}, []report.SourceRef{initial}, direct)
	} else {
		w.gap(initial, reason, "A shell source path could not be resolved within the captured plugin.")
	}
}

type hookSourceState struct {
	vars               map[string]string
	ambiguousFunctions map[string]bool
	returns            *hookSourceState
	functions          map[string]hookSourceFunction
	cwd                string
	positional         []hookSourceArgument
	canReturn          bool
	lookupUnknown      bool
	rootUnknown        bool
	returned           bool
	exited             bool
}

func (w *hookSourceWalk) commands(e *entry, view source.View, tree *shellsyntax.File, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	if tree == nil {
		return state
	}

	for i := 0; i < len(tree.Statements); {
		stmts := tree.Statements[i:]

		if !w.plugin.b.step() {
			return state.opaque()
		}

		end := hookAndOrEnd(stmts)
		if end != 0 {
			out := w.andOr(e, view, stmts[:end+1], state, chain, entrypoint)

			state = *out.merged()
			if out.success == nil && out.failure == nil {
				return state
			}
		} else if !w.statement(e, view, stmts[0], chain, entrypoint, &state) {
			return state
		}

		i += end + 1
	}

	return state
}

func (s hookSourceState) opaque() hookSourceState {
	s.cwd, s.vars, s.positional = "", nil, nil
	s.functions, s.ambiguousFunctions = nil, nil
	s.rootUnknown, s.lookupUnknown = true, true

	return s
}

func (w *hookSourceWalk) value(word *shellsyntax.Word, state hookSourceState, assignment bool) (string, bool) {
	if word == nil || word.Expands {
		return "", false
	}

	var b strings.Builder

	for _, part := range word.Parts {
		switch part.Kind {
		case "literal":
			b.WriteString(part.Text)
		case "parameter":
			if !assignment && !part.Quoted {
				return "", false
			}

			if part.Text != "" && part.Text == pluginRootParameters[w.plugin.host] && !state.rootUnknown {
				b.WriteString(pluginRootValue)
				continue
			}

			value, ok := state.parameter(part.Text)
			if !ok {
				return "", false
			}

			b.WriteString(value)
		default:
			return "", false
		}

		if b.Len() > 4096 {
			return "", false
		}
	}

	return b.String(), true
}

func (w *hookSourceWalk) bind(cmd *shellsyntax.Command, state *hookSourceState) {
	for _, assignment := range cmd.Assignments {
		if assignment.Name == pluginRootParameters[w.plugin.host] {
			state.rootUnknown = true
			delete(state.vars, assignment.Name)

			continue
		}

		if assignment.Name == "PATH" || assignment.Name == "CDPATH" || assignment.Name == "IFS" {
			*state = state.opaque()
			continue
		}

		value, known := w.value(assignment.Value, *state, true)
		if _, exists := state.vars[assignment.Name]; !known || !exists && len(state.vars) >= 128 {
			delete(state.vars, assignment.Name)
			continue
		}

		if state.vars == nil {
			state.vars = make(map[string]string)
		}

		state.vars[assignment.Name] = value
	}
}

func (w *hookSourceWalk) statement(e *entry, view source.View, stmt *shellsyntax.Statement, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	if stmt.Negated || stmt.Background || len(stmt.Commands) != 1 || stmt.Next == "&" {
		w.skipStatement(e, view, stmt, entrypoint, state)

		return true
	}

	cmd := stmt.Commands[0]
	if cmd.ExclusiveBranches && len(cmd.Words) == 0 && len(cmd.Redirects) == 0 && len(cmd.Assignments) == 0 && len(cmd.Invalidates) == 0 {
		*state = w.conditional(e, view, cmd, *state, chain, entrypoint)
		return !state.returned && !state.exited
	}

	if cmd.FunctionName != "" && cmd.FunctionBody != nil && len(cmd.Redirects) == 0 {
		w.defineFunction(e, view, cmd, chain, state)
		return true
	}

	if hookCommandWritesDuringExpansion(cmd) {
		return w.unverifiedCommand(e, view, cmd, state, "Shell expansions can change bindings used by further source commands.")
	}

	if len(cmd.Assignments) > 0 && len(cmd.Words) == 0 && len(cmd.Redirects) == 0 && hookSourceAssignment(cmd, *state) {
		w.bind(cmd, state)
		return true
	}

	if len(cmd.Words) == 0 || len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 {
		return w.modifiedStatement(e, view, cmd, entrypoint, state)
	}

	return w.simpleStatement(e, view, stmt, chain, entrypoint, state)
}

func hookSourceAssignment(cmd *shellsyntax.Command, state hookSourceState) bool {
	return cmd.Declaration == "" || cmd.Declaration == "export" && len(cmd.DeclarationArgs) == 0 && !state.hasFunction("export")
}

func (w *hookSourceWalk) simpleStatement(e *entry, view source.View, stmt *shellsyntax.Statement, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	cmd := stmt.Commands[0]

	name, literal := cmd.Words[0].Literal()
	if state.ambiguousFunctions[name] {
		w.commandGap(e, view, cmd.Span, "hook_source_function_unverified", "Shell branches leave the function called here ambiguous.")

		*state = state.opaque()

		return false
	}

	if fn, ok := state.functions[name]; ok && !state.lookupUnknown {
		return w.callFunction(e, view, cmd, fn, chain, state)
	}

	if !literal && (!entrypoint || !w.directLaunch(e, view, cmd, state, chain)) {
		return w.unverifiedCommand(e, view, cmd, state, "An expanded shell command name prevents resolving further source commands.")
	}

	if hookSourceHasRuntimeExpansion(cmd) && hookHasSourceCommand(cmd, entrypoint) {
		w.commandGap(e, view, cmd.Span, "hook_source_dynamic", "Shell expansions prevent resolving this source command.")

		*state = state.opaque()

		return false
	}

	if w.rootChanged(cmd) {
		state.rootUnknown = true
		state.vars = nil
	}

	switch name {
	case "exit", "return":
		if state.lookupUnknown || !w.knownExitStatus(cmd.Words[1:], *state) || name == "return" && !state.canReturn {
			return w.unverifiedCommand(e, view, cmd, state, "An unverified shell exit or return prevents resolving further source commands.")
		}

		state.returned = name == "return"

		state.exited = name == "exit"

		return false
	case "shift":
		state.positional = nil
		return true
	case "cd":
		if state.lookupUnknown {
			state.cwd = ""
			return true
		}

		state.changeDirectory("")

		return true
	}

	if hookSourceOpaqueCommand(name) {
		return w.unverifiedCommand(e, view, cmd, state, "Shell command effects prevent resolving further source commands.")
	}

	if literal && (name == "source" || name == "." || entrypoint && hookSourceLaunch(name)) {
		return w.linkCommand(e, view, cmd, name, state, chain)
	}

	if !hookSourceKeepsDirectory(name) {
		state.cwd = ""
	}

	return true
}

func (w *hookSourceWalk) directLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	value, known := w.value(cmd.Words[0], *state, false)
	if !known || !strings.HasPrefix(value, pluginRootMarker) {
		return false
	}

	w.resolveCommand(e, view, cmd, "", *state, chain)

	return true
}

func (w *hookSourceWalk) unverifiedCommand(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, message string) bool {
	w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", message)

	*state = state.opaque()

	return false
}

func (w *hookSourceWalk) modifiedStatement(e *entry, view source.View, cmd *shellsyntax.Command, entrypoint bool, state *hookSourceState) bool {
	if cmd.Group != nil || cmd.Prelude != nil || cmd.Subshell != nil || len(cmd.Alternatives) > 0 || len(cmd.Invalidates) > 0 {
		w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving further source commands.")

		*state = state.opaque()

		return false
	}

	if hookHasSourceCommand(cmd, entrypoint) {
		w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", "Shell command modifiers prevent resolving this source command.")
		name, _ := cmd.Words[0].Literal()
		state.lookupUnknown = state.lookupUnknown || name == "source" || name == "."
	}

	if cmd.Declaration != "" && (cmd.Declaration != "export" || state.hasFunction("export")) {
		return w.unverifiedCommand(e, view, cmd, state, "Shell declarations can change assignment semantics in further source commands.")
	}

	if w.rootChanged(cmd) {
		state.rootUnknown = true
	}

	state.cwd, state.vars, state.positional = "", nil, nil

	if len(cmd.Words) > 0 {
		name, literal := cmd.Words[0].Literal()
		if !literal || state.hasFunction(name) || hookSourceOpaqueCommand(name) || name == "exit" || name == "return" {
			return w.unverifiedCommand(e, view, cmd, state, "Shell command modifiers prevent resolving this function or command.")
		}
	}

	return true
}

func (w *hookSourceWalk) skipStatement(e *entry, view source.View, stmt *shellsyntax.Statement, entrypoint bool, state *hookSourceState) {
	for _, cmd := range stmt.Commands {
		if hookHasSourceCommand(cmd, entrypoint) {
			w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving this source command.")
		}
	}

	// Background jobs and pipelines have no modeled in-shell effects. A
	// negated command or an OR list may still modify the current shell.
	if !stmt.Background && stmt.Next != "&" {
		*state = state.opaque()
	}
}

func hookCommandWritesDuringExpansion(cmd *shellsyntax.Command) bool {
	for _, word := range cmd.Words {
		if word.Writes {
			return true
		}
	}

	for _, assignment := range cmd.Assignments {
		if assignment.Value != nil && assignment.Value.Writes {
			return true
		}
	}

	for _, redirect := range cmd.Redirects {
		if redirect.Target != nil && redirect.Target.Writes || redirect.Body != nil && redirect.Body.Writes {
			return true
		}
	}

	return false
}

func hookSourceHasRuntimeExpansion(cmd *shellsyntax.Command) bool {
	for _, word := range cmd.Words {
		for _, part := range word.Parts {
			if part.Kind == "substitution" || part.Tree != nil {
				return true
			}
		}
	}

	return false
}

func hookHasSourceCommand(cmd *shellsyntax.Command, entrypoint bool) bool {
	if len(cmd.Words) == 0 {
		return false
	}

	name, literal := cmd.Words[0].Literal()

	return name == "source" || name == "." || entrypoint && literal && hookSourceLaunch(name)
}

func (w *hookSourceWalk) rootChanged(cmd *shellsyntax.Command) bool {
	name := pluginRootParameters[w.plugin.host]
	for _, assignment := range cmd.Assignments {
		if assignment.Name == name {
			return true
		}
	}

	if cmd.Declaration != "" {
		return true
	}

	if len(cmd.Words) == 0 {
		return false
	}

	verb, _ := cmd.Words[0].Literal()
	switch verb {
	case "export", "read", "mapfile", "readarray", "getopts", "let":
		return true
	case "printf":
		if len(cmd.Words) > 1 {
			option, known := cmd.Words[1].Literal()
			return !known || strings.HasPrefix(option, "-v")
		}
	}

	return false
}

func (w *hookSourceWalk) commandGap(e *entry, view source.View, s source.Span, code, message string) {
	if span, err := view.Original(s); err == nil {
		if at := ref(e, span); at != nil {
			w.gap(*at, code, message)
		}
	}
}

func hookSourceOpaqueCommand(name string) bool {
	switch name {
	case "alias", "hash", "eval", "trap", "exec", "command", "builtin", "enable", "shopt", "set", "unset", "declare", "local", "typeset", "readonly":
		return true
	default:
		return false
	}
}

func hookSourceKeepsDirectory(name string) bool {
	switch name {
	case ":", "true", "false", "echo", "printf", "test", "[":
		return true
	default:
		return false
	}
}

func (w *hookSourceWalk) linkCommand(e *entry, view source.View, cmd *shellsyntax.Command, name string, state *hookSourceState, chain []report.SourceRef) bool {
	if state.lookupUnknown {
		return w.unverifiedCommand(e, view, cmd, state, "Earlier shell code can change which shell command is called.")
	}

	next, ok := w.resolveCommand(e, view, cmd, name, *state, chain)
	if name != "source" && name != "." {
		state.cwd = ""
		return true
	}

	if !ok {
		*state = state.opaque()
		return true
	}

	next.canReturn = state.canReturn
	if args := hookSourceOperands(cmd.Words, name); len(args) > 1 {
		next.positional = nil
		if w.hasFixedArgument(args[1:], *state) {
			next.positional = state.positional
		}
	}

	*state = next

	return !state.exited
}

func (w *hookSourceWalk) resolveCommand(e *entry, view source.View, cmd *shellsyntax.Command, name string, state hookSourceState, chain []report.SourceRef) (hookSourceState, bool) {
	span, err := view.Original(cmd.Span)
	if err != nil {
		return state, false
	}

	at := ref(e, span)
	if at == nil {
		return state, false
	}

	args := hookSourceOperands(cmd.Words, name)
	if len(args) == 0 {
		if name == "source" || name == "." {
			w.gap(*at, "hook_source_command_unverified", "Shell source options or operands could not be determined statically.")
		}

		return state, false
	}

	operand := args[0]

	value, known := w.value(operand, state, false)
	if !known {
		if name != "source" && name != "." && !hookSourceInterpreter(name) {
			return state, false
		}

		w.gap(*at, "hook_source_dynamic", "A shell source path could not be determined statically.")

		return state, false
	}

	if strings.HasPrefix(value, pluginRootValue) && state.rootUnknown {
		w.gap(*at, "hook_source_dynamic", "A shell source path could not be determined statically.")
		return state, false
	}

	rel, reason := w.resolveFile(value, state.cwd)
	if reason != "" {
		w.gap(*at, reason, "A shell source path could not be resolved within the captured plugin.")
		return state, false
	}

	steps := make([]report.SourceRef, 0, len(chain)+1)
	steps = append(steps, chain...)
	steps = append(steps, *at)

	isSource := name == "source" || name == "."
	direct := !isSource && !hookSourceInterpreter(name)
	arguments := state.positional

	if !isSource || len(args) > 1 {
		arguments = w.arguments(args[1:], state)
	}

	if !isSource {
		state = hookSourceState{cwd: state.cwd, rootUnknown: state.rootUnknown}
	}

	state.canReturn = isSource
	state.positional = arguments

	return w.follow(rel, state, steps, direct)
}

func hookSourceOperands(words []*shellsyntax.Word, name string) []*shellsyntax.Word {
	if name != "source" && name != "." && !hookSourceInterpreter(name) {
		return words
	}

	args := words[1:]
	if len(args) > 0 {
		if flag, _ := args[0].Literal(); flag == "--" {
			args = args[1:]
		} else if strings.HasPrefix(flag, "-") {
			return nil
		}
	}

	return args
}

type hookSourceArgument struct {
	value string
	known bool
}

func (s hookSourceState) parameter(name string) (string, bool) {
	if index, err := strconv.Atoi(name); err == nil && index > 0 && index <= len(s.positional) {
		arg := s.positional[index-1]
		return arg.value, arg.known
	}

	value, ok := s.vars[name]

	return value, ok
}

func (w *hookSourceWalk) arguments(words []*shellsyntax.Word, state hookSourceState) []hookSourceArgument {
	args := make([]hookSourceArgument, 0, min(len(words), 32))
	for _, word := range words[:min(len(words), 32)] {
		value, known := w.value(word, state, false)
		if !known && !hookFixedArgument(word) {
			// Field splitting or pathname expansion can change subsequent
			// argument positions as well.
			break
		}

		args = append(args, hookSourceArgument{value, known})
	}

	return args
}

func (w *hookSourceWalk) hasFixedArgument(words []*shellsyntax.Word, state hookSourceState) bool {
	for _, word := range words {
		if _, known := w.value(word, state, false); known || hookFixedArgument(word) {
			return true
		}
	}

	return false
}

func hookFixedArgument(word *shellsyntax.Word) bool {
	if word.Expands {
		return false
	}

	for _, part := range word.Parts {
		if part.Kind != "literal" && (!part.Quoted || part.Text == "@" || part.Text == "*") {
			return false
		}
	}

	return true
}

func hookSourceInterpreter(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh":
		return true
	default:
		return false
	}
}

func hookSourceLaunch(name string) bool {
	return hookSourceInterpreter(name) || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") || name == ""
}

func (w *hookSourceWalk) knownExitStatus(args []*shellsyntax.Word, state hookSourceState) bool {
	switch len(args) {
	case 0:
		return true
	case 1:
		value, known := w.value(args[0], state, false)
		_, err := strconv.ParseInt(value, 10, 64)

		return known && err == nil
	default:
		return false
	}
}

func (w *hookSourceWalk) directory(args []*shellsyntax.Word, state hookSourceState) string {
	if len(args) != 1 {
		return ""
	}

	value, known := w.value(args[0], state, false)
	if !known || state.rootUnknown && strings.HasPrefix(value, pluginRootValue) {
		return ""
	}

	rel, reason := w.resolve(value, state.cwd)
	if reason != "" {
		return ""
	}

	return rel
}

func (w *hookSourceWalk) resolveFile(value, cwd string) (string, string) {
	_, base := path.Split(value)
	if base == "" || base == "." || base == ".." {
		return "", "hook_source_path_unverified"
	}

	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, pluginRootMarker) && strings.Contains(value, "/") {
		value = "./" + value
	}

	return w.resolve(value, cwd)
}

func (w *hookSourceWalk) resolve(value, cwd string) (string, string) {
	var candidate string

	switch {
	case value == pluginRootValue:
		candidate = "."
	case strings.HasPrefix(value, pluginRootMarker):
		candidate = strings.TrimPrefix(value, pluginRootMarker)
		if candidate == "" {
			candidate = "."
		}
	case strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || value == "." || value == "..":
		if cwd == "" {
			return "", "hook_source_cwd_unknown"
		}

		candidate = path.Join(cwd, value)
	default:
		return "", "hook_source_path_unverified"
	}

	rel, reason := localPath(candidate, false)
	if reason != "" {
		return "", "hook_source_path_unverified"
	}

	return rel, ""
}

func (w *hookSourceWalk) follow(rel string, state hookSourceState, chain []report.SourceRef, direct bool) (hookSourceState, bool) {
	p := w.plugin

	last := chain[len(chain)-1]
	if len(chain) > maxHookSourceDepth || len(p.b.hookSourcePaths) >= p.b.r.Limits.References {
		w.gap(last, "hook_source_limit", "The shell source path budget was exhausted.")
		return state, false
	}

	e := p.entry(rel)
	if e == nil || e.doc == nil {
		w.gap(last, "hook_source_not_captured", "A referenced shell file was not captured in the plugin.")
		return state, false
	}

	if w.active[e.meta.Path] {
		w.gap(last, "hook_source_cycle", "A cycle was found in local shell source references.")
		return state, false
	}

	if direct && !hasShellShebang(e.doc.Artifact().Content()) {
		w.gap(last, "hook_source_interpreter_unverified", "The interpreter of a directly launched file could not be verified as shell.")
		return state, false
	}

	w.origins[e.meta.Path] = e.doc

	*e.doc = e.doc.WithHookSourceShell(p.b.ctx)

	unit, ok := hookSourceUnit(e.doc.Units())
	if !ok {
		w.gap(last, "hook_source_unparsed", "A referenced shell file could not be parsed.")
		return state, false
	}

	tree, _ := unit.Tree.(parse.ShellTree)

	partial := tree.ExecutionError != nil && (tree.DeclarationError != nil || tree.Declarations == nil)
	if partial {
		w.gap(last, "hook_source_unparsed", "A referenced shell file could not be parsed completely.")
	}

	root := hookSourceTree(tree)
	p.b.hookSourcePaths = append(p.b.hookSourcePaths, HookSourcePath{Target: e.meta.Path, Event: w.event, Steps: chain, Exclude: hookFunctionSpans(unit.View, root)})
	w.active[e.meta.Path] = true
	next := w.commands(e, unit.View, root, state.child(), chain, false).resume(state)
	delete(w.active, e.meta.Path)

	return next, !partial
}

func hasShellShebang(text string) bool {
	hint, ok := language.Shebang(text)
	return ok && hint.Language == language.Shell
}

func hookSourceTree(tree parse.ShellTree) *shellsyntax.File {
	if tree.DeclarationError == nil && tree.Declarations != nil {
		return tree.Declarations
	}

	return tree.Tree
}

func hookSourceUnit(units []document.Unit) (document.Unit, bool) {
	for _, unit := range units {
		if unit.Origin == "file" && unit.Language == language.Shell {
			_, ok := unit.Tree.(parse.ShellTree)
			return unit, ok
		}
	}

	return document.Unit{}, false
}

func (w *hookSourceWalk) gap(ref report.SourceRef, code, message string) {
	b := w.plugin.b
	if len(b.hookSourceDiagnostics) >= b.r.Limits.References {
		return
	}

	line, column := 0, 0
	if doc := w.origins[ref.Path]; doc != nil {
		line, column, _ = doc.Index().Position(ref.ByteStart)
	}

	diagnostic := report.Diagnostic{
		Code: code, Path: ref.Path, Line: line, Column: column, Message: message, AffectsScope: true,
	}

	if b.hookSourceSeen == nil {
		b.hookSourceSeen = make(map[report.Diagnostic]bool)
	}

	if !b.hookSourceSeen[diagnostic] {
		b.hookSourceSeen[diagnostic] = true
		b.hookSourceDiagnostics = append(b.hookSourceDiagnostics, diagnostic)
	}
}
