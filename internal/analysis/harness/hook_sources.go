package harness

import (
	"path"
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
	pluginRootMarker   = "\x00scout-plugin-root/"
)

// HookSources holds bounded static paths and their unresolved edges.
type HookSources struct {
	Paths       []HookSourcePath
	Diagnostics []report.Diagnostic
}

type HookSourcePath struct {
	Target string
	Event  string
	Steps  []report.SourceRef
}

type hookSourceWalk struct {
	plugin  *plugin
	event   string
	active  map[string]bool
	origins map[string]*document.File
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
	cwd         string
	conditional bool
	sourced     bool
	rootUnknown bool
	skipAnd     bool
}

func (w *hookSourceWalk) commands(e *entry, view source.View, tree *shellsyntax.File, state hookSourceState, chain []report.SourceRef, entrypoint bool) {
	if tree == nil {
		return
	}

	shadowed := hookSourceShadowed(tree)

	for _, stmt := range tree.Statements {
		if !w.plugin.b.step() {
			return
		}

		if state.skipAnd {
			state.skipAnd = stmt.Next == "&&"
			if !state.skipAnd && state.conditional {
				state.cwd, state.conditional = "", false
			}

			continue
		}

		if !w.statement(e, view, stmt, chain, entrypoint, shadowed, &state) {
			return
		}
	}
}

func (w *hookSourceWalk) statement(e *entry, view source.View, stmt *shellsyntax.Statement, chain []report.SourceRef, entrypoint, shadowed bool, state *hookSourceState) bool {
	if stmt.Negated || len(stmt.Commands) != 1 || stmt.Next == "||" || stmt.Next == "&" {
		w.skipStatement(e, view, stmt, entrypoint, state)

		return true
	}

	cmd := stmt.Commands[0]
	if w.rootChanged(cmd) {
		state.rootUnknown = true
	}

	if len(cmd.Words) == 0 || len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 {
		return w.modifiedStatement(e, view, cmd, entrypoint, state)
	}

	name, _ := cmd.Words[0].Literal()
	if hookSourceHasRuntimeExpansion(cmd) {
		state.cwd = ""

		if hookHasSourceCommand(cmd, entrypoint) {
			w.commandGap(e, view, cmd.Span, "hook_source_dynamic", "Shell expansions prevent resolving this source command.")
			return false
		}
	}

	switch name {
	case "exit", "return":
		return false
	case "alias", "hash", "eval", "trap", "exec":
		w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", "Shell command effects prevent resolving further source commands.")
		return false
	case "command", "builtin", "enable", "shopt", "set":
		w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", "Shell command options or wrappers prevent resolving further source commands.")
		return false
	case "cd":
		if shadowed || state.sourced {
			state.cwd = ""
			return true
		}

		state.cwd = w.directory(cmd.Words[1:], *state, stmt.Next == "&&")
		state.conditional = true

		return true
	}

	state.skipAnd = hookStopsAndChain(name, cmd, stmt, shadowed)

	if name == "source" || name == "." || entrypoint && hookSourceLaunch(name) {
		if shadowed || state.sourced {
			w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", "Earlier shell code can change which shell command is called.")
			return false
		}

		w.command(e, view, cmd, name, *state, chain)
		state.sourced = name == "source" || name == "."
	}

	if !hookSourceKeepsDirectory(name, cmd.Words) || state.conditional && stmt.Next != "&&" {
		state.cwd = ""
	}

	state.conditional = state.conditional && stmt.Next == "&&"

	return true
}

func hookStopsAndChain(name string, cmd *shellsyntax.Command, stmt *shellsyntax.Statement, shadowed bool) bool {
	return name == "false" && !shadowed && len(cmd.Words) == 1 && stmt.Next == "&&"
}

func (w *hookSourceWalk) modifiedStatement(e *entry, view source.View, cmd *shellsyntax.Command, entrypoint bool, state *hookSourceState) bool {
	if cmd.Group != nil || cmd.Prelude != nil || cmd.Subshell != nil || len(cmd.Alternatives) > 0 || len(cmd.Invalidates) > 0 {
		w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving further source commands.")
		return false
	}

	if hookHasSourceCommand(cmd, entrypoint) {
		w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", "Shell command modifiers prevent resolving this source command.")
		name, _ := cmd.Words[0].Literal()
		state.sourced = state.sourced || name == "source" || name == "."
	}

	state.cwd, state.conditional = "", false

	return true
}

func (w *hookSourceWalk) skipStatement(e *entry, view source.View, stmt *shellsyntax.Statement, entrypoint bool, state *hookSourceState) {
	for _, cmd := range stmt.Commands {
		state.rootUnknown = state.rootUnknown || w.rootChanged(cmd)
		if hookHasSourceCommand(cmd, entrypoint) {
			w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving this source command.")
			name, _ := cmd.Words[0].Literal()
			state.sourced = state.sourced || name == "source" || name == "."
		}
	}

	state.cwd, state.conditional = "", false
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
	case "export", "unset", "read", "mapfile", "readarray", "getopts", "let":
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

func hookSourceKeepsDirectory(name string, words []*shellsyntax.Word) bool {
	switch name {
	case ":", "true", "false", "echo", "printf":
		for _, word := range words[1:] {
			if _, ok := word.Literal(); !ok {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func hookSourceShadowed(tree *shellsyntax.File) bool {
	for _, stmt := range tree.Statements {
		for _, cmd := range stmt.Commands {
			if cmd.FunctionName == "source" || cmd.FunctionName == "." || cmd.FunctionName == "cd" || cmd.FunctionName == "false" || hookSourceInterpreter(cmd.FunctionName) {
				return true
			}
		}
	}

	return false
}

func (w *hookSourceWalk) command(e *entry, view source.View, cmd *shellsyntax.Command, name string, state hookSourceState, chain []report.SourceRef) {
	span, err := view.Original(cmd.Span)
	if err != nil {
		return
	}

	at := ref(e, span)
	if at == nil {
		return
	}

	operand := hookSourceOperand(cmd.Words, name)
	if operand == nil {
		if name == "source" || name == "." {
			w.gap(*at, "hook_source_command_unverified", "Shell source options or operands could not be determined statically.")
		}

		return
	}

	value, known := symbolicWord(operand, w.plugin.host)
	if !known {
		if name != "source" && name != "." && !hookSourceInterpreter(name) {
			return
		}

		w.gap(*at, "hook_source_dynamic", "A shell source path could not be determined statically.")

		return
	}

	if strings.HasPrefix(value, "\x00scout-plugin-root") && (state.rootUnknown || !hookRootQuoted(operand)) {
		w.gap(*at, "hook_source_dynamic", "A shell source path could not be determined statically.")
		return
	}

	rel, reason := w.resolveFile(value, state.cwd)
	if reason != "" {
		w.gap(*at, reason, "A shell source path could not be resolved within the captured plugin.")
		return
	}

	steps := make([]report.SourceRef, 0, len(chain)+1)
	steps = append(steps, chain...)
	steps = append(steps, *at)
	direct := name != "source" && name != "." && !hookSourceInterpreter(name)
	w.follow(rel, state, steps, direct)
}

func hookRootQuoted(word *shellsyntax.Word) bool {
	for _, part := range word.Parts {
		if part.Kind == "parameter" && !part.Quoted {
			return false
		}
	}

	return true
}

func hookSourceOperand(words []*shellsyntax.Word, name string) *shellsyntax.Word {
	if name != "source" && name != "." && !hookSourceInterpreter(name) {
		return words[0]
	}

	args := words[1:]
	if len(args) > 0 {
		if flag, _ := args[0].Literal(); flag == "--" {
			args = args[1:]
		} else if strings.HasPrefix(flag, "-") {
			return nil
		}
	}

	if len(args) == 0 {
		return nil
	}

	return args[0]
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

func (w *hookSourceWalk) directory(args []*shellsyntax.Word, state hookSourceState, successRequired bool) string {
	if len(args) != 1 || !successRequired || !hookRootQuoted(args[0]) {
		return ""
	}

	value, known := symbolicWord(args[0], w.plugin.host)
	if !known || state.rootUnknown && strings.HasPrefix(value, "\x00scout-plugin-root") {
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

	return w.resolve(value, cwd)
}

func (w *hookSourceWalk) resolve(value, cwd string) (string, string) {
	var candidate string

	switch {
	case value == "\x00scout-plugin-root":
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

func (w *hookSourceWalk) follow(rel string, state hookSourceState, chain []report.SourceRef, direct bool) {
	p := w.plugin

	last := chain[len(chain)-1]
	if len(chain) > maxHookSourceDepth || len(p.b.hookSourcePaths) >= p.b.r.Limits.References {
		w.gap(last, "hook_source_limit", "The shell source path budget was exhausted.")
		return
	}

	e := p.entry(rel)
	if e == nil || e.doc == nil {
		w.gap(last, "hook_source_not_captured", "A referenced shell file was not captured in the plugin.")
		return
	}

	if w.active[e.meta.Path] {
		w.gap(last, "hook_source_cycle", "A cycle was found in local shell source references.")
		return
	}

	if direct && !hasShellShebang(e.doc.Artifact().Content()) {
		w.gap(last, "hook_source_interpreter_unverified", "The interpreter of a directly launched file could not be verified as shell.")
		return
	}

	w.origins[e.meta.Path] = e.doc

	*e.doc = e.doc.WithHookSourceShell(p.b.ctx)

	unit, ok := hookSourceUnit(e.doc.Units())
	if !ok {
		w.gap(last, "hook_source_unparsed", "A referenced shell file could not be parsed.")
		return
	}

	tree, _ := unit.Tree.(parse.ShellTree)
	if tree.ExecutionError != nil && (tree.DeclarationError != nil || tree.Declarations == nil) {
		w.gap(last, "hook_source_unparsed", "A referenced shell file could not be parsed completely.")
	}

	p.b.hookSourcePaths = append(p.b.hookSourcePaths, HookSourcePath{Target: e.meta.Path, Event: w.event, Steps: chain})
	w.active[e.meta.Path] = true
	state.conditional = false
	state.skipAnd = false
	w.commands(e, unit.View, hookSourceTree(tree), state, chain, false)
	delete(w.active, e.meta.Path)
}

func hasShellShebang(text string) bool {
	hint, ok := language.Shebang(text)
	return ok && hint.Language == language.Shell
}

func hookSourceTree(tree parse.ShellTree) *shellsyntax.File {
	if tree.ExecutionError != nil && tree.DeclarationError == nil && tree.Declarations != nil {
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
