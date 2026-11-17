package harness

import (
	"path"
	"slices"
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
	maxHookSourceValue = 4096
	maxHookArguments   = 32
	pluginRootValue    = "\x00scout-plugin-root"
	pluginRootMarker   = pluginRootValue + "/"
	bashExecutable     = "\x00scout-bash"
)

// HookSources holds bounded static paths and their unresolved edges.
type HookSources struct {
	Paths       []HookSourcePath
	Diagnostics []report.Diagnostic
	Commands    []HookSourceCommand
}

type HookSourceCommand struct {
	report.SourceRef
	FileArgv bool // traced file invocation with no outer shell text
}

type HookSourcePath struct {
	Target   string
	Event    string
	Language string
	Steps    []report.SourceRef
	Scope    source.Span
	Exclude  []source.Span
}

type hookSourceWalk struct {
	plugin            *plugin
	config            *entry
	event             string
	active            map[string]bool
	activeFunctions   map[hookFunctionKey]bool
	origins           map[string]*document.File
	bashFallback      bool
	rootLaunch        *shellsyntax.Command
	boundedArrayDepth int
	tracingLoop       bool
}

func (p *plugin) inspectHookSources(e *entry, hook *jsonconfig.Node, event string) {
	if p.host == report.HostGeminiCLI {
		if !hookevent.Gemini(event) {
			p.issue("plugin_hook_event_unverified", e.meta.Path, report.OutcomePartial)
			return
		}
	} else if !hookevent.Known(event) {
		return
	}

	mode, _ := hook.Get("shell").Text()
	if hook.Get("shell") != nil && mode != "bash" && mode != "sh" {
		return
	}

	command := hook.Get("command")
	commandText, _ := command.Text()

	initial := ref(e, command.Span)
	if initial == nil {
		return
	}

	if len(p.b.hookSourceCommands) >= p.b.r.Limits.References {
		p.issue("hook_source_command_limit", e.meta.Path, report.OutcomePartial)
		return
	}

	walk := hookSourceWalk{
		plugin: p, config: e, event: event, active: map[string]bool{}, origins: map[string]*document.File{e.meta.Path: e.doc},
		bashFallback: mode == "bash" && hook.Get("args") == nil,
	}

	args := hook.Get("args")

	if p.host == report.HostGeminiCLI && strings.Contains(commandText, geminiExtensionPath) {
		p.b.hookSourceCommands = append(p.b.hookSourceCommands, HookSourceCommand{SourceRef: *initial})
		walk.geminiLaunch(commandText, args, *initial)

		return
	}

	fileArgv := args != nil && walk.argv(e, command, args, *initial)

	p.b.hookSourceCommands = append(p.b.hookSourceCommands, HookSourceCommand{SourceRef: *initial, FileArgv: fileArgv})

	for _, unit := range e.doc.Units() {
		if unit.Origin != document.OriginHookShell || unit.Span.Start < hook.Span.Start || unit.Span.End > hook.Span.End {
			continue
		}

		if tree, ok := unit.Tree.(parse.ShellTree); ok {
			shell := hookSourceTree(tree)
			walk.rootLaunch = nil

			if p.assumesShellHookRoot() && args == nil && unit.View.Text() == commandText &&
				shell != nil && !shell.OmittedExecution {
				// The supplied root is made up of shell inert characters.
				// Only use it in a single entry command, before shell state can
				// change. Captured files still need their own expansion proof.
				if launch, simple := simpleShellCommand(shell); simple {
					walk.rootLaunch = launch
				}
			}

			state := hookSourceState{}
			if args == nil && unit.View.Text() == commandText {
				walk.seedHostEnvironment(&state)
			}

			walk.commands(e, unit.View, shell, state, nil, true)
		}
	}
}

func (p *plugin) assumesShellHookRoot() bool {
	host := p.b.shellHookRoot.Host

	return host != "" && (host == p.host || host == report.HostAuto &&
		(pluginRootParameters[p.host] != "" || p.host == report.HostGeminiCLI))
}

func (p *plugin) seedHookLocale(state *hookSourceState) {
	if locale := p.b.shellHookRoot.LCAll; locale != "" && p.assumesShellHookRoot() {
		state.bindValue("LC_ALL", locale, true)
	}
}

func (w *hookSourceWalk) argv(e *entry, command, args *jsonconfig.Node, initial report.SourceRef) bool {
	if args.Kind != jsonconfig.KindArray {
		return false
	}

	for _, arg := range args.Elements {
		value, text := arg.Text()
		if !text || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}

	name, _ := command.Text()
	direct := !hookSourceInterpreter(name)
	operand, span := name, command.Span
	firstArgument := 0

	if !direct {
		index := shellsyntax.FileArgumentIndex(len(args.Elements), func(i int) (string, bool) { return args.Elements[i].Text() })
		if index < 0 {
			return false
		}

		arg := args.Elements[index]

		operand, _ = arg.Text()
		span = arg.Span
		firstArgument = index + 1
	}

	suffix, rooted := literalRootSuffix(operand, w.plugin.host, true)
	if !rooted {
		return false
	}

	span.Start = min(span.Start, initial.ByteStart)

	span.End = max(span.End, initial.ByteEnd)
	if at := ref(e, span); at != nil {
		initial = *at
	}

	value := pluginRootMarker + suffix
	rel, reason := w.resolveFile(value, "")

	if reason != "" {
		w.gap(initial, reason, "A shell source path could not be resolved within the captured plugin.")
		return false
	}

	steps := []report.SourceRef{initial}
	state := hookSourceState{
		scriptPath: value, sourcePath: value, explicitBash: w.knownLaunchBash(rel, steps, name, direct),
		positional: w.fileArgv(args.Elements[firstArgument:]),
	}
	w.seedHostEnvironment(&state)
	w.plugin.seedHookLocale(&state)
	_, checked := w.follow(rel, state, steps, direct)

	return checked
}

func (w *hookSourceWalk) fileArgv(words []*jsonconfig.Node) hookSourceArguments {
	args := make([]hookSourceArgument, 0, min(len(words), maxHookArguments))
	for _, word := range words {
		if len(args) == maxHookArguments {
			return hookSourceArguments{values: args}
		}

		value, _ := word.Text()
		if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") && rootParameter(w.plugin.host, value[2:len(value)-1], true) {
			args = append(args, hookSourceArgument{value: pluginRootValue, known: true})
		} else {
			args = append(args, hookSourceArgument{value: value, known: !strings.ContainsRune(value, '$')})
		}
	}

	return hookSourceArguments{values: args, exact: true}
}

type hookSourceState struct {
	vars          map[string]string
	kinds         map[string]hookVariableFact
	locals        map[string]hookSourceLocal
	readonly      map[string]bool // some reachable path locked this variable
	returns       *hookSourceState
	functions     map[string][]hookSourceFunction // present with no candidates means the definition is unknown
	cwd           string
	positional    hookSourceArguments
	scriptPath    string
	sourcePath    string
	explicitBash  bool
	canReturn     bool
	lookupUnknown bool
	rootUnknown   bool
	noglob        bool
	trapCommands  hookTrapCommands
	returned      bool
	exited        bool
	traceBlocked  bool
}

func (w *hookSourceWalk) commands(e *entry, view source.View, tree *shellsyntax.File, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	if tree == nil || state.traceBlocked {
		return state
	}

	for i := 0; i < len(tree.Statements); {
		stmts := tree.Statements[i:]

		if !w.plugin.b.step() {
			return state.blockTrace()
		}

		end := hookAndOrEnd(stmts)
		if end != 0 && stmts[end].Next == "&" {
			w.traceBackgroundList(e, view, stmts[:end+1], state, chain, entrypoint)
		} else if end != 0 {
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
	s.cwd, s.vars, s.positional, s.scriptPath = "", nil, hookSourceArguments{}, ""
	s.sourcePath = ""
	s.kinds = nil
	s.locals = nil
	s.readonly = nil
	s.explicitBash = false
	s.noglob = false
	s.functions = nil
	s.rootUnknown, s.lookupUnknown = true, true

	return s
}

func (s hookSourceState) blockTrace() hookSourceState {
	s = s.opaque()
	s.traceBlocked = true

	return s
}

func (w *hookSourceWalk) value(word *shellsyntax.Word, state hookSourceState, assignment bool) (string, bool) {
	if w.knownPluginDefault(word, state) {
		return pluginRootValue, true
	}

	if value, known := hookTrimmedPrefix(word, state, assignment); known {
		return value, true
	}

	if word == nil || word.Expands {
		return "", false
	}

	var b strings.Builder

	for _, part := range word.Parts {
		switch part.Kind {
		case "literal":
			b.WriteString(part.Text)
		case "parameter_replace_all":
			value, ok := w.replaceAll(part, state)
			if !ok {
				return "", false
			}

			b.WriteString(value)
		case "substitution":
			value, ok := w.hookPathSubstitution(part, state, assignment)
			if !ok {
				return "", false
			}

			b.WriteString(value)
		case "parameter", "parameter_default_dot", "parameter_default_empty", "parameter_script_dir", "parameter_bash_source":
			if (!assignment && !part.Quoted) || part.Text == "@" || part.Text == "*" {
				return "", false
			}

			if rootParameter(w.plugin.host, part.Text, true) && !state.rootUnknown {
				b.WriteString(pluginRootValue)
				continue
			}

			value, ok := state.expandParameter(part)
			if !ok {
				return "", false
			}

			b.WriteString(value)
		default:
			return "", false
		}

		if b.Len() > maxHookSourceValue {
			return "", false
		}
	}

	return b.String(), true
}

func (w *hookSourceWalk) bind(cmd *shellsyntax.Command, state *hookSourceState) {
	for _, assignment := range cmd.Assignments {
		if rootParameter(w.plugin.host, assignment.Name, true) {
			state.rootUnknown = true
			delete(state.vars, assignment.Name)
			delete(state.kinds, assignment.Name)

			continue
		}

		value, known := w.value(assignment.Value, *state, true)
		if hookAssignmentAffectsLookup(assignment.Name) && !hookSystemPathAssignment(assignment.Name, value, known) &&
			!(assignment.Name == "IFS" && hookLiteralAssignmentWord(assignment.Value)) {
			*state = state.opaque()
			continue
		}

		kind := w.assignmentKind(assignment.Value, *state)
		state.bindValue(assignment.Name, value, known)

		if kind != 0 && hookLocalVariable(assignment.Name, pluginRootParameters[w.plugin.host]) {
			state.markAssignmentKind(assignment, kind)
		}
	}
}

func hookSystemPathAssignment(name, value string, known bool) bool {
	if name != "PATH" || !known || value == "" {
		return false
	}

	for dir := range strings.SplitSeq(value, ":") {
		if dir != "/bin" && dir != "/usr/bin" {
			return false
		}
	}

	return true
}

func hookAssignmentAffectsLookup(name string) bool {
	switch name {
	case "PATH", "CDPATH", "IFS", "BASH_ENV", "ENV":
		return true
	default:
		return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
	}
}

func (s *hookSourceState) bindValue(name, value string, known bool) {
	delete(s.kinds, name)

	if _, exists := s.vars[name]; s.readonly[name] || !known || !exists && len(s.vars) >= 128 {
		delete(s.vars, name)
		return
	}

	if s.vars == nil {
		s.vars = make(map[string]string)
	}

	s.vars[name] = value
}

func (w *hookSourceWalk) statement(e *entry, view source.View, stmt *shellsyntax.Statement, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	if stmt.Negated {
		// An and/or list handles the inverted status separately. A
		// standalone negation still executes its operand and its effects.
		operand := *stmt
		operand.Negated = false
		stmt = &operand
	}

	if len(stmt.Commands) == 1 && hookReadOnlyBracket(stmt.Commands[0], *state) {
		w.traceSubstitutions(e, view, stmt.Commands[0], *state, chain)
		return true
	}

	if w.hookReadOnlyPredicate(stmt, state) {
		w.traceSubstitutions(e, view, stmt.Commands[0], *state, chain)
		return true
	}

	if hookReadOnlyPipeline(stmt, *state) {
		for _, cmd := range stmt.Commands {
			w.traceSubstitutions(e, view, cmd, *state, chain)
		}

		return true
	}

	if w.traceExplicitSubshell(e, view, stmt, *state, chain) {
		return true
	}

	if w.traceForkedStatement(e, view, stmt, state, chain, entrypoint) {
		return true
	}

	if len(stmt.Commands) != 1 {
		w.skipStatement(e, view, stmt, entrypoint, state)

		return true
	}

	return w.command(e, view, stmt, chain, entrypoint, state)
}

func (w *hookSourceWalk) traceExplicitSubshell(e *entry, view source.View, stmt *shellsyntax.Statement, state hookSourceState, chain []report.SourceRef) bool {
	if len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if cmd.Subshell == nil || len(cmd.Words) != 0 || len(cmd.Assignments) != 0 ||
		hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	for _, redirect := range cmd.Redirects {
		if !hookDiscardedOutput(redirect) {
			return false
		}
	}

	w.traceSubstitutions(e, view, cmd, state, chain)
	w.commands(e, view, cmd.Subshell, state.child(), chain, true)

	return true
}

func (w *hookSourceWalk) command(e *entry, view source.View, stmt *shellsyntax.Statement, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	cmd := stmt.Commands[0]
	if len(cmd.NumericTest) != 0 {
		return w.unverifiedCommand(e, view, cmd, state, "Shell arithmetic operands could not be verified.")
	}

	if len(cmd.IndirectTest) != 0 {
		return w.unverifiedCommand(e, view, cmd, state, "An indirect shell test operand has no verified scalar referent.")
	}

	if cmd.ArithmeticUpdate != "" {
		return w.updateArithmeticBinding(e, view, cmd, state)
	}

	if w.applyLoop(e, view, cmd, state, chain) {
		return !state.exited && !state.returned && !state.traceBlocked
	}

	if hookPlainCompound(cmd) && cmd.Case != nil {
		*state = w.caseStatement(e, view, cmd, *state, chain, entrypoint)
		return !state.returned && !state.exited && !state.traceBlocked
	}

	if (cmd.Group != nil || cmd.ExclusiveBranches) && hookPlainCompound(cmd) {
		if cmd.Group != nil {
			*state = w.commands(e, view, cmd.Group, *state, chain, entrypoint)
		} else {
			*state = w.conditional(e, view, cmd, *state, chain, entrypoint)
		}

		return !state.returned && !state.exited && !state.traceBlocked
	}

	if cmd.FunctionName != "" && cmd.FunctionBody != nil && len(cmd.Redirects) == 0 {
		return w.bindFunction(e, view, cmd, chain, state)
	}

	if w.hasUnverifiedExpansion(cmd, *state) {
		return w.unverifiedCommand(e, view, cmd, state, "Shell expansions can change bindings used by further source commands.")
	}

	w.traceSubstitutions(e, view, cmd, *state, chain)

	return w.applySimpleCommand(e, view, cmd, chain, entrypoint, state)
}

func (w *hookSourceWalk) applySimpleCommand(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	if w.traceHostEnvironmentWrite(e, view, cmd, *state) {
		return true
	}

	if replaces, traced := w.traceNodeLaunch(e, view, cmd, *state, chain); traced {
		state.exited = replaces
		return !replaces
	}

	if w.bindAssignment(cmd, state) {
		return true
	}

	if hookBareExport(cmd, *state) || hookLiteralNoop(cmd, *state) || hookRedirectedIO(cmd, *state) || w.forgetReadDestinations(cmd, state) {
		return true
	}

	if len(cmd.Words) == 0 || len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 {
		return w.modifiedStatement(e, view, cmd, chain, entrypoint, state)
	}

	return w.simpleStatement(e, view, cmd, chain, entrypoint, state)
}

func (w *hookSourceWalk) bindAssignment(cmd *shellsyntax.Command, state *hookSourceState) bool {
	if len(cmd.Words) != 0 || len(cmd.Assignments) == 0 {
		return false
	}

	ordinary := hookSourceAssignment(cmd, *state)
	if len(cmd.Redirects) == 0 {
		if ordinary {
			w.bind(cmd, state)
			return true
		}

		return w.bindShellDeclaration(cmd, state)
	}

	if state.lookupUnknown || !ordinary || slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool {
		return !hookDiscardedOutput(r)
	}) {
		return false
	}

	// A failed redirect can leave the previous assignment intact.
	before := state.clone()
	w.bind(cmd, state)
	*state = state.join(before)

	return true
}

func (w *hookSourceWalk) updateArithmeticBinding(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState) bool {
	counter := cmd.ArithmeticUpdate
	if !state.explicitBash || len(cmd.Redirects) != 0 || !w.decimalBinding(counter, *state) {
		return w.unverifiedCommand(e, view, cmd, state, "The shell arithmetic update may evaluate an unverified value.")
	}

	state.bindValue(counter, "", false)
	state.markDecimal(counter)

	return true
}

func (w *hookSourceWalk) bindFunction(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, state *hookSourceState) bool {
	if state.trapCommands&hookTrapCommand(cmd.FunctionName) != 0 {
		return w.unverifiedCommand(e, view, cmd, state, "A function definition can change a registered shell trap.")
	}

	w.defineFunction(e, view, cmd, chain, state)

	return true
}

func hookPlainCompound(cmd *shellsyntax.Command) bool {
	return len(cmd.Words) == 0 && len(cmd.Redirects) == 0 && len(cmd.Assignments) == 0 && len(cmd.Invalidates) == 0
}

func hookBareExport(cmd *shellsyntax.Command, state hookSourceState) bool {
	return cmd.Declaration == "export" && len(cmd.DeclarationArgs) == 0 && len(cmd.Assignments) == 0 &&
		len(cmd.Words) == 0 && len(cmd.Redirects) == 0 && len(cmd.Invalidates) == 0 &&
		!state.lookupUnknown && !state.hasFunction("export")
}

func hookRedirectedIO(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || len(cmd.Words) == 0 || len(cmd.Redirects) == 0 || len(cmd.Assignments) != 0 {
		return false
	}

	// A single command with discarded output has the same binding proof
	// as a pipeline stage. A redirected grep predicate preserves bindings.
	if hookPipelineStage(cmd, state) {
		return true
	}

	name, _ := cmd.Words[0].Literal()
	if state.hasFunction(name) {
		return false
	}

	if name == "cat" && len(cmd.Words) == 1 {
		return hookCatHereDocument(cmd.Redirects)
	}

	if name != "echo" && (name != "printf" || hookPrintfMayWrite(cmd.Words[1:])) {
		return false
	}

	for _, redirect := range cmd.Redirects {
		switch redirect.Op {
		case ">", ">>", ">&":
		default:
			return false
		}
	}

	return true
}

func hookCatHereDocument(redirects []*shellsyntax.Redirect) bool {
	input := false

	for _, redirect := range redirects {
		if (redirect.Op == "<<" || redirect.Op == "<<-") && (redirect.FD == "" || redirect.FD == "0") && redirect.BodyVerified {
			if input {
				return false
			}

			input = true
		} else if !hookDiscardedOutput(redirect) {
			return false
		}
	}

	return input
}

func (s *hookSourceState) applyWhileAssignments(names []string, root string) bool {
	if len(names) == 0 || s.lookupUnknown {
		return false
	}

	for _, name := range names {
		if !hookOrdinaryVariable(name, root) {
			return false
		}
	}

	for _, name := range names {
		delete(s.vars, name)
		delete(s.kinds, name)
	}

	return true
}

func hookOrdinaryVariable(name, root string) bool {
	if root == pluginRootParameters[report.HostCodex] && name == codexHookRootAlias {
		return false
	}

	switch name {
	case root, "PATH", "CDPATH", "IFS", "SHELLOPTS", "ENV", "GLOBIGNORE", "FUNCNEST", "POSIXLY_CORRECT", "OPTIND":
		return false
	default:
		return !strings.HasPrefix(name, "BASH") && !strings.HasPrefix(name, "LD_") && !strings.HasPrefix(name, "DYLD_")
	}
}

func hookLiteralNoop(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) != 1 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 1 || state.lookupUnknown || state.hasFunction(":") {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	redirect := cmd.Redirects[0]

	return name == ":" && redirect.Op == "<<" && (redirect.FD == "" || redirect.FD == "0") && redirect.QuotedDelimiter && redirect.BodyVerified
}

func (w *hookSourceWalk) hookReadOnlyPredicate(stmt *shellsyntax.Statement, state *hookSourceState) bool {
	if len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if w.hookSafeTest(cmd, *state) {
		if cmd.RegexTest && !stmt.Background && stmt.Next != "&" {
			delete(state.vars, "BASH_REMATCH")
			delete(state.kinds, "BASH_REMATCH")
		}

		return true
	}

	return hookGitProbe(cmd, *state) || hookCommandLookupProbe(cmd, *state)
}

func hookCommandLookupProbe(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("command") {
		return false
	}

	if len(cmd.Words) != 3 || len(cmd.Assignments) != 0 || hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	for _, redirect := range cmd.Redirects {
		if !hookDiscardedOutput(redirect) {
			return false
		}
	}

	name, _ := cmd.Words[0].Literal()
	option, _ := cmd.Words[1].Literal()
	operand := hookTestOperand(cmd.Words[2])

	return name == "command" && (option == "-v" || option == "-V") && operand
}

func hookDiscardedOutput(redirect *shellsyntax.Redirect) bool {
	target, known := redirect.Target.Literal()
	if !known {
		return false
	}

	if redirect.Op == ">&" {
		return redirect.FD == "2" && target == "1" || (redirect.FD == "" || redirect.FD == "1") && target == "2"
	}

	return target == "/dev/null" && (redirect.Op == ">" || redirect.Op == "&>") &&
		(redirect.FD == "" || redirect.FD == "1" || redirect.FD == "2")
}

func hookSourceAssignment(cmd *shellsyntax.Command, state hookSourceState) bool {
	return cmd.Declaration == "" || cmd.Declaration == "export" && len(cmd.DeclarationArgs) == 0 && !state.hasFunction("export")
}

func (w *hookSourceWalk) simpleStatement(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	name, literal := cmd.Words[0].Literal()
	if continued, handled := w.dispatchKnownCommand(e, view, cmd, chain, state, name, literal); handled {
		return continued
	}

	if name == "exec" {
		if w.execShell(e, view, cmd, *state, chain) {
			state.exited = true
			return false
		}

		return w.unverifiedExec(e, view, cmd, state)
	}

	if !literal && !w.directLaunch(e, view, cmd, state, chain) {
		return w.unverifiedCommand(e, view, cmd, state, "An expanded shell command name prevents resolving further source commands.")
	}

	if hookLiteralLocalLaunch(name, literal, *state) {
		return w.linkCommand(e, view, cmd, name, state, chain)
	}

	if hookHasSourceCommand(cmd, entrypoint) && w.runtimeSourceOperand(cmd, name, *state) {
		w.commandGap(e, view, cmd.Span, "hook_source_dynamic", "Shell expansions prevent resolving this source command.")

		*state = state.blockTrace()

		return false
	}

	if w.rootChanged(cmd) {
		state.rootUnknown = true
		state.vars = nil
		state.kinds = nil
	}

	switch name {
	case "break", "continue":
		if w.boundedArrayDepth > 0 || w.tracingLoop {
			return w.unverifiedCommand(e, view, cmd, state, "A control transfer in the shell loop is unverified.")
		}
	case "exit", "return":
		return w.exitOrReturn(e, view, cmd, state, name)
	case "shift":
		state.shift(cmd)
		return true
	case "set":
		if w.replaceArguments(cmd.Words[1:], state) || state.applyShellOptions(cmd.Words[1:]) {
			return true
		}
	case "shopt":
		if hookKnownGlobOptions(cmd.Words[1:], *state) {
			return true
		}
	case "trap":
		if w.applyHookTrap(cmd.Words[1:], state) {
			return true
		}
	case "unset":
		if state.unsetScalars(cmd.Words[1:], pluginRootParameters[w.plugin.host]) {
			return true
		}
	case "cd":
		if state.lookupUnknown {
			state.cwd = ""
			return true
		}

		state.changeDirectory("")

		return true
	}

	if w.hasOpaqueEffects(name, cmd.Words[1:], *state) {
		return w.unverifiedCommand(e, view, cmd, state, "Shell command effects prevent resolving further source commands.")
	}

	if literal && hookHasSourceCommand(cmd, entrypoint) {
		return w.linkCommand(e, view, cmd, name, state, chain)
	}

	if !hookSourceKeepsDirectory(name) {
		state.cwd = ""
	}

	return true
}

func (w *hookSourceWalk) unverifiedExec(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState) bool {
	if !state.lookupUnknown && len(cmd.Words) > 2 {
		if value, known := w.value(cmd.Words[2], *state, false); known {
			rel, reason := w.resolveFile(value, state.cwd)
			if candidate := w.plugin.entry(rel); reason == "" && candidate != nil && candidate.doc != nil {
				w.commandGap(e, view, cmd.Words[1].Span, "hook_source_exec_runtime_unverified",
					"Exec has a captured file argument, but its executable and dispatch are unverified.")

				*state = state.blockTrace()

				return false
			}
		}
	}

	return w.unverifiedCommand(e, view, cmd, state, "Shell command effects prevent resolving further source commands.")
}

func (w *hookSourceWalk) dispatchKnownCommand(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, state *hookSourceState, name string, literal bool) (bool, bool) {
	if state.lookupUnknown {
		return false, false
	}

	if literal {
		if state.hasFunction(name) {
			return w.callFunctions(e, view, cmd, name, chain, state), true
		}

		return false, false
	}

	value, known := w.value(cmd.Words[0], *state, false)
	if !known {
		return false, false
	}

	switch {
	case state.hasFunction(value):
		return w.callFunctions(e, view, cmd, value, chain, state), true
	case hookSourceInterpreter(value) && len(hookSourceOperands(cmd.Words, value)) > 0:
		return w.linkCommand(e, view, cmd, value, state, chain), true
	default:
		return false, false
	}
}

func (w *hookSourceWalk) exitOrReturn(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, name string) bool {
	args := cmd.Words[1:]

	status, maySplit := hookPreviousStatus(args)
	if state.lookupUnknown || name == "return" && !state.canReturn || !status && !w.knownExitStatus(args, *state) {
		return w.unverifiedCommand(e, view, cmd, state, "An unverified shell exit or return prevents resolving further source commands.")
	}

	if maySplit {
		// An inherited IFS may split an unquoted status into multiple operands.
		// Keep the path where Bash rejects extra operands and resumes.
		stopped := state.clone()
		stopped.returned, stopped.exited = name == "return", name == "exit"
		*state = state.join(stopped)

		return true
	}

	state.returned = name == "return"
	state.exited = name == "exit"

	return false
}

func hookKnownGlobOptions(args []*shellsyntax.Word, state hookSourceState) bool {
	if !state.explicitBash || state.lookupUnknown || len(args) < 2 {
		return false
	}

	flag, _ := args[0].Literal()
	if flag != "-s" && flag != "-u" {
		return false
	}

	// Unrestricted lists already allow any number of iterations. The
	// captured-file walker visits dotfiles and guards launches with -f, so
	// these two options cannot add a target outside its candidate set.
	return !slices.ContainsFunc(args[1:], func(word *shellsyntax.Word) bool {
		name, _ := word.Literal()
		return name != "dotglob" && name != "nullglob"
	})
}

func hookPreviousStatus(args []*shellsyntax.Word) (status, maySplit bool) {
	if len(args) != 1 || args[0].Writes || len(args[0].Parts) != 1 {
		return false, false
	}

	part := args[0].Parts[0]
	if part.Kind != "parameter" || part.Text != "?" || !part.PlainParameter {
		return false, false
	}

	return true, !part.Quoted
}

func (w *hookSourceWalk) hasOpaqueEffects(name string, args []*shellsyntax.Word, state hookSourceState) bool {
	switch name {
	case "eval":
		return !w.isLiteralPrint(args, state)
	default:
		return hookSourceOpaqueCommand(name)
	}
}

func (w *hookSourceWalk) directLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	if state.lookupUnknown {
		return false
	}

	value, known := w.value(cmd.Words[0], *state, false)
	if (!known || !hookLocalLaunchPath(value, state.cwd)) && !w.unquotedPluginPath(cmd.Words[0], *state) {
		return false
	}

	w.resolveCommand(e, view, cmd, "", *state, chain)

	return true
}

func hookLiteralLocalLaunch(name string, literal bool, state hookSourceState) bool {
	return literal && strings.HasPrefix(name, "./") && state.cwd != "" && !state.lookupUnknown
}

func hookLocalLaunchPath(value, cwd string) bool {
	return strings.HasPrefix(value, pluginRootMarker) || cwd != "" && strings.HasPrefix(value, "./")
}

func hookTrimmedPrefix(word *shellsyntax.Word, state hookSourceState, assignment bool) (string, bool) {
	if word == nil || word.Writes || len(word.Parts) != 1 {
		return "", false
	}

	part := word.Parts[0]
	if part.TrimPrefix == "" || !assignment && !part.Quoted {
		return "", false
	}

	value, known := state.parameter(part.Text)
	if !known || strings.IndexByte(value, 0) >= 0 {
		return "", false
	}

	return strings.TrimPrefix(value, part.TrimPrefix), true
}

func (w *hookSourceWalk) knownPluginDefault(word *shellsyntax.Word, state hookSourceState) bool {
	if word == nil || word.Writes || len(word.Parts) != 1 || state.rootUnknown {
		return false
	}

	part := word.Parts[0]

	return rootParameter(w.plugin.host, part.Text, true) && part.Quoted && part.Kind == "parameter_value" && part.DefaultIfUnset
}

func (w *hookSourceWalk) unverifiedCommand(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, message string) bool {
	w.commandGap(e, view, cmd.Span, "hook_source_command_unverified", message)

	*state = state.blockTrace()

	return false
}

func (w *hookSourceWalk) modifiedStatement(e *entry, view source.View, cmd *shellsyntax.Command, chain []report.SourceRef, entrypoint bool, state *hookSourceState) bool {
	if w.traceRedirectedGroup(e, view, cmd, state, chain, entrypoint) {
		return !state.exited && !state.returned && !state.traceBlocked
	}

	if w.traceTemporaryEnvLaunch(e, view, cmd, *state, chain) {
		return true
	}

	if w.hookDiscardRedirectedLaunch(cmd, *state, entrypoint) {
		before := state.clone()
		w.simpleStatement(e, view, cmd, chain, entrypoint, state)
		*state = state.join(before)

		return !state.exited
	}

	if cmd.Group != nil || cmd.Prelude != nil || cmd.Subshell != nil || len(cmd.Alternatives) > 0 || len(cmd.Invalidates) > 0 {
		w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving further source commands.")

		*state = state.blockTrace()

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

	if hookFileOperationWithoutShellWrites(cmd, *state) {
		state.forgetFileBindings()
		return true
	}

	state.cwd, state.vars, state.positional = "", nil, hookSourceArguments{}
	state.kinds = nil

	if len(cmd.Words) > 0 {
		name, literal := cmd.Words[0].Literal()
		if !literal || state.hasFunction(name) || hookSourceOpaqueCommand(name) || name == "exit" || name == "return" {
			return w.unverifiedCommand(e, view, cmd, state, "Shell command modifiers prevent resolving this function or command.")
		}
	}

	return true
}

func (s *hookSourceState) forgetFileBindings() {
	s.cwd = ""

	// Filesystem operations leave the caller's arithmetic values and locale intact.
	for name, value := range s.vars {
		if name != "LC_ALL" && value != hostEnvironmentMarker && value != "false" && value != "true" && !decimalDigits(value) {
			delete(s.vars, name)
		}
	}

	for name, fact := range s.kinds {
		if fact.kind != hookDecimalScalar {
			delete(s.kinds, name)
		}
	}
}

func hookFileOperationWithoutShellWrites(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || len(cmd.Assignments) != 0 || len(cmd.Words) < 2 || len(cmd.Redirects) == 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	if state.hasFunction(name) {
		return false
	}

	if name == "cat" || name == "tail" {
		return hookFileOutputReader(name, cmd)
	}

	if name == "grep" && !hookCommandWritesDuringExpansion(cmd) {
		return !slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool {
			return !hookDiscardedOutput(r) && !hookGroupFileOutput(r) && !hookProcessFileOutput(r, state)
		})
	}

	if len(cmd.Words) != 3 {
		return false
	}

	first, _ := cmd.Words[1].Literal()
	second, _ := cmd.Words[2].Literal()

	switch name {
	case "mv":
		return first != "" && !strings.HasPrefix(first, "-") && second != "" && !strings.HasPrefix(second, "-") &&
			!slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) })
	case "cut":
		return strings.HasPrefix(first, "-d") && len(first) == 3 && decimalDigits(strings.TrimPrefix(second, "-f")) &&
			strings.HasPrefix(second, "-f") && hookKnownFileOutput(cmd.Redirects)
	default:
		return false
	}
}

func hookProcessFileOutput(r *shellsyntax.Redirect, state hookSourceState) bool {
	if !state.explicitBash || r.Op != ">" || (r.FD != "" && r.FD != "1" && r.FD != "2") ||
		r.Target == nil || r.Target.Writes || r.Target.Expands || len(r.Target.Parts) != 2 {
		return false
	}

	prefix, id := r.Target.Parts[0], r.Target.Parts[1]

	// Field splitting may make the redirect fail, but a literal absolute
	// prefix followed by the process ID cannot mutate shell bindings.
	return prefix.Kind == "literal" && strings.HasPrefix(prefix.Text, "/") &&
		id.Kind == "parameter" && id.PlainParameter && id.Text == "$"
}

func hookFileOutputReader(name string, cmd *shellsyntax.Command) bool {
	if !hookKnownFileOutput(cmd.Redirects) {
		return false
	}

	if name == "cat" {
		return len(cmd.Words) == 2 && hookSingleBracketWord(cmd.Words[1])
	}

	if len(cmd.Words) != 4 {
		return false
	}

	option, _ := cmd.Words[1].Literal()

	return option == "-n" && hookSingleBracketWord(cmd.Words[2]) && hookSingleBracketWord(cmd.Words[3])
}

func hookKnownFileOutput(redirects []*shellsyntax.Redirect) bool {
	return !slices.ContainsFunc(redirects, func(r *shellsyntax.Redirect) bool {
		return !hookDiscardedOutput(r) && !hookGroupFileOutput(r)
	})
}

func (w *hookSourceWalk) skipStatement(e *entry, view source.View, stmt *shellsyntax.Statement, entrypoint bool, state *hookSourceState) {
	for _, cmd := range stmt.Commands {
		if hookHasSourceCommand(cmd, entrypoint) || cmd.Group != nil || cmd.Subshell != nil || cmd.Prelude != nil || len(cmd.Alternatives) != 0 {
			w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "Shell control flow prevents resolving this source command.")
		}
	}

	// Background jobs run in a separate scope. An unverified foreground
	// statement may modify the current shell.
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

func (w *hookSourceWalk) runtimeSourceOperand(cmd *shellsyntax.Command, name string, state hookSourceState) bool {
	args := hookSourceOperands(cmd.Words, name)
	if len(args) == 0 || !hookWordHasSubstitution(args[0]) {
		return false
	}

	_, known := w.value(args[0], state, false)

	return !known
}

func hookWordHasSubstitution(word *shellsyntax.Word) bool {
	for range word.Substitutions() {
		return true
	}

	return false
}

func hookHasSourceCommand(cmd *shellsyntax.Command, entrypoint bool) bool {
	if len(cmd.Words) == 0 {
		return false
	}

	name, literal := cmd.Words[0].Literal()

	return name == "source" || name == "." || literal && (entrypoint && hookSourceLaunch(name) ||
		hookSourceInterpreter(name) && len(hookSourceOperands(cmd.Words, name)) > 0)
}

func (w *hookSourceWalk) rootChanged(cmd *shellsyntax.Command) bool {
	for _, assignment := range cmd.Assignments {
		if rootParameter(w.plugin.host, assignment.Name, true) {
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
		return hookPrintfMayWrite(cmd.Words[1:])
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

// A literal empty action ignores SIGPIPE without installing shell code.
func hookIgnoresPipe(args []*shellsyntax.Word) bool {
	if len(args) != 2 {
		return false
	}

	action, literal := args[0].Literal()
	signal, _ := args[1].Literal()

	return literal && action == "" && (signal == "PIPE" || signal == "SIGPIPE")
}

func (w *hookSourceWalk) isLiteralPrint(args []*shellsyntax.Word, state hookSourceState) bool {
	if len(args) != 1 || state.lookupUnknown || state.hasFunction("printf") {
		return false
	}

	text, known := w.value(args[0], state, false)
	if !known || len(text) > 512 {
		return false
	}

	tree, err := shellsyntax.Parse(w.plugin.b.ctx, text)

	cmd, simple := simpleShellCommand(tree)
	if err != nil || !simple || tree.Statements[0].Negated || len(cmd.Words) < 2 {
		return false
	}

	name, literal := cmd.Words[0].Literal()

	format, constant := cmd.Words[1].Literal()
	if !literal || name != "printf" || !constant || format != "%s" && format != `%s\n` {
		return false
	}

	for _, word := range cmd.Words[2:] {
		if _, known := word.Literal(); !known {
			return false
		}
	}

	return true
}

// These options do not change which file a later explicit source names.
func (s *hookSourceState) applyShellOptions(words []*shellsyntax.Word) bool {
	if s.lookupUnknown || len(words) == 0 {
		return false
	}

	noglob := s.noglob

	for i := 0; i < len(words); i++ {
		option, known := words[i].Literal()
		switch {
		case !known:
			return false
		case option == "+f":
			noglob = false
			continue
		case option == "+e":
			continue
		}

		if len(option) < 2 || option[0] != '-' || strings.Trim(option[1:], "eECfuoxv") != "" {
			return false
		}

		noglob = noglob || strings.ContainsRune(option, 'f')
		if strings.ContainsRune(option, 'o') {
			i++
			if i >= len(words) || option[len(option)-1] != 'o' {
				return false
			}

			switch name, _ := words[i].Literal(); name {
			case "noglob":
				noglob = true
			case "pipefail":
			default:
				return false
			}
		}
	}

	s.noglob = noglob

	return true
}

func hookSourceKeepsDirectory(name string) bool {
	switch name {
	case ":", "true", "false", "echo", "printf", "test", "[", "bash", "sh", "dash", "zsh", "ksh", "eval", "trap":
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
		return true
	}

	if !ok {
		*state = state.opaque()
		return true
	}

	next.canReturn = state.canReturn

	next.sourcePath = state.sourcePath
	if args := hookSourceOperands(cmd.Words, name); len(args) > 1 {
		next.positional = hookSourceArguments{}
		if w.hasFixedArgument(args[1:], *state) {
			next.positional = state.positional
		}
	}

	*state = next

	return !state.exited && !state.traceBlocked
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

	isSource := name == "source" || name == "."
	value, known := w.value(operand, state, false)
	conditionalRoot := false

	if !known && w.unquotedPluginPath(operand, state) {
		value, known = w.value(operand, state, true)

		assumedLaunch := e == w.config && w.rootLaunch == cmd && (name == "" || hookSourceInterpreter(name))
		if !assumedLaunch && !w.singleFieldRoot(e, state) {
			conditionalRoot = true

			w.commandGap(e, view, operand.Parts[0].Span, "hook_source_unquoted_root",
				"An unquoted plugin root can split or expand before the shell resolves this file.")
		}
	}

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

	direct := !isSource && !hookSourceInterpreter(name)
	arguments := state.positional

	if !isSource || len(args) > 1 {
		arguments = w.arguments(args[1:], state)
	}

	if !isSource {
		child := hookSourceState{cwd: state.cwd, rootUnknown: state.rootUnknown}
		w.inheritHostEnvironment(&child, state, cmd.Assignments)
		state = child

		state.scriptPath = value
		state.explicitBash = w.knownLaunchBash(rel, steps, name, direct)

		if e == w.config && w.rootLaunch == cmd && len(chain) == 0 {
			w.plugin.seedHookLocale(&state)
		}
	}

	state.canReturn = isSource
	state.sourcePath = value
	state.positional = arguments

	next, checked := w.follow(rel, state, steps, direct)

	return next, checked && !conditionalRoot
}

func (w *hookSourceWalk) unquotedPluginPath(word *shellsyntax.Word, state hookSourceState) bool {
	host := w.plugin.host

	return !state.rootUnknown && !state.lookupUnknown && (word.HasUnquotedPluginRootPath(pluginRootParameters[host]) ||
		host == report.HostCodex && word.HasUnquotedPluginRootPath(codexHookRootAlias))
}

func (w *hookSourceWalk) singleFieldRoot(e *entry, state hookSourceState) bool {
	ifs, known := state.vars["IFS"]
	// The host may substitute placeholders in the command template before
	// the shell starts. These settings only prove shell expansion in files.
	return e != w.config && state.noglob && known && ifs == ""
}

func (w *hookSourceWalk) knownLaunchBash(rel string, steps []report.SourceRef, name string, direct bool) bool {
	if !direct {
		return name == "bash" || name == "/bin/bash" || name == "/usr/bin/bash" || name == bashExecutable
	}

	handler := w.plugin.entry(rel)

	if handler == nil || handler.doc == nil {
		return false
	}

	firstLine, _, _ := strings.Cut(handler.doc.Artifact().Content(), "\n")

	shebang, ok := strings.CutPrefix(firstLine, "#!")
	if ok {
		switch strings.Join(strings.Fields(shebang), " ") {
		case "/bin/bash", "/usr/bin/bash", "/usr/bin/env bash":
			return true
		}
	}

	return w.canCheckBashFallback(handler, steps)
}

func hookSourceOperands(words []*shellsyntax.Word, name string) []*shellsyntax.Word {
	if name != "source" && name != "." && !hookSourceInterpreter(name) {
		return words
	}

	args := words[1:]
	if hookSourceInterpreter(name) {
		index := shellsyntax.FileArgumentIndex(len(args), func(i int) (string, bool) { return args[i].Literal() })
		if index < 0 {
			return nil
		}

		return args[index:]
	}

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

type hookSourceArguments struct {
	values []hookSourceArgument
	exact  bool
}

func (s *hookSourceState) shift(cmd *shellsyntax.Command) {
	if count := hookShiftCount(cmd); !s.lookupUnknown && count > 0 {
		if count <= len(s.positional.values) {
			s.positional.values = s.positional.values[count:]
			return
		}

		if s.positional.exact {
			return
		}
	}

	s.positional = hookSourceArguments{}
}

func (s hookSourceState) expandParameter(part shellsyntax.Part) (string, bool) {
	if part.Kind == "parameter_bash_source" {
		return s.sourcePath, s.sourcePath != "" && s.explicitBash
	}

	value, ok := s.parameter(part.Text)
	if !ok {
		return "", false
	}

	if value == "" && part.Kind == "parameter_default_dot" {
		return ".", true
	}

	if part.Kind == "parameter_script_dir" {
		if !strings.HasPrefix(value, pluginRootMarker) {
			return "", false
		}

		return path.Dir(value), true
	}

	return value, true
}

func (w *hookSourceWalk) replaceAll(part shellsyntax.Part, state hookSourceState) (string, bool) {
	value, known := state.parameter(part.Text)
	if !known || rootParameter(w.plugin.host, part.Text, true) && !state.rootUnknown || strings.IndexByte(value, 0) >= 0 {
		// Symbolic plugin roots and interpreters cannot be substituted as bytes.
		return "", false
	}

	r := part.Replacement
	if len(value)+(len(r.Value)-len(r.Pattern))*strings.Count(value, r.Pattern) > maxHookSourceValue {
		return "", false
	}

	return strings.ReplaceAll(value, r.Pattern, r.Value), true
}

func (s hookSourceState) parameter(name string) (string, bool) {
	if name == "0" {
		return s.scriptPath, s.scriptPath != ""
	}

	if value, ok := s.vars[name]; ok {
		return value, value != hostEnvironmentMarker
	}

	if name == "BASH" && s.explicitBash {
		return bashExecutable, true
	}

	if index, err := strconv.Atoi(name); err == nil && index > 0 && index <= len(s.positional.values) {
		arg := s.positional.values[index-1]
		return arg.value, arg.known
	}

	return "", false
}

func (w *hookSourceWalk) arguments(words []*shellsyntax.Word, state hookSourceState) hookSourceArguments {
	args := make([]hookSourceArgument, 0, min(len(words), maxHookArguments))
	for _, word := range words {
		if len(args) == maxHookArguments {
			return hookSourceArguments{values: args}
		}

		if hookQuotedPositionalSpread(word) {
			remaining := min(len(state.positional.values), maxHookArguments-len(args))
			args = append(args, state.positional.values[:remaining]...)

			if !state.positional.exact || remaining < len(state.positional.values) {
				return hookSourceArguments{values: args}
			}

			continue
		}

		value, known := w.value(word, state, false)
		if !known && !hookFixedArgument(word) {
			// Later arguments can move when this word splits or globs.
			return hookSourceArguments{values: args}
		}

		args = append(args, hookSourceArgument{value, known})
	}

	return hookSourceArguments{values: args, exact: true}
}

func hookQuotedPositionalSpread(word *shellsyntax.Word) bool {
	return len(word.Parts) == 1 && word.Parts[0].Kind == "parameter" && word.Parts[0].Text == "@" && word.Parts[0].Quoted
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
	case "bash", "sh", "dash", "zsh", "ksh", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh", bashExecutable:
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

	if direct && !hasShellShebang(e.doc.Artifact().Content()) && !w.canCheckBashFallback(e, chain) {
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

func (w *hookSourceWalk) canCheckBashFallback(e *entry, chain []report.SourceRef) bool {
	// A captured executable text file with no shebang may be read as a shell
	// script by an explicitly selected Bash. This models only that launch.
	return w.bashFallback && len(chain) == 1 && e.meta.Executable && e.meta.Kind == "text" &&
		!strings.HasPrefix(e.doc.Artifact().Content(), "#!")
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
		b.issue("hook_source_diagnostic_limit", "", "", report.OutcomePartial)
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
