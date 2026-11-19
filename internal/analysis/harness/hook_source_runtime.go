package harness

import (
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) traceRuntimeLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) (replaces, traced bool) {
	if state.lookupUnknown || len(cmd.Words) < 2 || len(cmd.Assignments) != 0 ||
		slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) }) {
		return false, false
	}

	launch := w.runtimeLaunchWords(cmd, state)
	if len(launch.operands) == 0 {
		return false, false
	}

	value, known := w.runtimeFileOperand(e, view, cmd, launch.operands, state)
	if !known || !strings.HasPrefix(value, pluginRootMarker) && (state.cwd == "" || !strings.HasPrefix(value, "./")) {
		return false, false
	}

	ext := path.Ext(value)
	if launch.language == language.JavaScript && ext != ".js" && ext != ".cjs" && ext != ".mjs" ||
		launch.language == language.TypeScript && ext != ".ts" && ext != ".tsx" ||
		launch.language == language.Python && ext != ".py" {
		return false, false
	}

	span, err := view.Original(cmd.Span)
	if err != nil {
		return false, false
	}

	at := ref(e, span)
	if at == nil {
		return false, false
	}

	rel, reason := w.resolveFile(value, state.cwd)
	if reason != "" {
		w.gap(*at, reason, "A hook script path could not be resolved within the captured plugin.")
		return false, false
	}

	target := w.plugin.entry(rel)
	if target == nil || target.doc == nil {
		w.gap(*at, "hook_source_not_captured", "A referenced hook script was not captured in the plugin.")
		return false, false
	}

	b := w.plugin.b
	if len(chain) >= maxHookSourceDepth || len(b.hookSourcePaths) >= b.r.Limits.References {
		w.gap(*at, "hook_source_limit", "The hook source path budget was exhausted.")
		return false, false
	}

	steps := append(slices.Clone(chain), *at)
	w.recordRuntimeScript(target, rel, launch.language, w.nodeHookFirstArgument(launch.operands, state), launch.isolatedPythonArgs, steps)

	return launch.replaces, true
}

func (w *hookSourceWalk) recordRuntimeScript(target *entry, rel, lang string, firstArg hookSourceArgument, isolatedPythonArgs int, steps []report.SourceRef) {
	b := w.plugin.b
	b.hookSourcePaths = append(b.hookSourcePaths, HookSourcePath{Target: target.meta.Path, Event: w.event, Language: lang, Steps: steps})

	at := steps[len(steps)-1]

	switch lang {
	case language.JavaScript:
		w.gap(at, "hook_source_node_scope_unverified", "Node module resolution and runtime execution remain unverified for the captured hook script.")
		w.traceCommonJSHook(target, rel, firstArg, steps)
	case language.TypeScript:
		w.gap(at, "hook_source_bun_scope_unverified", "Bun module resolution and runtime execution remain unverified for the captured hook script.")
	case language.Python:
		if isolatedPythonArgs < 0 || !knownIsolatedPythonFile(target.doc.Units(), isolatedPythonArgs) {
			w.gap(at, "hook_source_python_scope_unverified", "Python import resolution and runtime execution remain unverified for the captured hook script.")
		}
	}
}

func runtimeShebang(text string) string {
	const maxLine = 512

	line, _, ended := strings.Cut(text[:min(len(text), maxLine+1)], "\n")
	if !ended && len(text) > maxLine {
		return ""
	}

	shebang, ok := strings.CutPrefix(line, "#!")
	if !ok || strings.ContainsRune(line, '\r') {
		return ""
	}

	fields := strings.FieldsFunc(shebang, func(r rune) bool { return r == ' ' || r == '\t' })
	switch {
	case len(fields) == 1 && strings.HasPrefix(fields[0], "/"):
		return hookRuntime(fields[0])
	case len(fields) == 2 && fields[0] == "/usr/bin/env":
		return hookRuntime(fields[1])
	default:
		return ""
	}
}

func (w *hookSourceWalk) nodeHookFirstArgument(words []*shellsyntax.Word, state hookSourceState) hookSourceArgument {
	args := w.arguments(words, state)
	if len(args.values) > 1 {
		return args.values[1]
	}

	if w.unquotedPluginPath(words[0], state) {
		afterPath := w.arguments(words[1:], state)
		if len(afterPath.values) > 0 {
			return afterPath.values[0]
		}
	}

	return hookSourceArgument{}
}

type hookRuntimeLaunch struct {
	operands           []*shellsyntax.Word
	language           string
	isolatedPythonArgs int // -1 unless Python's isolation, startup and argv can be verified
	replaces           bool
}

func (w *hookSourceWalk) runtimeLaunchWords(cmd *shellsyntax.Command, state hookSourceState) hookRuntimeLaunch {
	words, name, replaces := w.runtimeCommand(cmd.Words, state)
	if len(words) < 2 {
		return hookRuntimeLaunch{}
	}

	launch := hookRuntimeLaunch{language: hookRuntime(name), replaces: replaces, isolatedPythonArgs: -1}
	switch launch.language {
	case language.Python:
		launch.operands, launch.isolatedPythonArgs = pythonFileLaunchOperands(cmd, words[1:], name)
		return launch
	case language.JavaScript:
		launch.operands = hookSkipLiteral(words[1:], "--")
		return launch
	}

	if hookBun(name) {
		launch.operands, launch.language = hookSkipLiteral(words[1:], "--"), language.TypeScript
		return launch
	}

	if hookUV(name) && len(words) > 5 {
		run, _ := words[1].Literal()
		project, _ := words[2].Literal()
		python, _ := words[3].Literal()
		version, _ := words[4].Literal()

		if run == "run" && project == "--no-project" && python == "--python" && hookPythonMinor(version) {
			launch.operands, launch.language = words[5:], language.Python
			return launch
		}
	}

	return hookRuntimeLaunch{}
}

func pythonFileLaunchOperands(cmd *shellsyntax.Command, words []*shellsyntax.Word, name string) ([]*shellsyntax.Word, int) {
	var isolated, noSite bool

	for len(words) != 0 {
		option, _ := words[0].Literal()
		switch option {
		case "-I":
			isolated = true
		case "-S":
			noSite = true
		case "-B":
		default:
			words = hookSkipLiteral(words, "--")
			if isolated && noSite && len(words) > 0 && hookProvenPythonLaunch(cmd, words[1:], name) {
				return words, len(words) - 1
			}

			return words, -1
		}

		words = words[1:]
	}

	return nil, -1
}

// runtimeCommand removes modeled wrappers but preserves the interpreter's
// option boundary so that an operand after -- is never treated as an option.
func (w *hookSourceWalk) runtimeCommand(words []*shellsyntax.Word, state hookSourceState) ([]*shellsyntax.Word, string, bool) {
	name, _ := words[0].Literal()
	replaces := name == "exec" && !state.hasFunction("exec")
	external := replaces

	if replaces {
		words = hookSkipLiteral(words[1:], "--")
	}

	if len(words) > 1 {
		name, _ = words[0].Literal()
		if name == "env" && (replaces || !state.hasFunction("env")) {
			words = runtimeEnvWords(words[1:])
			external = true
		}
	}

	if len(words) == 0 {
		return nil, "", false
	}

	name, _ = w.value(words[0], state, false)
	if name == "" && hookKnownBunVariable(words[0], state) {
		name = "bun"
	}

	if !external && state.hasFunction(name) {
		return nil, "", false
	}

	return words, name, replaces
}

func hookBun(name string) bool {
	switch name {
	case "bun", "/usr/bin/bun", "/usr/local/bin/bun", "/opt/homebrew/bin/bun":
		return true
	default:
		return false
	}
}

func hookKnownBunVariable(word *shellsyntax.Word, state hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("bun") || len(word.Parts) != 1 {
		return false
	}

	name := word.Parts[0].Text

	return quotedGlobVariable(word, name) && state.kinds[name].kind == hookBunExecutable
}

func hookBunAssignment(word *shellsyntax.Word, state hookSourceState) bool {
	if word.Writes || word.Expands || state.lookupUnknown {
		return false
	}

	if len(word.Parts) == 2 {
		home, suffix := word.Parts[0], word.Parts[1]

		return home.Kind == shellsyntax.PartParameter && home.PlainParameter && home.Quoted && home.Text == "HOME" &&
			suffix.Kind == shellsyntax.PartLiteral && suffix.Quoted && suffix.Text == "/.bun/bin/bun"
	}

	if len(word.Parts) != 1 || word.Parts[0].Kind != shellsyntax.PartSubstitution || state.hasFunction("bun") {
		return false
	}

	tree := word.Parts[0].Tree
	if tree == nil || tree.OmittedExecution || len(tree.Statements) != 1 {
		return false
	}

	stmt := tree.Statements[0]
	if stmt.Negated || stmt.Background || stmt.Next == shellsyntax.Background || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if !hookCommandLookupProbe(cmd, state) || slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool {
		return r.FD != shellsyntax.StderrFD || r.Op != shellsyntax.RedirectOutput
	}) {
		return false
	}

	flag, _ := cmd.Words[1].Literal()
	name, _ := cmd.Words[2].Literal()

	return flag == "-v" && name == "bun"
}

func hookRuntime(name string) string {
	switch name {
	case "node", "nodejs", "/usr/bin/node", "/usr/local/bin/node", "/opt/homebrew/bin/node":
		return language.JavaScript
	}

	switch path.Dir(name) {
	case "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin":
		name = path.Base(name)
	}

	if name == "python" || name == "python3" {
		return language.Python
	}

	if version, ok := strings.CutPrefix(name, "python"); ok && hookPythonMinor(version) {
		return language.Python
	}

	return ""
}

func hookPythonMinor(version string) bool {
	minor, ok := strings.CutPrefix(version, "3.")

	return ok && minor != "" && decimalDigits(minor)
}

func hookUV(name string) bool {
	switch name {
	case "uv", "/usr/bin/uv", "/usr/local/bin/uv", "/opt/homebrew/bin/uv":
		return true
	default:
		return false
	}
}

func (w *hookSourceWalk) traceRuntimeInline(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) (replaces, traced bool) {
	if state.lookupUnknown || len(cmd.Words) < 3 {
		return false, false
	}

	words, name, replaces := w.runtimeCommand(cmd.Words, state)
	if len(words) < 3 {
		return false, false
	}

	lang := hookRuntime(name)

	if slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool {
		return !hookDiscardedOutput(r) && (lang != language.Python || r.Op != shellsyntax.RedirectHereString || !hookStdinRedirect(r))
	}) {
		return false, false
	}

	optionIndex := 1
	isolated := lang == language.Python && len(words) >= 5 && hookIsolatedPythonFlags(words[1:])

	if isolated {
		optionIndex = 3
	}

	option, _ := words[optionIndex].Literal()
	program := words[optionIndex+1]

	if !hookFixedArgument(program) {
		return false, false
	}

	root := pluginRootParameters[w.plugin.host]
	for _, binding := range cmd.Assignments {
		if !hookOrdinaryVariable(binding.Name, root) {
			return false, false
		}
	}

	switch {
	case lang == language.Python && option == "-c":
		argc := -1
		if isolated && hookProvenPythonLaunch(cmd, words[5:], name) {
			argc = len(words) - 5
		}

		if !w.projectRuntimeInline(e, view, cmd.Span, program, lang, chain, argc) {
			w.commandGap(e, view, cmd.Span, "hook_source_python_scope_unverified", "Inline Python runtime execution remains unverified.")
		}
	case lang == language.JavaScript && (option == "-e" || option == "--eval"):
		if len(words) > 3 {
			separator, _ := words[3].Literal()
			if separator != "--" {
				return false, false
			}
		}

		w.commandGap(e, view, cmd.Span, "hook_source_node_scope_unverified", "Inline Node runtime execution remains unverified.")
		w.projectRuntimeInline(e, view, cmd.Span, program, lang, chain, -1)
	default:
		return false, false
	}

	return replaces, true
}

func hookProvenPythonLaunch(cmd *shellsyntax.Command, args []*shellsyntax.Word, name string) bool {
	direct, literal := cmd.Words[0].Literal()

	return literal && direct == name && path.Base(name) != "python" && len(cmd.Assignments) == 0 &&
		len(args) <= 8 && !slices.ContainsFunc(args, hookUnverifiedPythonArgument)
}

func hookUnverifiedPythonArgument(arg *shellsyntax.Word) bool {
	return arg.Expands || arg.Writes || slices.ContainsFunc(arg.Parts, func(part shellsyntax.Part) bool {
		return part.Kind != shellsyntax.PartLiteral &&
			(part.Kind != shellsyntax.PartParameter || !part.PlainParameter || !part.Quoted || !hookVariableName(part.Text))
	})
}

func hookIsolatedPythonFlags(words []*shellsyntax.Word) bool {
	if len(words) < 2 {
		return false
	}

	first, _ := words[0].Literal()
	second, _ := words[1].Literal()

	return first == "-I" && second == "-S" || first == "-S" && second == "-I"
}

func (w *hookSourceWalk) projectRuntimeInline(e *entry, view source.View, command source.Span, word *shellsyntax.Word, lang string, chain []report.SourceRef, isolatedArgs int) bool {
	span := word.Span

	literal, known := word.Literal()
	if !known || literal == "" || e.doc == nil || span.End-span.Start < 2 {
		return false
	}

	raw := view.Text()[span.Start:span.End]
	if (raw[0] != '\'' && raw[0] != '"') || raw[len(raw)-1] != raw[0] || raw[1:len(raw)-1] != literal {
		return false
	}

	body := source.Span{Start: span.Start + 1, End: span.End - 1}

	return w.projectRuntimeBody(e, view, command, body, lang, chain, isolatedArgs)
}

func (w *hookSourceWalk) projectRuntimeBody(e *entry, view source.View, command, body source.Span, lang string, chain []report.SourceRef, isolatedArgs int) bool {
	b := w.plugin.b

	// The embedded body is a leaf. Its final source reference does not add
	// a recursive shell step.
	if e.doc == nil || len(chain) > maxHookSourceDepth || len(b.hookSourcePaths) >= b.r.Limits.References || !b.step() {
		return false
	}

	child, err := view.Select([]source.Span{body})
	if err != nil {
		return false
	}

	at, scope, ok := inlineRuntimeSource(e, view, command, body)
	if !ok {
		return false
	}

	doc, kept := e.doc.WithHookInlineRuntime(b.ctx, lang, child)
	if !kept {
		w.gap(at, "hook_source_limit", "The hook program could not be prepared within the source budget.")
		return false
	}

	*e.doc = doc
	b.hookSourcePaths = append(b.hookSourcePaths, HookSourcePath{
		Target: e.meta.Path, Event: w.event, Language: lang, Scope: scope, Steps: append(slices.Clone(chain), at),
	})

	return isolatedArgs >= 0 && knownIsolatedPythonProgram(doc.Units(), scope, isolatedArgs)
}

func (w *hookSourceWalk) noteUnverifiedRuntimeLaunch(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) {
	if state.lookupUnknown || len(cmd.Words) == 0 {
		return
	}

	words, name, _ := w.runtimeCommand(cmd.Words, state)
	if hookBun(name) {
		w.commandGap(e, view, cmd.Span, "hook_source_bun_scope_unverified", "The Bun program or its module scope could not be verified.")
		return
	}

	if len(words) == 0 || hookRuntime(name) != language.Python {
		return
	}

	if w.tracePythonStdin(e, view, cmd, words, name, chain) {
		return
	}

	w.commandGap(e, view, cmd.Span, "hook_source_python_scope_unverified", "The Python program or its import scope could not be verified.")
}

func (w *hookSourceWalk) tracePythonStdin(e *entry, view source.View, cmd *shellsyntax.Command, words []*shellsyntax.Word, name string, chain []report.SourceRef) bool {
	body := hookQuotedRuntimeStdin(cmd.Redirects)
	if body == nil {
		return false
	}

	argc := -1
	operands := words[1:]
	isolated := hookIsolatedPythonFlags(operands)

	if isolated {
		operands = operands[2:]
	}

	operands = hookSkipLiteral(operands, "--")
	if len(operands) != 0 {
		arg, _ := operands[0].Literal()
		if arg != "-" {
			return false
		}

		if isolated && hookProvenPythonLaunch(cmd, operands[1:], name) {
			argc = len(operands) - 1
		}
	}

	return w.projectRuntimeBody(e, view, cmd.Span, body.Span, language.Python, chain, argc)
}

func hookQuotedRuntimeStdin(redirects []*shellsyntax.Redirect) *shellsyntax.Word {
	var body *shellsyntax.Word

	for _, r := range redirects {
		if hookDiscardedOutput(r) {
			continue
		}

		if body != nil || r.Op != shellsyntax.RedirectHereDoc || r.FD != "" && r.FD != shellsyntax.StdinFD || !r.QuotedDelimiter || !r.BodyVerified || r.Body == nil {
			return nil
		}

		body = r.Body
	}

	return body
}

func inlineRuntimeSource(e *entry, view source.View, command, body source.Span) (report.SourceRef, source.Span, bool) {
	physical, err := view.Original(command)
	if err != nil {
		return report.SourceRef{}, source.Span{}, false
	}

	at := ref(e, physical)
	if at == nil {
		return report.SourceRef{}, source.Span{}, false
	}

	scope, err := view.Original(body)

	return *at, scope, err == nil
}

func runtimeEnvWords(words []*shellsyntax.Word) []*shellsyntax.Word {
	words = hookSkipLiteral(words, "-i")
	words = hookSkipLiteral(words, "--")

	for i, word := range words {
		if i >= maxHookArguments {
			return nil
		}

		if !hookFixedArgument(word) || len(word.Parts) == 0 || word.Parts[0].Kind != shellsyntax.PartLiteral {
			return nil
		}

		name, _, assignment := strings.Cut(word.Parts[0].Text, "=")
		if !assignment || !hookVariableName(name) {
			return words[i:]
		}
	}

	return nil
}

func hookSkipLiteral(words []*shellsyntax.Word, token string) []*shellsyntax.Word {
	if len(words) > 0 {
		if first, _ := words[0].Literal(); first == token {
			return words[1:]
		}
	}

	return words
}

func (w *hookSourceWalk) runtimeFileOperand(e *entry, view source.View, cmd *shellsyntax.Command, words []*shellsyntax.Word, state hookSourceState) (string, bool) {
	args := w.arguments(words, state)
	if len(args.values) > 0 && args.values[0].known {
		return args.values[0].value, true
	}

	first := words[0]
	if !w.unquotedPluginPath(first, state) {
		return "", false
	}

	if (e != w.config || w.rootLaunch != cmd) && !w.singleFieldRoot(e, state) {
		w.commandGap(e, view, first.Parts[0].Span, "hook_source_unquoted_root",
			hookUnquotedRootMessage)
	}

	return w.value(first, state, true)
}
