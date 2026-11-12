package shell

import (
	"context"
	"io/fs"
	"iter"
	"path"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

// GeneratedScripts recovers scripts from a document's prepared shell units.
func GeneratedScripts(ctx context.Context, doc document.File) (views []source.View, limited bool) {
	units := doc.Units()
	return GeneratedScriptsIn(ctx, units, document.MaxRegions-len(units), document.MaxScanBytes)
}

// GeneratedScriptsIn inspects a single generation of prepared units. Every
// recovered view maps through its parent to the captured bytes.
func GeneratedScriptsIn(ctx context.Context, units []document.Unit, remaining, bytes int) ([]source.View, bool) {
	views, _, limited, _ := RecoverGeneratedShellIn(ctx, units, remaining, bytes)
	return views, limited
}

// RecoverGeneratedShellIn retains recovered bodies and their bounded local uses.
func RecoverGeneratedShellIn(ctx context.Context, units []document.Unit, remaining, bytes int) ([]source.View, []document.GeneratedShellExecution, bool, bool) {
	scan := generatedShellScan{ctx: ctx, remaining: remaining, bytes: bytes}

	for _, unit := range units {
		tree, ok := unit.Tree.(parse.ShellTree)
		if !ok {
			continue
		}

		root := tree.Tree
		if tree.ExecutionError != nil && tree.Declarations != nil && tree.DeclarationError == nil {
			root = tree.Declarations
		}

		scan.view = unit.View
		state := scriptScope{variables: map[string]string{}, functions: map[string]scriptFunction{}}
		state.collectFunctions(root)

		if !scan.walk(root, &state, true, nil) || !scan.walkFunctions(&state) {
			break
		}
	}

	return scan.views, scan.executions, scan.limited, scan.executionLimit
}

type generatedShellScan struct {
	view           source.View
	ctx            context.Context
	views          []source.View
	pending        []pendingScriptFunction
	executions     []document.GeneratedShellExecution
	remaining      int
	bytes          int
	limited        bool
	executionLimit bool
}

type pendingScriptFunction struct {
	body    *shellsyntax.File
	effects scriptEffects
}

type scriptScope struct {
	variables map[string]string
	functions map[string]scriptFunction
	scriptEffects
}

type scriptEffects struct {
	shadow         scriptWriterAliases
	bindingsUnsafe bool
	pathUnsafe     bool
	hashUnsafe     bool
	consumerHashes uint32
	cdpathUnsafe   bool
	trapUnsafe     bool
}

type scriptFunction struct {
	effects scriptEffects
	seen    bool
}

func (e *scriptEffects) merge(other scriptEffects) {
	e.shadow.merge(other.shadow)
	e.bindingsUnsafe = e.bindingsUnsafe || other.bindingsUnsafe
	e.pathUnsafe = e.pathUnsafe || other.pathUnsafe
	e.hashUnsafe = e.hashUnsafe || other.hashUnsafe
	e.consumerHashes |= other.consumerHashes
	e.cdpathUnsafe = e.cdpathUnsafe || other.cdpathUnsafe
	e.trapUnsafe = e.trapUnsafe || other.trapUnsafe
}

func (e *scriptEffects) unknown() {
	e.shadow = scriptWriterAliases{cat: true, tee: true, command: true, catFunction: true, teeFunction: true, commandFunction: true}
	e.shadow.consumerAliases, e.shadow.consumerFunctions = ^uint32(0), ^uint32(0)
	e.bindingsUnsafe, e.pathUnsafe, e.hashUnsafe = true, true, true
	e.cdpathUnsafe, e.trapUnsafe = true, true
	e.consumerHashes = ^uint32(0)
}

func (s *generatedShellScan) walk(tree *shellsyntax.File, scope *scriptScope, recoverWrites bool, flow *generatedShellFlow) bool {
	if tree == nil {
		return true
	}

	conditional := false

	if flow == nil {
		flow = &generatedShellFlow{cwd: "."}
	}

	successChain := false

	for _, stmt := range tree.Statements {
		if s.ctx.Err() != nil {
			s.limited = true
			return false
		}

		isolated := len(stmt.Commands) > 1 || shellBranchLinks[stmt.Next] || conditional
		mergesStderr := slices.Contains(stmt.Pipes, "|&")

		track := recoverWrites && len(stmt.Commands) == 1 && stmt.Next != "&" && stmt.Next != "||" && !stmt.Negated && !scope.trapUnsafe
		if !track {
			flow.reset()
		}

		if isolated {
			clear(scope.variables)
		}

		var fileFlow *generatedShellFlow
		if track {
			fileFlow = flow
		}

		for i, c := range stmt.Commands {
			if !s.visitGeneratedCommand(c, scope, fileFlow, recoverWrites, mergesStderr, i+1 < len(stmt.Commands)) {
				return false
			}

			scope.bind(c, !isolated)
		}

		if successChain && stmt.Next != "&&" {
			// The following statement can also run after a failed operand.
			flow.reset()
		}

		successChain = stmt.Next == "&&"
		conditional = shellConditionalLinks[stmt.Next]
	}

	return true
}

func (s *generatedShellScan) visitGeneratedCommand(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow, recoverWrites, mergesStderr, stdoutPiped bool) bool {
	scope.shadow.observe(c)

	if flow != nil {
		flow.invalidateBefore(c, scope.variables)
	}

	if recoverWrites && !mergesStderr {
		written, more := s.recover(c, scope, stdoutPiped, flow)
		if !more {
			return false
		}

		if flow != nil && !written && !plainGeneratedShellGroup(c) {
			s.observeGeneratedUse(c, scope, flow)
		}
	}

	return s.children(c, scope, recoverWrites, flow)
}

// A function's writer lookup is evaluated at call time. Admit its writes only
// after seeing the enclosing unit's possible effects, including late changes.
func (s *generatedShellScan) walkFunctions(scope *scriptScope) bool {
	for i := 0; i < len(s.pending); i++ {
		function := s.pending[i]
		function.effects.merge(scope.scriptEffects)

		nested := scriptScope{variables: map[string]string{}, functions: scope.functions, scriptEffects: function.effects}
		if !s.walk(function.body, &nested, true, nil) {
			return false
		}
	}

	s.pending = nil

	return true
}

func (s *generatedShellScan) recover(c *shellsyntax.Command, scope *scriptScope, stdoutPiped bool, flow *generatedShellFlow) (written, more bool) {
	hdoc, writer, bypass := scriptHeredoc(c, scope.variables, stdoutPiped)
	if hdoc == nil {
		return false, true
	}

	wrapperShadowed := bypass && literalWordEquals(c.Words[0], "command") && scope.shadow.shadows(c.Words[0], false)
	if hdoc.Body == nil || !hdoc.BodyVerified || wrapperShadowed || scope.shadow.shadows(writer, bypass) ||
		scope.lookupUncertain(c.Words, writer) {
		s.limited = true
		return false, true
	}

	if hdoc.Body.Span.Start == hdoc.Body.Span.End {
		return false, true
	}

	if len(s.views) >= s.remaining || s.bytes == 0 || !analysisbudget.Consume(s.ctx, 1) {
		s.limited = true
		return false, false
	}

	view, ok := scriptHeredocView(s.view, hdoc, scope.variables)
	if !ok || len(view.Text()) > s.bytes {
		s.limited = true
		return false, true
	}

	if view.Text() != "" {
		s.bytes -= len(view.Text())

		s.views = append(s.views, view)
		if flow != nil {
			s.rememberGeneratedWrite(flow, c, hdoc, writer, view, scope.variables)
		}
	}

	return view.Text() != "", true
}

func (s *scriptScope) lookupUncertain(words []*shellsyntax.Word, writer *shellsyntax.Word) bool {
	name, _ := writer.Literal()
	if strings.HasPrefix(name, "/") {
		return false
	}

	standardPath := len(words) > 1 && literalWordEquals(words[0], "command") && literalWordEquals(words[1], "-p")
	// Bash can honor an explicit hash entry even with command -p.
	return s.hashUnsafe || s.consumerHashes&shellConsumerBit(name) != 0 || s.pathUnsafe && !standardPath
}

func (s *generatedShellScan) children(c *shellsyntax.Command, scope *scriptScope, recoverWrites bool, flow *generatedShellFlow) bool {
	if c.Group != nil || c.Prelude != nil || len(c.Alternatives) > 0 {
		clear(scope.variables)

		for _, child := range append([]*shellsyntax.File{c.Group, c.Prelude}, c.Alternatives...) {
			clear(scope.variables)

			var childFlow *generatedShellFlow
			if child == c.Group && plainGeneratedShellGroup(c) {
				childFlow = flow
			}

			if !s.walk(child, scope, recoverWrites, childFlow) {
				return false
			}
		}
	}

	for child := range scriptIsolatedTrees(c) {
		if child != nil {
			nested := scriptScope{variables: map[string]string{}, functions: scope.functions, scriptEffects: scope.scriptEffects}

			function := child == c.FunctionBody && c.FunctionName != ""
			if function && recoverWrites {
				s.pending = append(s.pending, pendingScriptFunction{body: child, effects: scope.scriptEffects})
			}

			if !s.walk(child, &nested, recoverWrites && !function, nil) {
				return false
			}

			if function {
				summary := scope.functions[c.FunctionName]
				summary.effects.merge(nested.scriptEffects)
				summary.seen = true
				scope.functions[c.FunctionName] = summary
			}
		}
	}

	return true
}

func (s *scriptScope) bind(c *shellsyntax.Command, stable bool) {
	s.observeEffects(c)

	if s.bindingsUnsafe || !stable || c.Declaration != "" || len(c.Words) != 0 || len(c.Redirects) != 0 || c.Group != nil ||
		c.Prelude != nil || len(c.Alternatives) != 0 || len(c.Invalidates) != 0 {
		clear(s.variables)
		return
	}

	for _, a := range c.Assignments {
		value, known := sourceWord(a.Value, s.variables)
		if known && staticScriptVariable(a.Name) && len(s.variables) < MaxShellBindings {
			s.variables[a.Name] = value
		} else {
			delete(s.variables, a.Name)
		}
	}
}

func (s *scriptScope) observeEffects(c *shellsyntax.Command) {
	name := c.Declaration

	words := scriptBuiltinWords(c.Words)
	if len(c.Words) > 0 {
		direct, known := c.Words[0].Literal()
		if !known {
			s.unknown()
			return
		}

		if fn, local := s.functions[direct]; local {
			if fn.seen {
				s.merge(fn.effects)
			} else {
				s.unknown()
			}
		}

		if len(words) > 0 {
			var resolved bool

			name, resolved = words[0].Literal()
			if !resolved {
				s.unknown()
				return
			}
		}
	}

	if len(c.Words) == 0 {
		for _, a := range c.Assignments {
			s.observeSearchPath(a.Name)
		}
	}

	s.observeBuiltinEffects(name, words)
}

func (s *scriptScope) observeBuiltinEffects(name string, words []*shellsyntax.Word) {
	switch name {
	case "declare", "typeset", "local", "readonly", "nameref":
		s.bindingsUnsafe = true
	case "eval", ".", "source":
		s.unknown()
	case "trap":
		if len(words) > 1 && !literalWordEquals(words[1], "-p") && !literalWordEquals(words[1], "-l") {
			s.unknown()
		}
	case "hash":
		if len(words) > 3 && literalWordEquals(words[1], "-p") {
			for _, operand := range words[3:] {
				value, known := operand.Literal()
				s.hashUnsafe = s.hashUnsafe || !known || value == "cat" || value == "tee"
				s.consumerHashes |= shellConsumerBit(value)
			}
		}
	case "printf":
		if len(words) > 2 && literalWordEquals(words[1], "-v") {
			key, _ := words[2].Literal()
			s.observeSearchPath(key)
		}
	}

	if len(words) < 2 {
		return
	}

	switch name {
	case "export", "declare", "typeset", "local", "readonly", "nameref", "read", "unset", "mapfile", "readarray", "getopts":
		for _, arg := range words[1:] {
			if len(arg.Parts) == 0 || arg.Parts[0].Kind != "literal" {
				continue
			}

			key, _, _ := strings.Cut(arg.Parts[0].Text, "=")
			s.observeSearchPath(key)
		}
	}
}

func (s *scriptScope) observeSearchPath(key string) {
	s.pathUnsafe = s.pathUnsafe || key == "PATH"
	s.cdpathUnsafe = s.cdpathUnsafe || key == "CDPATH"
}

func staticScriptVariable(name string) bool {
	switch name {
	case "RANDOM", "SRANDOM", "SECONDS", "LINENO", "BASHPID", "BASHOPTS", "SHELLOPTS", "EPOCHSECONDS", "EPOCHREALTIME",
		"OPTIND", "PIPESTATUS", "GROUPS", "DIRSTACK", "FUNCNAME", "UID", "EUID", "PPID", "_":
		return false
	}

	return !strings.HasPrefix(name, "BASH_")
}

func scriptIsolatedTrees(c *shellsyntax.Command) iter.Seq[*shellsyntax.File] {
	return func(yield func(*shellsyntax.File) bool) {
		if !yield(c.FunctionBody) {
			return
		}

		for child := range shellNestedTrees(c) {
			if !yield(child) {
				return
			}
		}

		for _, a := range c.Assignments {
			if a.Value == nil {
				continue
			}

			for _, part := range a.Value.Parts {
				if part.Tree != nil && !yield(part.Tree) {
					return
				}
			}
		}
	}
}

type scriptWriterAliases struct {
	cat, tee, command                         bool
	catFunction, teeFunction, commandFunction bool
	consumerAliases, consumerFunctions        uint32
}

func (s *scriptScope) collectFunctions(tree *shellsyntax.File) {
	if tree == nil {
		return
	}

	for _, stmt := range tree.Statements {
		for _, c := range stmt.Commands {
			if c.FunctionName != "" {
				s.functions[c.FunctionName] = scriptFunction{}
				s.shadow.catFunction = s.shadow.catFunction || c.FunctionName == "cat"
				s.shadow.teeFunction = s.shadow.teeFunction || c.FunctionName == "tee"
				s.shadow.commandFunction = s.shadow.commandFunction || c.FunctionName == "command"
				s.shadow.consumerFunctions |= shellConsumerBit(c.FunctionName)
			}

			s.collectFunctions(c.Group)
			s.collectFunctions(c.Prelude)

			for _, branch := range c.Alternatives {
				s.collectFunctions(branch)
			}

			for child := range scriptIsolatedTrees(c) {
				s.collectFunctions(child)
			}
		}
	}
}

func (a *scriptWriterAliases) merge(other scriptWriterAliases) {
	a.cat, a.tee, a.command = a.cat || other.cat, a.tee || other.tee, a.command || other.command
	a.catFunction = a.catFunction || other.catFunction
	a.teeFunction = a.teeFunction || other.teeFunction
	a.commandFunction = a.commandFunction || other.commandFunction
	a.consumerAliases |= other.consumerAliases
	a.consumerFunctions |= other.consumerFunctions
}

// An explicit alias can change the bytes written by a bare command. Once a
// possible definition is seen, keep that uncertainty for the rest of the unit.
func (a *scriptWriterAliases) observe(c *shellsyntax.Command) {
	if len(c.Words) < 2 {
		return
	}

	words := scriptBuiltinWords(c.Words)
	if len(words) < 2 {
		return
	}

	if name, _ := words[0].Literal(); name != "alias" {
		return
	}

	for _, arg := range words[1:] {
		value, literal := arg.Literal()
		if !literal {
			a.cat, a.tee, a.command = true, true, true
			a.consumerAliases = ^uint32(0)

			return
		}

		if key, _, ok := strings.Cut(value, "="); ok {
			a.cat = a.cat || key == "cat"
			a.tee = a.tee || key == "tee"
			a.command = a.command || key == "command"
			a.consumerAliases |= shellConsumerBit(key)
		}
	}
}

func scriptBuiltinWords(words []*shellsyntax.Word) []*shellsyntax.Word {
	for len(words) > 0 {
		switch {
		case literalWordEquals(words[0], "command"):
			words, _ = scriptWriterWords(words)
		case literalWordEquals(words[0], "builtin"):
			words = words[1:]
			if len(words) > 0 && literalWordEquals(words[0], "--") {
				words = words[1:]
			}
		default:
			return words
		}
	}

	return nil
}

func (a scriptWriterAliases) shadows(word *shellsyntax.Word, bypass bool) bool {
	if bypass {
		return false
	}

	name, _ := word.Literal()

	return name == "cat" && (a.catFunction || !word.Quoted && a.cat) ||
		name == "tee" && (a.teeFunction || !word.Quoted && a.tee) ||
		name == "command" && (a.commandFunction || !word.Quoted && a.command)
}

// Admit identity writers with unambiguous stdin and fresh local outputs.
// Other operands, descriptors and append writes can change the bytes.
func scriptHeredoc(c *shellsyntax.Command, vars map[string]string, stdoutPiped bool) (*shellsyntax.Redirect, *shellsyntax.Word, bool) {
	if len(c.Words) == 0 || len(c.Redirects) == 0 || len(c.Assignments) != 0 {
		return nil, nil, false
	}

	input, output := generatedWriterRedirects(c.Redirects)
	if input == nil {
		return nil, nil, false
	}

	words, bypass := scriptWriterWords(c.Words)
	if len(words) == 0 {
		return nil, nil, false
	}

	name, _ := words[0].Literal()
	switch name {
	case "/bin/cat", "/bin/tee", "/usr/bin/cat", "/usr/bin/tee":
		name, bypass = path.Base(name), true
	}

	args := words[1:]
	if len(args) > 0 {
		if value, _ := args[0].Literal(); value == "--" {
			args = args[1:]
		}
	}

	switch name {
	case "cat":
		if len(args) == 1 {
			if value, _ := args[0].Literal(); value == "-" {
				args = args[1:]
			}
		}

		if len(args) == 0 && output != nil && localScriptPath(output.Target, vars) {
			return input, words[0], bypass
		}
	case "tee":
		// A tee whose stdout is still a pipe can stop writing its files on EPIPE.
		if (!stdoutPiped || output != nil) && teeWritesScript(args, output, vars) {
			return input, words[0], bypass
		}
	}

	return nil, nil, false
}

func generatedWriterRedirects(redirects []*shellsyntax.Redirect) (input, output *shellsyntax.Redirect) {
	for _, r := range redirects {
		switch {
		case input == nil && (r.FD == "" || r.FD == "0") && (r.Op == "<<" || r.Op == "<<-"):
			input = r
		case output == nil && (r.FD == "" || r.FD == "1") && (r.Op == ">" || r.Op == ">|"):
			output = r
		case r.FD == "2" && r.Op == ">" && literalWordEquals(r.Target, "/dev/null"):
		default:
			return nil, nil
		}
	}

	return input, output
}

func scriptWriterWords(words []*shellsyntax.Word) ([]*shellsyntax.Word, bool) {
	if !literalWordEquals(words[0], "command") {
		return words, false
	}

	words = words[1:]
	for _, flag := range []string{"-p", "--"} {
		if len(words) > 0 && literalWordEquals(words[0], flag) {
			words = words[1:]
		}
	}

	return words, true
}

func teeWritesScript(args []*shellsyntax.Word, output *shellsyntax.Redirect, vars map[string]string) bool {
	found := false
	if output != nil {
		found = localScriptPath(output.Target, vars)
		if !found && !literalWordEquals(output.Target, "/dev/null") {
			return false
		}
	}

	for _, arg := range args {
		value, known := scriptPathWord(arg, vars)
		if !known || value != "/dev/null" && !localWritePath(value) {
			return false
		}

		found = found || strings.HasSuffix(value, ".sh")
	}

	return found
}

func literalWordEquals(word *shellsyntax.Word, want string) bool {
	value, ok := word.Literal()
	return ok && value == want
}

func scriptPathWord(word *shellsyntax.Word, vars map[string]string) (string, bool) {
	if word == nil {
		return "", false
	}

	for _, part := range word.Parts {
		if part.Kind == "parameter" && !part.Quoted {
			return "", false
		}
	}

	return sourceWord(word, vars)
}

func localScriptPath(word *shellsyntax.Word, vars map[string]string) bool {
	value, known := scriptPathWord(word, vars)
	return known && strings.HasSuffix(value, ".sh") && localWritePath(value)
}

func localWritePath(value string) bool {
	return !strings.HasPrefix(value, "-") &&
		!strings.ContainsAny(value, "\\:\r\n\x00") && fs.ValidPath(strings.TrimPrefix(value, "./"))
}

func scriptHeredocView(parent source.View, input *shellsyntax.Redirect, vars map[string]string) (source.View, bool) {
	view, err := parent.Select([]source.Span{input.Body.Span})
	if err != nil {
		return source.View{}, false
	}

	var ok bool
	if !input.QuotedDelimiter {
		view, ok = joinHeredocLines(view)
		if !ok {
			return source.View{}, false
		}
	}

	if input.Op == "<<-" {
		view, ok = stripHeredocTabs(view)
		if !ok {
			return source.View{}, false
		}
	}

	if input.QuotedDelimiter {
		return view, true
	}

	return expandScriptHeredoc(view, vars)
}

// Join lines before interpreting tabs or parameters. A parameter name can
// straddle an escaped newline, and a tab can become the start of a logical line.
func joinHeredocLines(view source.View) (source.View, bool) {
	text := view.Text()

	var escapes []source.Replacement

	for i := 0; i+1 < len(text); i++ {
		if text[i] != '\\' {
			continue
		}

		if text[i+1] == '\\' {
			i++
			continue
		}

		if text[i+1] == '\n' {
			escapes = append(escapes, source.Replacement{Span: source.Span{Start: i, End: i + 2}})
			if len(escapes) > document.MaxSourceSegments {
				return source.View{}, false
			}

			i++
		}
	}

	return replaceHeredoc(view, escapes)
}

func expandScriptHeredoc(view source.View, vars map[string]string) (source.View, bool) {
	text := view.Text()
	size := len(text)

	var changes []source.Replacement

	for i := 0; i < len(text); i++ {
		start, end, value := i, i, ""
		switch text[i] {
		case '`':
			return source.View{}, false
		case '\\':
			if i+1 < len(text) && strings.ContainsRune("$`\\", rune(text[i+1])) {
				end = i + 1
				i++ // Preserve the escaped byte without interpreting it.
			}
		case '$':
			name, next, known := scriptHeredocParameter(text, i)
			if !known {
				return source.View{}, false
			}

			if name != "" {
				var bound bool

				value, bound = vars[name]
				if !bound {
					return source.View{}, false
				}

				end, i = next, next-1
			}
		}

		if end == start {
			continue
		}

		size += len(value) - (end - start)

		changes = append(changes, source.Replacement{Span: source.Span{Start: start, End: end}, Text: value})
		if size > shellsyntax.MaxBytes || len(changes) > document.MaxSourceSegments {
			return source.View{}, false
		}
	}

	return replaceHeredoc(view, changes)
}

// An empty name represents a dollar that Bash treats literally. Special,
// positional and compound expansions are outside the proven binding grammar.
func scriptHeredocParameter(text string, at int) (string, int, bool) {
	start := at + 1
	if start == len(text) {
		return "", start, true
	}

	braced := text[start] == '{'
	if braced {
		start++
	}

	end := start
	for end < len(text) && shellNameByte(text[end], end != start) {
		end++
	}

	if end == start {
		return "", end, !braced && !strings.ContainsRune("0123456789@*#?$!-([", rune(text[start]))
	}

	if braced {
		if end == len(text) || text[end] != '}' {
			return "", end, false
		}

		return text[start:end], end + 1, true
	}

	return text[start:end], end, true
}

func shellNameByte(c byte, allowDigit bool) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || allowDigit && c >= '0' && c <= '9'
}

func replaceHeredoc(view source.View, changes []source.Replacement) (source.View, bool) {
	if len(changes) == 0 {
		return view, true
	}

	projected, err := view.Replace(changes)

	return projected, err == nil
}

func stripHeredocTabs(view source.View) (source.View, bool) {
	var spans []source.Span

	offset := 0
	for line := range strings.Lines(view.Text()) {
		start := offset + len(line) - len(strings.TrimLeft(line, "\t"))

		offset += len(line)
		if start == offset {
			continue
		}

		if n := len(spans); n > 0 && spans[n-1].End == start {
			spans[n-1].End = offset
		} else {
			spans = append(spans, source.Span{Start: start, End: offset})
		}

		if len(spans) > document.MaxSourceSegments {
			return source.View{}, false
		}
	}

	projected, err := view.Select(spans)

	return projected, err == nil
}
