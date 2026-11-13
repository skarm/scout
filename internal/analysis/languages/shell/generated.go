package shell

import (
	"context"
	"io/fs"
	"iter"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

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
	recovery := RecoverGeneratedShellIn(ctx, units, remaining, bytes)
	return recovery.Views, recovery.Gaps != 0
}

type GeneratedShellRecovery struct {
	Views            []source.View
	Executions       []document.GeneratedShellExecution
	Gaps             document.GeneratedShellGaps
	Issues           []document.GeneratedShellIssue
	ExecutionLimited bool
}

// RecoverGeneratedShellIn retains recovered bodies and their bounded local uses.
func RecoverGeneratedShellIn(ctx context.Context, units []document.Unit, remaining, bytes int) GeneratedShellRecovery {
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
		state := scriptScope{variables: map[string]string{}}
		scan.functions = newGeneratedFunctionScan(root)

		if !scan.walk(root, &state, nil) || !scan.walkFunctions(&state) {
			break
		}
	}

	return GeneratedShellRecovery{
		Views: scan.views, Executions: scan.executions, Gaps: scan.gaps, Issues: scan.issues, ExecutionLimited: scan.executionLimit,
	}
}

type generatedShellScan struct {
	view           source.View
	ctx            context.Context
	views          []source.View
	functions      generatedFunctionScan
	executions     []document.GeneratedShellExecution
	seenExecutions map[document.GeneratedShellExecution]bool
	remaining      int
	bytes          int
	gaps           document.GeneratedShellGaps
	issues         []document.GeneratedShellIssue
	seenIssues     map[document.GeneratedShellIssue]bool
	executionLimit bool
}

type scriptScope struct {
	variables       map[string]string
	functions       map[string]*shellsyntax.File
	aliases         map[string]bool
	conditionalDefs bool
	functionBody    bool
	repeated        bool
	returned        bool
	failedReturn    bool
	returnEffects   *functionReturnState
	stdoutPiped     bool
	temporaryPath   bool
	temporaryCDPath bool
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
	aliasUnsafe    bool
}

func (e *scriptEffects) merge(other scriptEffects) {
	e.shadow.merge(other.shadow)
	e.bindingsUnsafe = e.bindingsUnsafe || other.bindingsUnsafe
	e.pathUnsafe = e.pathUnsafe || other.pathUnsafe
	e.hashUnsafe = e.hashUnsafe || other.hashUnsafe
	e.consumerHashes |= other.consumerHashes
	e.cdpathUnsafe = e.cdpathUnsafe || other.cdpathUnsafe
	e.trapUnsafe = e.trapUnsafe || other.trapUnsafe
	e.aliasUnsafe = e.aliasUnsafe || other.aliasUnsafe
}

func (e *scriptEffects) unknown() {
	e.shadow = scriptWriterAliases{cat: true, tee: true, command: true, catFunction: true, teeFunction: true, commandFunction: true}
	e.shadow.consumerAliases, e.shadow.consumerFunctions = ^uint32(0), ^uint32(0)
	e.bindingsUnsafe, e.pathUnsafe, e.hashUnsafe = true, true, true
	e.cdpathUnsafe, e.trapUnsafe = true, true
	e.aliasUnsafe = true
	e.consumerHashes = ^uint32(0)
}

func (s *generatedShellScan) walk(tree *shellsyntax.File, scope *scriptScope, flow *generatedShellFlow) bool {
	if tree == nil {
		return true
	}

	conditional := false

	if flow == nil {
		flow = &generatedShellFlow{cwd: "."}
	}

	successChain := false

	for _, stmt := range tree.Statements {
		if scope.returned {
			return true
		}

		if s.ctx.Err() != nil {
			s.noteGap(stmt.Span.Start, document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
			return false
		}

		if !s.walkStatement(stmt, scope, flow, conditional) {
			return false
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

func (s *generatedShellScan) walkStatement(stmt *shellsyntax.Statement, scope *scriptScope, flow *generatedShellFlow, conditional bool) bool {
	pipeline := len(stmt.Commands) > 1
	background := stmt.Next == "&"
	forked := pipeline || background
	isolated := forked || shellBranchLinks[stmt.Next] || conditional
	fileFlow := flow

	if forked || stmt.Next == "||" || stmt.Negated || scope.trapUnsafe {
		flow.reset()

		fileFlow = nil
	}

	if pipeline && !s.recoverPipedStdin(stmt, scope) {
		return false
	}

	for i, c := range stmt.Commands {
		if scope.functionBody && !s.functions.step(s.ctx) {
			s.noteGap(c.Span.Start, document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
			return false
		}

		current := scope
		if forked {
			stage := scope.nested()
			current = &stage
		}

		if scope.functionBody && !forked && !conditional && !stmt.Negated {
			if status, returns := current.plainFunctionReturn(c); returns {
				scope.returned, scope.failedReturn = true, status%256 != 0
				return true
			}
		}

		mergesStderr := i < len(stmt.Pipes) && stmt.Pipes[i] == "|&"
		if !s.visitGeneratedCommand(c, current, fileFlow, mergesStderr, i+1 < len(stmt.Commands), !isolated) {
			return false
		}

		if pipeline && !background && i+1 == len(stmt.Commands) {
			// Bash lastpipe may run the last stage in the current shell.
			scope.mergePossibleFunctionState(current)
			scope.retainPositionals(current)
		}
	}

	if forked {
		scope.clearNamedVariables()
	}

	return true
}

func (s *generatedShellScan) visitGeneratedCommand(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow, mergesStderr, stdoutPiped, stable bool) bool {
	scope.observeAliases(c)
	s.functions.define(c, scope, stable)

	if body := scope.localFunctionCall(c); body != nil {
		more := s.callFunction(c, body, scope, flow, stdoutPiped, stable)
		if more {
			scope.bind(c, stable, false)
		}

		return more
	}

	if !s.recoverDirectStdin(c, scope) {
		return false
	}

	written, more := s.recover(c, scope, mergesStderr, stdoutPiped || scope.stdoutPiped, flow)
	if !more {
		return false
	}

	if flow != nil && !written && !plainGeneratedShellGroup(c) && !plainGeneratedShellConditional(c) {
		written = s.observeGeneratedUse(c, scope, flow)
	}

	conditionalDefs := scope.conditionalDefs
	inheritedPipe := scope.stdoutPiped
	scope.conditionalDefs = conditionalDefs || !stable
	scope.stdoutPiped = inheritedPipe || stdoutPiped
	more = s.children(c, scope, flow)
	scope.conditionalDefs = conditionalDefs
	scope.stdoutPiped = inheritedPipe

	if !more {
		return false
	}

	scope.observeEffects(c)
	scope.bind(c, stable, written && generatedWritePreservesBindings(c))

	if scope.trapUnsafe && !s.functions.fallback {
		s.functions.opaque = true
	}

	return true
}

func (s *generatedShellScan) recover(c *shellsyntax.Command, scope *scriptScope, mergesStderr, stdoutPiped bool, flow *generatedShellFlow) (written, more bool) {
	if flow != nil {
		app := scriptAppendHeredoc(c, scope.variables, mergesStderr, stdoutPiped)

		pending := make([]pendingGeneratedAppend, 0, len(app.paths))

		for _, p := range app.paths {
			key := flow.key(p)
			prior, known := flow.files[key]
			pending = append(pending, pendingGeneratedAppend{key: key, prior: prior, known: known})
			delete(flow.files, key)
		}

		flow.invalidateBefore(c, scope.variables)

		if len(pending) != 0 {
			return s.recoverAppend(c, scope, flow, app, pending)
		}
	}

	write := scriptHeredoc(c, scope.variables, stdoutPiped)
	if write.input == nil || mergesStderr {
		s.noteGap(c.Span.Start, generatedShellWriteGaps(c, scope.variables, s.view), document.GeneratedShellUnsupported)
		return false, true
	}

	hdoc := write.input
	preamble := generatedHeredocPreamble(s.view, hdoc, scope.variables)
	shebang := shellShebang(preamble)
	confirmed := shebang || slices.ContainsFunc(write.paths, generatedShellName)

	if reason := generatedWriterIssue(c, scope, hdoc, write.writer, write.bypass); reason != "" {
		if confirmed {
			s.noteGap(c.Span.Start, document.GeneratedShellUnrecovered, reason)
		}

		return false, true
	}

	if !confirmed {
		if flow != nil {
			s.rememberGeneratedWrite(flow, c, write, source.View{}, preamble, newGeneratedCandidate(c, hdoc, scope))
		}

		return true, true
	}

	if hdoc.Body.Span.Start == hdoc.Body.Span.End {
		if flow != nil {
			s.rememberGeneratedWrite(flow, c, write, source.View{}, preamble, nil)
		}

		return true, true
	}

	capacity := len(s.views) < s.remaining && s.bytes > 0
	if !capacity && !scope.functionBody || !analysisbudget.Consume(s.ctx, 1) {
		s.noteGap(c.Span.Start, document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
		return false, false
	}

	view, reason := scriptHeredocView(s.view, hdoc, scope.variables)
	if reason != "" {
		s.noteGap(c.Span.Start, document.GeneratedShellUnrecovered, reason)
		return false, true
	}

	if retained, more := s.retainGeneratedView(c.Span.Start, hdoc, view, scope.functionBody); !retained {
		return false, more
	}

	if flow != nil {
		s.rememberGeneratedWrite(flow, c, write, view, preamble, nil)
	}

	return true, true
}

func generatedWriterIssue(c *shellsyntax.Command, scope *scriptScope, input *shellsyntax.Redirect, writer *shellsyntax.Word, bypass bool) document.GeneratedShellReason {
	if input.Body == nil || !input.BodyVerified {
		return document.GeneratedShellInput
	}

	wrapperShadowed := bypass && literalWordEquals(c.Words[0], "command") && scope.shadow.shadows(c.Words[0], false)
	if wrapperShadowed || scope.shadow.shadows(writer, bypass) || scope.lookupUncertain(c.Words, writer) {
		return document.GeneratedShellWriter
	}

	return ""
}

func (s *generatedShellScan) retainGeneratedView(at int, input *shellsyntax.Redirect, view source.View, functionBody bool) (retained, more bool) {
	if view.Text() == "" || functionBody && s.functions.hasProjection(input, view) {
		return true, true
	}

	capacity := len(s.views) < s.remaining && s.bytes > 0
	if !capacity || len(view.Text()) > s.bytes {
		s.noteGap(at, document.GeneratedShellUnrecovered, document.GeneratedShellLimit)
		return false, capacity
	}

	s.bytes -= len(view.Text())
	s.views = append(s.views, view)

	if functionBody {
		s.functions.projections[input] = append(s.functions.projections[input], view)
	}

	return true, true
}

func (s *generatedShellScan) noteGap(at int, kinds document.GeneratedShellGaps, reason document.GeneratedShellReason) {
	if kinds == 0 {
		return
	}

	s.gaps |= kinds
	if len(s.issues) >= document.MaxRegions {
		return
	}

	issue := document.GeneratedShellIssue{Kinds: kinds, Reason: reason, At: -1}

	if at >= 0 && at < len(s.view.Text()) {
		_, size := utf8.DecodeRuneInString(s.view.Text()[at:])
		if span, err := s.view.Original(source.Span{Start: at, End: at + size}); err == nil {
			issue.At = span.Start
		}
	}

	if s.seenIssues == nil {
		s.seenIssues = make(map[document.GeneratedShellIssue]bool)
	}

	if !s.seenIssues[issue] {
		s.seenIssues[issue] = true
		s.issues = append(s.issues, issue)
	}
}

func (s *scriptScope) lookupUncertain(words []*shellsyntax.Word, writer *shellsyntax.Word) bool {
	name, _ := writer.Literal()
	if strings.HasPrefix(name, "/") {
		return false
	}

	standardPath := len(words) > 1 && literalWordEquals(words[0], "command") && literalWordEquals(words[1], "-p")
	// Bash can honor an explicit hash entry even with command -p.
	return s.hashUnsafe || s.consumerHashes&shellConsumerBit(name) != 0 || (s.pathUnsafe || s.temporaryPath) && !standardPath
}

func (s *generatedShellScan) children(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow) bool {
	if plainGeneratedShellGroup(c) {
		if !s.walk(c.Group, scope, flow) {
			return false
		}
	} else if c.ExclusiveBranches {
		if !plainGeneratedShellConditional(c) {
			flow = nil
		}

		if !s.walkConditional(c, scope, flow) {
			return false
		}
	} else if c.Group != nil || c.Prelude != nil || len(c.Alternatives) > 0 {
		scope.clearNamedVariables()

		if c.Loop {
			scope.clearPositionals()
		}

		conditional, repeated := scope.conditionalDefs, scope.repeated
		scope.conditionalDefs = true
		scope.repeated = repeated || c.Loop

		for _, child := range append([]*shellsyntax.File{c.Group, c.Prelude}, c.Alternatives...) {
			scope.clearNamedVariables()

			if !s.walk(child, scope, nil) {
				return false
			}
		}

		scope.conditionalDefs = conditional
		scope.repeated = repeated
	}

	for child := range scriptIsolatedTrees(c) {
		if child == nil || child == c.FunctionBody {
			continue
		}

		nested := scope.nested()
		if child != c.Subshell {
			nested.clearNamedVariables()
		}

		if !s.walk(child, &nested, nil) {
			return false
		}
	}

	return true
}

func (s *generatedShellScan) walkConditional(c *shellsyntax.Command, scope *scriptScope, flow *generatedShellFlow) bool {
	scope.clearNamedVariables()

	before := flow.clone()

	if !s.walk(c.Prelude, scope, flow) {
		return false
	}

	if scope.returned {
		return true
	}

	if flow != nil {
		// A test command can fail. Only facts unaffected by its evaluation
		// are safe to share with both its success and its failure branch.
		flow.intersect(before)
	}

	incoming := scope.nested()

	var (
		exits  functionReturnState
		joined *generatedShellFlow
	)

	continues := scope.conditionalDefs || len(c.Alternatives) == 0
	for _, branch := range c.Alternatives {
		nested := incoming.nested()
		branchFlow := flow.clone()

		nested.returnEffects = scope.returnEffects
		if !s.walk(branch, &nested, branchFlow) {
			return false
		}

		if nested.returned && scope.returnEffects != nil {
			exits.add(&nested, branchFlow)
		} else {
			scope.mergePossibleFunctionState(&nested)
			scope.retainPositionals(&nested)
		}

		if branchFlow != nil && !nested.returned {
			if joined == nil {
				joined = branchFlow
			} else {
				joined.intersect(branchFlow)
			}
		}

		continues = continues || !nested.returned
	}

	if exits.scope != nil {
		if continues {
			scope.returnEffects.add(exits.scope, exits.flow)
		} else {
			scope.scriptEffects = exits.scope.scriptEffects
			scope.functions = exits.scope.functions
			scope.aliases = exits.scope.aliases
			scope.failedReturn = exits.scope.failedReturn
			joined = exits.flow
		}
	}

	scope.returned = !continues
	if flow != nil {
		if joined == nil || scope.trapUnsafe || len(c.Alternatives) < 2 {
			flow.reset()
		} else {
			*flow = *joined
		}
	}

	return true
}

func generatedWritePreservesBindings(c *shellsyntax.Command) bool {
	for _, redirect := range c.Redirects {
		if generatedRedirectRunsCode(redirect) {
			return false
		}
	}

	return true
}

func (s *scriptScope) bind(c *shellsyntax.Command, stable, preserve bool) {
	if s.trapUnsafe {
		clear(s.variables)
		return
	}

	if preserve && !s.bindingsUnsafe {
		return
	}

	if s.bindingsUnsafe || !stable || c.Declaration != "" || len(c.Words) != 0 || len(c.Redirects) != 0 || c.Group != nil ||
		c.Prelude != nil || len(c.Alternatives) != 0 || len(c.Invalidates) != 0 {
		s.clearNamedVariables()
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
	args := c.DeclarationArgs

	words := scriptBuiltinWords(c.Words)
	if len(c.Words) > 0 {
		direct, known := c.Words[0].Literal()
		if !known {
			s.unknown()
			return
		}

		if _, local := s.functions[direct]; local || s.mayAlias(c.Words[0], direct) {
			s.unknown()
			return
		}

		if len(words) > 0 {
			var resolved bool

			name, resolved = words[0].Literal()
			if !resolved {
				s.unknown()
				return
			}

			args = words[1:]
		}
	}

	if len(c.Words) == 0 {
		for _, a := range c.Assignments {
			s.observeSearchPath(a.Name)
		}
	}

	s.observeBuiltinEffects(name, args)
}

func (s *scriptScope) observeBuiltinEffects(name string, args []*shellsyntax.Word) {
	switch name {
	case "declare", "typeset", "local", "readonly", "nameref":
		s.bindingsUnsafe = true
		s.observeReferenceOptions(name, args)
	case "eval", ".", "source":
		s.unknown()
	case "trap":
		if len(args) > 0 && !literalWordEquals(args[0], "-p") && !literalWordEquals(args[0], "-l") {
			s.unknown()
		}
	case "hash":
		s.observeHash(args)
	case "printf":
		s.observePrintfAssignment(args)
	case "shift":
		s.clearPositionals()
	case "set":
		if len(args) != 0 {
			s.clearPositionals()
		}
	case "unset":
		s.unsetFunctions(args)
	}

	switch name {
	case "export", "declare", "typeset", "local", "readonly", "nameref", "unset":
		s.observeSearchPathOperands(args, true)
	case "read":
		s.observeReadTargets(args)
	case "mapfile", "readarray", "getopts":
		s.observeSearchPathOperands(args, false)
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

func (a *scriptWriterAliases) define(name string) {
	a.catFunction = a.catFunction || name == "cat"
	a.teeFunction = a.teeFunction || name == "tee"
	a.commandFunction = a.commandFunction || name == "command"
	a.consumerFunctions |= shellConsumerBit(name)
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
func (s *scriptScope) observeAliases(c *shellsyntax.Command) {
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

	a := &s.shadow

	for _, arg := range words[1:] {
		value, literal := arg.Literal()
		if !literal {
			s.aliasUnsafe = true
			a.cat, a.tee, a.command = true, true, true
			a.consumerAliases = ^uint32(0)

			return
		}

		if key, _, ok := strings.Cut(value, "="); ok {
			s.rememberAlias(key)
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
func scriptHeredoc(c *shellsyntax.Command, vars map[string]string, stdoutPiped bool) generatedHeredocWrite {
	if len(c.Words) == 0 || len(c.Redirects) == 0 || len(c.Assignments) != 0 {
		return generatedHeredocWrite{}
	}

	input, output := generatedWriterRedirects(c.Redirects)
	if input == nil || output != nil && output.Op == ">>" {
		return generatedHeredocWrite{}
	}

	words, bypass := scriptWriterWords(c.Words)
	if len(words) == 0 {
		return generatedHeredocWrite{}
	}

	name, absolute := generatedWriterName(words[0])
	args := skipGeneratedOptionEnd(words[1:])

	var targets []*shellsyntax.Word

	switch name {
	case "cat":
		if len(args) == 1 {
			if value, _ := args[0].Literal(); value == "-" {
				args = args[1:]
			}
		}

		if len(args) == 0 && output != nil {
			targets = []*shellsyntax.Word{output.Target}
		}
	case "tee":
		// A tee whose stdout is still a pipe can stop writing its files on EPIPE.
		if !stdoutPiped || output != nil {
			targets = args
			if output != nil {
				targets = append([]*shellsyntax.Word{output.Target}, args...)
			}
		}
	}

	return newGeneratedHeredocWrite(input, words[0], targets, vars, bypass || absolute)
}

func generatedWriterName(word *shellsyntax.Word) (name string, absolute bool) {
	name, _ = word.Literal()
	switch name {
	case "/bin/cat", "/bin/tee", "/usr/bin/cat", "/usr/bin/tee":
		return path.Base(name), true
	}

	return name, false
}

func generatedWriterRedirects(redirects []*shellsyntax.Redirect) (input, output *shellsyntax.Redirect) {
	for _, r := range redirects {
		switch {
		case input == nil && (r.FD == "" || r.FD == "0") && (r.Op == "<<" || r.Op == "<<-"):
			input = r
		case output == nil && (r.FD == "" || r.FD == "1") && (r.Op == ">" || r.Op == ">|" || r.Op == ">>"):
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

func generatedShellName(value string) bool {
	return strings.HasSuffix(value, ".sh")
}

func localWritePath(value string) bool {
	return !strings.HasPrefix(value, "-") &&
		!strings.ContainsAny(value, "\\:\r\n\x00") && fs.ValidPath(strings.TrimPrefix(value, "./"))
}

func scriptHeredocView(parent source.View, input *shellsyntax.Redirect, vars map[string]string) (source.View, document.GeneratedShellReason) {
	view, err := parent.Select([]source.Span{input.Body.Span})
	if err != nil {
		return source.View{}, document.GeneratedShellInput
	}

	var reason document.GeneratedShellReason
	if !input.QuotedDelimiter {
		view, reason = joinHeredocLines(view)
		if reason != "" {
			return source.View{}, reason
		}
	}

	if input.Op == "<<-" {
		view, reason = stripHeredocTabs(view)
		if reason != "" {
			return source.View{}, reason
		}
	}

	if input.QuotedDelimiter {
		return view, ""
	}

	return expandScriptHeredoc(view, vars)
}

// Join lines before interpreting tabs or parameters. A parameter name can
// straddle an escaped newline, and a tab can become the start of a logical line.
func joinHeredocLines(view source.View) (source.View, document.GeneratedShellReason) {
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
				return source.View{}, document.GeneratedShellLimit
			}

			i++
		}
	}

	return replaceHeredoc(view, escapes)
}

func expandScriptHeredoc(view source.View, vars map[string]string) (source.View, document.GeneratedShellReason) {
	text := view.Text()
	size := len(text)

	var changes []source.Replacement

	for i := 0; i < len(text); i++ {
		start, end, value := i, i, ""
		switch text[i] {
		case '`':
			return source.View{}, document.GeneratedShellExpansion
		case '\\':
			if i+1 < len(text) && strings.ContainsRune("$`\\", rune(text[i+1])) {
				end = i + 1
				i++ // Preserve the escaped byte without interpreting it.
			}
		case '$':
			name, next, known := scriptHeredocParameter(text, i)
			if !known {
				return source.View{}, document.GeneratedShellExpansion
			}

			if name != "" {
				var bound bool

				value, bound = vars[name]
				if !bound {
					return source.View{}, document.GeneratedShellExpansion
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
			return source.View{}, document.GeneratedShellLimit
		}
	}

	return replaceHeredoc(view, changes)
}

// An empty name represents a dollar that Bash treats literally.
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
	if start < len(text) && text[start] >= '1' && text[start] <= '9' {
		end++
		for braced && end < len(text) && text[end] >= '0' && text[end] <= '9' {
			end++
		}
	} else {
		for end < len(text) && shellNameByte(text[end], end != start) {
			end++
		}
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

func replaceHeredoc(view source.View, changes []source.Replacement) (source.View, document.GeneratedShellReason) {
	if len(changes) == 0 {
		return view, ""
	}

	projected, err := view.Replace(changes)
	if err != nil {
		return source.View{}, document.GeneratedShellInput
	}

	return projected, ""
}

func stripHeredocTabs(view source.View) (source.View, document.GeneratedShellReason) {
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
			return source.View{}, document.GeneratedShellLimit
		}
	}

	projected, err := view.Select(spans)
	if err != nil {
		return source.View{}, document.GeneratedShellInput
	}

	return projected, ""
}
