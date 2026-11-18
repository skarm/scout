package harness

import (
	"maps"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (w *hookSourceWalk) applyWhile(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	root := pluginRootParameters[w.plugin.host]
	if hookPlainCompound(cmd) && state.applyWhileAssignments(cmd.WhileAssignments, root) {
		return true
	}

	if !cmd.Loop || cmd.Prelude == nil || len(cmd.Alternatives) != 2 || state.lookupUnknown {
		return false
	}

	if w.applyShiftCaseLoop(e, view, cmd, state, chain) {
		return true
	}

	readNames, reader := hookReadLoop(cmd, *state, root)
	body := cmd.Alternatives[0]

	if !reader {
		if !hookPlainCompound(cmd) {
			return false
		}

		body = &shellsyntax.File{Statements: slices.Concat(cmd.Prelude.Statements, body.Statements)}
	}

	// Analyze any iteration with all loop-written values forgotten.
	effects := hookLoopEffects{writes: readNames}
	if !w.hookReadLoopWrites(body, &effects, *state, root) {
		if reader {
			return w.applyReadCallbackLoop(e, view, cmd, readNames, state, chain)
		}

		return w.applyDirectoryRetry(e, view, cmd, state, chain)
	}

	w.traceSubstitutions(e, view, cmd, *state, chain)

	effects.forgetWrites(state)
	iteration := *state

	if reader {
		w.traceReadLoopBody(e, view, cmd.Prelude, *state, chain)
		iteration = w.guardedReadIteration(body, iteration, effects, readNames)
	}

	w.traceReadLoopBody(e, view, body, iteration, chain)

	return true
}

// An until loop can retry directory creation. The condition changes only the
// filesystem, so the usual loop join can track shell effects of the body.
func (w *hookSourceWalk) applyDirectoryRetry(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	if !cmd.Until || len(cmd.Prelude.Statements) != 1 {
		return false
	}

	test := cmd.Prelude.Statements[0]
	if test.Negated || test.Background || test.Next == "&" || hookAndOrLink(test.Next) || len(test.Commands) != 1 ||
		!hookDirectoryOperation(test.Commands[0], *state, "mkdir") {
		return false
	}

	start := state.clone()
	start.forgetFileBindings()

	if !w.traceLoopInvariant(e, view, cmd, cmd.Alternatives[0], nil, &start, chain, "mkdir") {
		return false
	}

	*state = start

	return true
}

// At the start of an iteration a failed validation can skip its remainder.
// Keep a guard fact only when neither the body nor a helper can rewrite it.
func (w *hookSourceWalk) guardedReadIteration(body *shellsyntax.File, state hookSourceState, effects hookLoopEffects, readNames []string) hookSourceState {
	if !state.explicitBash {
		return state
	}

	for i := 0; i+1 < len(body.Statements); i += 2 {
		test, skip := body.Statements[i], body.Statements[i+1]
		if len(test.Commands) != 1 || !hookAndOrLink(test.Next) || hookAndOrLink(skip.Next) ||
			!hookKnownStatus(skip, state, "continue") || skip.Negated {
			break
		}

		cmd := test.Commands[0]
		guard := cmd.DecimalGuard

		if guard == nil || !cmd.ReadOnlyTest || !hookPlainCompound(cmd) || !slices.Contains(readNames, guard.Name) ||
			slices.Contains(effects.writes[len(readNames):], guard.Name) || effects.hasFoldedExport(guard.Name) {
			break
		}

		if i == 0 {
			state = state.clone()
		}

		w.refineDecimalGuard(test, &state, (test.Next == "||") != test.Negated)
	}

	return state
}

func (w *hookSourceWalk) traceReadLoopBody(e *entry, view source.View, body *shellsyntax.File, state hookSourceState, chain []report.SourceRef) {
	for _, stmt := range body.Statements {
		if !w.plugin.b.step() {
			return
		}

		for _, cmd := range stmt.Commands {
			w.traceSubstitutions(e, view, cmd, state, chain)

			for _, nested := range []*shellsyntax.File{cmd.Group, cmd.Prelude} {
				if nested != nil {
					w.traceReadLoopBody(e, view, nested, state, chain)
				}
			}

			for _, branch := range cmd.Alternatives {
				w.traceReadLoopBody(e, view, branch, state, chain)
			}
		}
	}
}

func hookReadLoop(cmd *shellsyntax.Command, state hookSourceState, root string) ([]string, bool) {
	if state.lookupUnknown || state.hasFunction("read") || !cmd.Loop || cmd.Prelude == nil ||
		len(cmd.Alternatives) != 2 || !hookReadLoopInput(cmd) {
		return nil, false
	}

	tests := cmd.Prelude.Statements
	if len(tests) == 0 || len(tests) > 2 {
		return nil, false
	}

	test := tests[0]
	if test.Negated || test.Background || len(test.Commands) != 1 {
		return nil, false
	}

	names, known := hookReadDestinations(test.Commands[0], state, root)
	if known && len(tests) == 2 {
		known = test.Next == "||" && hookReadsFinalLine(tests[1], state, names)
	}

	return names, known
}

func hookReadsFinalLine(stmt *shellsyntax.Statement, state hookSourceState, names []string) bool {
	if stmt.Negated || stmt.Background || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if cmd.NonemptyParameter != "" {
		return hookPlainCompound(cmd) && slices.Contains(names, cmd.NonemptyParameter)
	}

	expr, ok := hookBracketExpression(cmd, state)
	if !ok || len(expr) != 2 {
		return false
	}

	operator, _ := expr[0].Literal()

	return operator == "-n" && slices.ContainsFunc(names, func(name string) bool { return quotedGlobVariable(expr[1], name) })
}

func hookReadDestinations(cmd *shellsyntax.Command, state hookSourceState, root string) ([]string, bool) {
	if state.lookupUnknown || state.hasFunction("read") || len(cmd.Words) < 2 || !hookReadLoopEnvironment(cmd.Assignments, state) ||
		!hookReadLoopInput(cmd) {
		return nil, false
	}

	head, _ := cmd.Words[0].Literal()

	option, _ := cmd.Words[1].Literal()

	if head != "read" {
		return nil, false
	}

	destinations := cmd.Words[2:]
	if option == "-ra" && state.explicitBash && len(destinations) == 1 {
		name, _ := destinations[0].Literal()
		if hookLocalVariable(name, root) {
			return []string{name}, true
		}
	}

	if option != "-r" {
		return nil, false
	}

	if len(destinations) >= 2 {
		flag, _ := destinations[0].Literal()
		if flag == "-d" {
			if _, literal := destinations[1].Literal(); !literal {
				return nil, false
			}

			destinations = destinations[2:]
		}
	}

	if len(destinations) == 0 {
		return []string{"REPLY"}, hookLocalVariable("REPLY", root)
	}

	names := make([]string, 0, len(destinations))
	for _, word := range destinations {
		name, _ := word.Literal()
		// Bash read commonly uses _ to discard a field. Its volatile binding
		// is forgotten and cannot be used as a stable arithmetic fact.
		if !hookVariableName(name) || name != "_" && !hookLocalVariable(name, root) {
			return nil, false
		}

		names = append(names, name)
	}

	return names, true
}

func (w *hookSourceWalk) forgetReadDestinations(cmd *shellsyntax.Command, state *hookSourceState) bool {
	names, known := hookReadDestinations(cmd, *state, pluginRootParameters[w.plugin.host])
	if !known {
		return false
	}

	for _, name := range names {
		state.bindValue(name, "", false)
	}

	return true
}

func hookReadLoopEnvironment(assignments []shellsyntax.Assignment, state hookSourceState) bool {
	if len(assignments) == 0 {
		return true
	}

	if len(assignments) != 1 || assignments[0].Name != "IFS" {
		return false
	}

	value := assignments[0].Value
	if value == nil || value.Writes {
		return false
	}

	if hookLiteralAssignmentWord(value) || hookTestOperand(value) {
		return true
	}

	// A quoted substitution of a constant printf supplies only the IFS
	// value. The caller still traces the substitution in its child scope.
	if len(value.Parts) != 1 || value.Parts[0].Kind != "substitution" || !value.Parts[0].Quoted || state.hasFunction("printf") {
		return false
	}

	tree := value.Parts[0].Tree
	cmd, known := simpleShellCommand(tree)

	if !known || tree.OmittedExecution || len(cmd.Words) != 2 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	format, fixed := cmd.Words[1].Literal()

	return name == "printf" && fixed && hookReadOnlyPrintf(format)
}

func hookLiteralAssignmentWord(word *shellsyntax.Word) bool {
	if word == nil || word.Writes {
		return false
	}

	_, literal := word.Literal()

	// An ANSI-C quoted literal can change the delimiter, but it cannot
	// change command lookup or run another expansion.
	return literal || len(word.Parts) == 1 && word.Parts[0].Quoted && word.Parts[0].Kind == "literal"
}

func hookReadLoopInput(cmd *shellsyntax.Command) bool {
	if len(cmd.Redirects) == 0 {
		return true
	}

	if len(cmd.Redirects) != 1 || hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	return hookStdinRedirect(cmd.Redirects[0])
}

func hookStdinRedirect(r *shellsyntax.Redirect) bool {
	if r.FD != "" && r.FD != "0" {
		return false
	}

	switch r.Op {
	case "<<<":
		return true
	case "<":
		return hookSingleBracketWord(r.Target) || hookProcessInput(r.Target)
	case "<<", "<<-":
		return r.BodyVerified
	default:
		return false
	}
}

func hookProcessInput(word *shellsyntax.Word) bool {
	return len(word.Parts) == 1 && word.Parts[0].Kind == "process_substitution" && word.Parts[0].Tree != nil
}

type hookLoopEffects struct {
	writes         []string
	locals         []string
	tests          []*shellsyntax.Command
	counters       []string
	foldedExports  []string
	indexedAppends []string
	helperDepth    int
	fileWrites     bool
	statusOnly     bool
}

const maxHookLoopHelperDepth = 3

func (effects hookLoopEffects) forgetWrites(state *hookSourceState) {
	if effects.fileWrites {
		state.forgetFileBindings()
	}

	effects.forgetFoldedExports(state)

	for _, key := range effects.writes {
		state.bindValue(key, "", false)
	}

	for _, key := range effects.indexedAppends {
		state.forgetAppendedArray(key)
	}

	for _, counter := range effects.counters {
		state.bindValue(counter, "", false)
		state.markDecimal(counter)
	}

	// The loop may never declare a local. If it later assigns the name,
	// returning from the function must allow for either scope.
	for _, key := range effects.locals {
		if _, declared := state.locals[key]; !declared {
			state.locals[key] = hookSourceLocal{maybe: true}
		}
	}
}

func (effects hookLoopEffects) hasFoldedExport(name string) bool {
	return slices.ContainsFunc(effects.foldedExports, func(candidate string) bool { return strings.EqualFold(candidate, name) })
}

func (effects hookLoopEffects) forgetFoldedExports(state *hookSourceState) {
	for name := range state.vars {
		if effects.hasFoldedExport(name) {
			delete(state.vars, name)
		}
	}

	for name := range state.kinds {
		if effects.hasFoldedExport(name) {
			delete(state.kinds, name)
		}
	}
}

func (w *hookSourceWalk) hookReadLoopWrites(body *shellsyntax.File, effects *hookLoopEffects, state hookSourceState, root string) bool {
	if !w.scanReadLoop(body, effects, state, root) || len(state.locals)+len(effects.locals) > maxHookLocals {
		return false
	}

	if len(effects.foldedExports) != 0 && (slices.Contains(effects.writes, "LC_ALL") || slices.Contains(effects.counters, "LC_ALL")) {
		return false
	}

	if len(effects.counters) != 0 {
		unknown := make(map[string]bool, len(effects.writes))
		for _, name := range effects.writes {
			unknown[name] = true
		}

		for _, counter := range effects.counters {
			if !w.decimalBinding(counter, state) || unknown[counter] || effects.hasFoldedExport(counter) {
				return false
			}
		}
	}

	// Predicates must remain safe after any iteration.
	state.vars = maps.Clone(state.vars)
	state.kinds = maps.Clone(state.kinds)

	if effects.fileWrites {
		state.forgetFileBindings()
	}

	effects.forgetFoldedExports(&state)

	for _, key := range effects.writes {
		delete(state.vars, key)
		delete(state.kinds, key)
	}

	for _, key := range effects.indexedAppends {
		state.forgetAppendedArray(key)
	}

	for _, counter := range effects.counters {
		delete(state.vars, counter)
		state.markDecimal(counter)
	}

	return !slices.ContainsFunc(effects.tests, func(cmd *shellsyntax.Command) bool { return !w.hookSafeTest(cmd, state) })
}

func (w *hookSourceWalk) scanReadLoop(body *shellsyntax.File, effects *hookLoopEffects, state hookSourceState, root string) bool {
	for _, stmt := range body.Statements {
		if !w.plugin.b.step() || stmt.Background || stmt.Next == "&" {
			return false
		}

		if hookReadOnlyPipeline(stmt, state) && (!effects.statusOnly || !slices.ContainsFunc(stmt.Commands, hookLoopSubstitutions)) {
			continue
		}

		if len(stmt.Commands) > 1 {
			if !w.scanLoopPipeline(stmt, effects, state, root) {
				return false
			}

			continue
		}

		if len(stmt.Commands) != 1 || !w.scanLoopCommand(stmt, effects, state, root) {
			return false
		}
	}

	return true
}

func (w *hookSourceWalk) scanLoopCommand(stmt *shellsyntax.Statement, effects *hookLoopEffects, state hookSourceState, root string) bool {
	cmd := stmt.Commands[0]
	plain := hookPlainCompound(cmd)

	if effects.statusOnly && hookLoopSubstitutions(cmd) {
		return false
	}

	counter := hookLoopCounter(cmd, root, state.explicitBash)

	switch {
	case plain && cmd.Group != nil:
		return w.scanReadLoop(cmd.Group, effects, state, root)
	case plain && cmd.ExclusiveBranches:
		return w.scanReadLoop(cmd.Prelude, effects, state, root) && w.scanLoopArms(cmd, effects, state, root)
	case plain && cmd.ReadOnlyTest:
		effects.tests = append(effects.tests, cmd)

		if cmd.RegexTest {
			effects.writes = append(effects.writes, "BASH_REMATCH")
		}
	case w.loopReadOnly(stmt, state):
	case !effects.statusOnly && hookLoopFileOperation(cmd, state):
		effects.fileWrites = true
	case w.collectLoopFunctionWrites(cmd, effects, state, root):
	case hookPlainIteration(cmd, root):
		if !w.scanReadLoop(cmd.Alternatives[0], effects, state, root) {
			return false
		}

		effects.writes = append(effects.writes, cmd.ForArguments)
	case !effects.statusOnly && cmd.Loop:
		names, ok := hookReadLoop(cmd, state, root)
		if !ok || !w.scanReadLoop(cmd.Alternatives[0], effects, state, root) {
			return false
		}

		effects.writes = append(effects.writes, names...)
	case plain && cmd.Case != nil && hookScalarCaseSelector(cmd.Case.Word) && hookStaticCasePatterns(cmd.Case):
		return w.scanLoopCase(cmd, effects, state, root)
	case counter != "":
		effects.counters = append(effects.counters, counter)
	case len(cmd.Assignments) > 0 && len(cmd.Words) == 0 && len(cmd.Redirects) == 0 && !hookCommandWritesDuringExpansion(cmd):
		return w.recordLoopWrites(cmd, effects, state, root)
	default:
		return false
	}

	return true
}

// A self-update can preserve a decimal loop invariant. The caller proves the
// initial value and rejects any other possible write to the same variable.
func hookLoopCounter(cmd *shellsyntax.Command, root string, explicitBash bool) string {
	if name := cmd.ArithmeticUpdate; name != "" {
		if explicitBash && len(cmd.Redirects) == 0 && hookLocalVariable(name, root) {
			return name
		}

		return ""
	}

	if len(cmd.Assignments) != 1 || len(cmd.Words) != 0 || len(cmd.Redirects) != 0 || cmd.Declaration != "" {
		return ""
	}

	assignment := cmd.Assignments[0]

	operands := arithmeticOperands(assignment.Value)
	if len(operands) == 0 || !hookLocalVariable(assignment.Name, root) {
		return ""
	}

	for _, operand := range operands {
		if len(operand.Parts) != 1 || operand.Parts[0].Text != assignment.Name {
			return ""
		}

		kind := operand.Parts[0].Kind
		if kind != "parameter" && kind != "arithmetic_variable" {
			return ""
		}
	}

	return assignment.Name
}

func hookScalarCaseSelector(word *shellsyntax.Word) bool {
	if hookTestOperand(word) {
		return true
	}

	// The case selector does not undergo splitting or pathname expansion.
	return !word.Expands && !word.Writes && len(word.Parts) == 1 &&
		word.Parts[0].Kind == "parameter" && hookVariableName(word.Parts[0].Text)
}

func (w *hookSourceWalk) collectLoopFunctionWrites(cmd *shellsyntax.Command, effects *hookLoopEffects, state hookSourceState, root string) bool {
	if effects.helperDepth >= maxHookLoopHelperDepth || state.lookupUnknown || len(cmd.Words) == 0 ||
		len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 || hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	name, known := cmd.Words[0].Literal()

	fn, defined := state.singleFunction(name)
	if !known || !defined {
		return false
	}

	// A status helper can read paths and write ordinary variables. Reject
	// substitutions in its body, which need their own execution contexts.
	child := state.child()
	child.canReturn = true
	child.locals = map[string]hookSourceLocal{}
	helper := hookLoopEffects{statusOnly: true, helperDepth: effects.helperDepth + 1}

	if !w.hookReadLoopWrites(fn.body, &helper, child, root) {
		return false
	}

	// A local may be conditional. Forget every possible helper write in the
	// caller unless a stronger model can prove that it was local.
	effects.writes = append(effects.writes, helper.writes...)
	effects.writes = append(effects.writes, helper.counters...)
	effects.tests = append(effects.tests, helper.tests...)
	effects.foldedExports = append(effects.foldedExports, helper.foldedExports...)

	return true
}

func hookLoopFileOperation(cmd *shellsyntax.Command, state hookSourceState) bool {
	if hookFileOperationWithoutShellWrites(cmd, state) {
		return true
	}

	if len(cmd.Words) > 0 && !hookCommandWritesDuringExpansion(cmd) &&
		slices.ContainsFunc(cmd.Redirects, hookGroupFileOutput) && hookRedirectedIO(cmd, state) {
		name, _ := cmd.Words[0].Literal()
		return name == "echo" || name == "printf"
	}

	if state.lookupUnknown || state.hasFunction("rm") || len(cmd.Words) != 3 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	flag, _ := cmd.Words[1].Literal()

	return name == "rm" && flag == "-f" && hookSingleBracketWord(cmd.Words[2])
}

func hookLoopSubstitutions(cmd *shellsyntax.Command) bool {
	if slices.ContainsFunc(cmd.Words, hookWordHasSubstitution) || slices.ContainsFunc(cmd.ExpansionWords, hookWordHasSubstitution) {
		return true
	}

	for _, assignment := range cmd.Assignments {
		if hookWordHasSubstitution(assignment.Value) {
			return true
		}
	}

	return slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool {
		return hookWordHasSubstitution(r.Target) || hookWordHasSubstitution(r.Body)
	})
}

func (w *hookSourceWalk) scanLoopPipeline(stmt *shellsyntax.Statement, effects *hookLoopEffects, state hookSourceState, root string) bool {
	if effects.statusOnly {
		return false
	}

	commands := stmt.Commands
	for _, cmd := range commands[:len(commands)-1] {
		if !w.plugin.b.step() || !hookPipelineStage(cmd, state) {
			return false
		}
	}

	// lastpipe can run the last stage in the current shell. Account for
	// its possible assignments as if it always did.
	last := commands[len(commands)-1]

	stage := &shellsyntax.Statement{Span: last.Span, Commands: []*shellsyntax.Command{last}}

	return w.scanReadLoop(&shellsyntax.File{Statements: []*shellsyntax.Statement{stage}}, effects, state, root)
}

func hookPlainIteration(cmd *shellsyntax.Command, root string) bool {
	return cmd.ForArguments != "" && hookLocalVariable(cmd.ForArguments, root) && cmd.ForArraySlice == nil &&
		len(cmd.Redirects) == 0 && len(cmd.Alternatives) == 2
}

func (w *hookSourceWalk) scanLoopArms(cmd *shellsyntax.Command, effects *hookLoopEffects, state hookSourceState, root string) bool {
	return !slices.ContainsFunc(cmd.Alternatives, func(branch *shellsyntax.File) bool {
		return !w.scanReadLoop(branch, effects, state, root)
	})
}

func (w *hookSourceWalk) scanLoopCase(cmd *shellsyntax.Command, effects *hookLoopEffects, state hookSourceState, root string) bool {
	for i, branch := range cmd.Alternatives {
		if i < len(cmd.Case.Patterns) {
			names := hookGuardedExport(cmd.Case.Word, cmd.Case.Patterns[i], branch, state, root)
			if len(names) != 0 {
				effects.foldedExports = append(effects.foldedExports, names...)
				continue
			}
		}

		if !w.scanReadLoop(branch, effects, state, root) {
			return false
		}
	}

	return true
}

func hookGuardedExport(selector *shellsyntax.Word, patterns []*shellsyntax.Word, branch *shellsyntax.File, state hookSourceState, root string) []string {
	if !state.explicitBash || state.lookupUnknown || state.hasFunction("export") ||
		(state.vars["LC_ALL"] != "C" && state.vars["LC_ALL"] != "POSIX") || len(branch.Statements) != 1 {
		return nil
	}

	stmt := branch.Statements[0]
	if stmt.Background || stmt.Negated || stmt.Next != "" || len(stmt.Commands) != 1 || len(selector.Parts) != 1 {
		return nil
	}

	cmd := stmt.Commands[0]
	if cmd.Declaration != "export" || len(cmd.DeclarationArgs) != 1 || !hookPlainCompound(cmd) {
		return nil
	}

	word := cmd.DeclarationArgs[0]
	if word.Expands || word.Writes || len(word.Parts) != 3 {
		return nil
	}

	key, assignment, value := word.Parts[0], word.Parts[1], word.Parts[2]
	if !quotedGlobVariable(selector, key.Text) || key.Kind != "parameter" || !key.Quoted ||
		assignment.Kind != "literal" || assignment.Text != "=" || value.Kind != "parameter" || !value.Quoted ||
		!hookVariableName(value.Text) {
		return nil
	}

	return hookOrdinaryExportNames(patterns, root)
}

// nocasematch can accept other spellings of a name in C. Keep every such
// write and reject spellings that can affect command lookup or the locale.
func hookOrdinaryExportNames(patterns []*shellsyntax.Word, root string) []string {
	names := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		value, literal := pattern.Literal()
		name := strings.ToUpper(value)

		if !literal || !hookVariableName(value) || !hookLocalVariable(name, strings.ToUpper(root)) ||
			strings.HasPrefix(name, "LC_") || name == "LANG" || name == "LANGUAGE" {
			return nil
		}

		names = append(names, name)
	}

	return names
}

func (w *hookSourceWalk) recordLoopWrites(cmd *shellsyntax.Command, effects *hookLoopEffects, state hookSourceState, root string) bool {
	if cmd.Declaration != "" && (cmd.Declaration != "local" || !w.canBindLocals(cmd, state)) {
		return false
	}

	for _, assignment := range cmd.Assignments {
		if !hookLocalVariable(assignment.Name, root) {
			return false
		}

		if cmd.Declaration == "" && assignment.Value != nil && assignment.Value.ArrayAppend &&
			state.explicitBash && state.kinds[assignment.Name].indexedArray() {
			effects.indexedAppends = append(effects.indexedAppends, assignment.Name)
		} else {
			effects.writes = append(effects.writes, assignment.Name)
		}

		if cmd.Declaration == "local" {
			effects.locals = append(effects.locals, assignment.Name)
		}
	}

	return true
}

func (w *hookSourceWalk) loopReadOnly(stmt *shellsyntax.Statement, state hookSourceState) bool {
	cmd := stmt.Commands[0]
	if _, supported, _ := w.unaryTest(stmt, state); supported {
		return true
	}

	if hookReadOnlyBracket(cmd, state) || hookCommandLookupProbe(cmd, state) || hookGitProbe(cmd, state) ||
		hookKnownStatus(stmt, state, "continue") || hookKnownStatus(stmt, state, "break") ||
		hookKnownStatus(stmt, state, ":") || hookKnownStatus(stmt, state, "true") || hookKnownStatus(stmt, state, "false") {
		return true
	}

	if len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	name, known := cmd.Words[0].Literal()
	if fn, defined := state.singleFunction(name); known && defined && len(cmd.Redirects) == 0 {
		return w.statusFunctionBody(fn.body, state)
	}

	if !known || state.hasFunction(name) {
		return false
	}

	if name == "exit" || name == "return" && state.canReturn {
		// Only fixed argument counts and syntax inside the loop body.
		for _, word := range cmd.Words[1:] {
			if _, fixed := word.Literal(); !fixed {
				return false
			}
		}

		return len(cmd.Redirects) == 0 && w.knownExitStatus(cmd.Words[1:], state)
	}

	return hookPipelineStage(cmd, state)
}

// A status-only function can be called on arbitrary loop inputs. Its body
// may branch on data and return a literal status, with no writes or commands
// that need their argument values resolved.
func (w *hookSourceWalk) statusFunctionBody(body *shellsyntax.File, state hookSourceState) bool {
	for _, stmt := range body.Statements {
		if !w.plugin.b.step() || stmt.Background || len(stmt.Commands) != 1 {
			return false
		}

		cmd := stmt.Commands[0]
		switch {
		case hookPlainCompound(cmd) && cmd.Group != nil:
			if !w.statusFunctionBody(cmd.Group, state) {
				return false
			}
		case hookPlainCompound(cmd) && cmd.Case != nil && hookTestOperand(cmd.Case.Word) && hookStaticCasePatterns(cmd.Case):
			for _, arm := range cmd.Alternatives {
				if !w.statusFunctionBody(arm, state) {
					return false
				}
			}
		case hookFixedReturn(cmd, state):
		default:
			return false
		}
	}

	return true
}

func hookFixedReturn(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) != 2 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 || state.hasFunction("return") {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	value, known := cmd.Words[1].Literal()

	return name == "return" && known && decimalDigits(value)
}

func hookVariableName(name string) bool {
	if name == "" {
		return false
	}

	for i, ch := range name {
		if ch != '_' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (i == 0 || ch < '0' || ch > '9') {
			return false
		}
	}

	return true
}
