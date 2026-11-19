package harness

import (
	"slices"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

const (
	maxBoundedArrayItems   = 8
	maxPositionalCaseItems = 16
)

func (w *hookSourceWalk) applyArgumentLoop(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	root := pluginRootParameters[w.plugin.host]
	if state.lookupUnknown || !hookLocalVariable(cmd.ForArguments, root) || len(cmd.Redirects) != 0 || len(cmd.Alternatives) != 2 {
		return false
	}

	if slice := cmd.ForArraySlice; slice != nil &&
		(!hookLocalVariable(slice.Name, root) || slice.OffsetVariable != "" && !w.decimalBinding(slice.OffsetVariable, *state)) {
		return false
	}

	body := cmd.Alternatives[0]
	if cmd.ForPositional && w.applyPositionalCases(e, view, cmd.ForArguments, body, state, chain) {
		return true
	}

	effects := hookLoopEffects{writes: []string{cmd.ForArguments}}
	if !w.hookReadLoopWrites(body, &effects, *state, root) {
		if w.applyRuntimeLoop(e, view, cmd, state, chain) {
			return true
		}

		if w.applyBoundedArray(e, view, cmd, state, chain) {
			return true
		}

		if cmd.ForArray != "" && hookSingleCaseBody(body) {
			return w.traceLoopInvariant(e, view, cmd, body, []string{cmd.ForArguments}, state, chain)
		}

		callback := hookFileCallbackBody(body, cmd.ForArguments, *state)

		return callback != nil && w.traceLoopInvariant(e, view, cmd, callback, []string{cmd.ForArguments}, state, chain, "[", "continue")
	}

	w.traceSubstitutions(e, view, cmd, *state, chain)

	effects.forgetWrites(state)

	// The list may contain runtime arguments or glob results. Analyze all
	// loop bodies with the bindings they can change forgotten.
	w.traceReadLoopBody(e, view, body, *state, chain)

	return true
}

func (w *hookSourceWalk) applyRuntimeLoop(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	if len(cmd.ForWords) == 0 || w.boundedArrayDepth >= 2 {
		return false
	}

	args := w.arguments(cmd.ForWords, *state)
	if !args.exact || len(args.values) != len(cmd.ForWords) ||
		!slices.ContainsFunc(args.values, func(arg hookSourceArgument) bool {
			return arg.known && (hookRuntime(arg.value) != "" || hookUV(arg.value))
		}) {
		return false
	}

	w.traceSubstitutions(e, view, cmd, *state, chain)

	w.boundedArrayDepth++
	defer func() { w.boundedArrayDepth-- }()

	// The loop evaluates the entire list before running its first iteration.
	for _, arg := range args.values {
		state.bindValue(cmd.ForArguments, arg.value, arg.known)
		*state = w.commands(e, view, cmd.Alternatives[0], *state, chain, false)

		if state.exited || state.returned || state.traceBlocked || state.lookupUnknown {
			break
		}
	}

	return true
}

// An early file guard and trailing continue only skip the rest of the current
// iteration. Trace the callback with an unknown filename on the passing path.
func hookFileCallbackBody(body *shellsyntax.File, variable string, state hookSourceState) *shellsyntax.File {
	if len(body.Statements) != 4 {
		return nil
	}

	guard, skip, call, fallback := body.Statements[0], body.Statements[1], body.Statements[2], body.Statements[3]
	if !hookLoopFallthrough(guard, skip, state) || !hookLoopFallthrough(call, fallback, state) {
		return nil
	}

	test := guard.Commands[0]
	if len(test.Words) != 4 || !hookReadOnlyBracket(test, state) || !quotedGlobVariable(test.Words[2], variable) {
		return nil
	}

	operator, _ := test.Words[1].Literal()
	if operator != "-f" {
		return nil
	}

	invoke := *call
	invoke.Next = ""
	callback := &shellsyntax.File{Statements: []*shellsyntax.Statement{&invoke}}

	if _, known := state.singleFunction(hookReadCallbackName(callback)); !known {
		return nil
	}

	return callback
}

func hookLoopFallthrough(stmt, fallback *shellsyntax.Statement, state hookSourceState) bool {
	return !stmt.Negated && !stmt.Background && stmt.Next == shellsyntax.OrElse && len(stmt.Commands) == 1 &&
		!fallback.Negated && !hookAndOrLink(fallback.Next) && hookKnownStatus(fallback, state, "continue")
}

func hookSingleCaseBody(body *shellsyntax.File) bool {
	if len(body.Statements) != 1 {
		return false
	}

	stmt := body.Statements[0]
	if stmt.Background || stmt.Negated || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]

	return hookPlainCompound(cmd) && cmd.Case != nil && hookStaticCasePatterns(cmd.Case)
}

func (w *hookSourceWalk) applyBoundedArray(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	count := state.kinds[cmd.ForArray].fixedArraySize - 1
	if !state.explicitBash || count < 0 || count > maxBoundedArrayItems || w.boundedArrayDepth >= 2 {
		return false
	}

	w.boundedArrayDepth++
	defer func() { w.boundedArrayDepth-- }()

	// Shell expands the entire quoted list once. Its length is known even
	// when the individual elements depend on the launch environment.
	for range count {
		state.bindValue(cmd.ForArguments, "", false)
		*state = w.commands(e, view, cmd.Alternatives[0], *state, chain, false)

		if state.exited || state.returned || state.lookupUnknown {
			break
		}
	}

	return true
}

// A finite argv permits resolving an option loop without treating every arm
// as reachable. Validate all selected arms before updating caller bindings.
func (w *hookSourceWalk) applyPositionalCases(e *entry, view source.View, name string, body *shellsyntax.File, state *hookSourceState, chain []report.SourceRef) bool {
	args := state.positional
	if !args.exact || len(args.values) > maxPositionalCaseItems {
		return false
	}

	if len(args.values) == 0 {
		return true
	}

	selection := positionalCase(body, name)
	if selection == nil {
		return false
	}

	arms := make([]*shellsyntax.File, 0, len(args.values))
	root := pluginRootParameters[w.plugin.host]

	for _, arg := range args.values {
		if !arg.known || strings.IndexByte(arg.value, 0) >= 0 {
			return false
		}

		arm, resolved := w.positionalCaseArm(view, selection, arg.value)
		if !resolved || !w.plainOptionArm(arm, *state, root, nil) {
			return false
		}

		arms = append(arms, arm)
	}

	for i, arm := range arms {
		state.bindValue(name, args.values[i].value, true)
		*state = w.commands(e, view, arm, *state, chain, false)
	}

	return true
}

// Model a finite shift loop when each selected arm consumes a known number of arguments.
func (w *hookSourceWalk) applyShiftCaseLoop(e *entry, view source.View, cmd *shellsyntax.Command, state *hookSourceState, chain []report.SourceRef) bool {
	args := state.positional
	tested, maySplit := hookPositionalLoopTest(cmd.Prelude, *state)

	if cmd.Until || !hookPlainCompound(cmd) || !tested {
		return false
	}

	selection := positionalCase(cmd.Alternatives[0], "1")
	if selection == nil {
		return false
	}

	if !args.exact || len(args.values) > maxPositionalCaseItems || slices.ContainsFunc(args.values, func(arg hookSourceArgument) bool { return !arg.known }) {
		return w.summarizeShiftCaseLoop(selection, state)
	}

	root := pluginRootParameters[w.plugin.host]
	arms := make([]*shellsyntax.File, 0, len(args.values))

	for i := 0; i < len(args.values); {
		arm, consumed := w.shiftCaseArm(view, selection, args.values[i], *state, root)
		if consumed == 0 || consumed > len(args.values)-i {
			return false
		}

		arms = append(arms, arm)
		i += consumed
	}

	var earlyExit *hookSourceState

	for _, arm := range arms {
		if maySplit {
			// A changed IFS can make the unquoted count test fail early.
			earlyExit = mergeHookPath(earlyExit, state.clone())
		}

		*state = w.commands(e, view, arm, *state, chain, false)
	}

	if earlyExit != nil {
		*state = state.join(*earlyExit)
	}

	return true
}

// Unknown argv can select any arm. Keep unrelated bindings only when each
// arm is limited to local data assignments, a shift, and an optional break.
func (w *hookSourceWalk) summarizeShiftCaseLoop(selection *shellsyntax.Command, state *hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("shift") || !hookStaticCasePatterns(selection.Case) {
		return false
	}

	root := pluginRootParameters[w.plugin.host]
	effects := hookLoopEffects{}

	for _, arm := range selection.Alternatives[:len(selection.Case.Patterns)] {
		if !w.plugin.b.step() {
			return false
		}

		prefix := hookShiftLoopPrefix(arm, *state)
		if prefix == nil || !w.plainOptionArm(prefix, *state, root, &effects) {
			return false
		}
	}

	effects.forgetWrites(state)
	state.positional = hookSourceArguments{}

	return true
}

func hookShiftLoopPrefix(arm *shellsyntax.File, state hookSourceState) *shellsyntax.File {
	stmts := arm.Statements
	if len(stmts) == 0 {
		return nil
	}

	last := stmts[len(stmts)-1]
	if !last.Negated && !hookAndOrLink(last.Next) && hookKnownStatus(last, state, "break") {
		stmts = stmts[:len(stmts)-1]
		if len(stmts) == 0 {
			return nil
		}

		last = stmts[len(stmts)-1]
	}

	if last.Background || last.Next == shellsyntax.Background || last.Negated || hookAndOrLink(last.Next) ||
		len(last.Commands) != 1 || hookShiftCount(last.Commands[0]) == 0 {
		return nil
	}

	return &shellsyntax.File{Statements: stmts[:len(stmts)-1]}
}

func (w *hookSourceWalk) shiftCaseArm(view source.View, selection *shellsyntax.Command, arg hookSourceArgument, state hookSourceState, root string) (*shellsyntax.File, int) {
	if !arg.known || strings.IndexByte(arg.value, 0) >= 0 {
		return nil, 0
	}

	arm, known := w.positionalCaseArm(view, selection, arg.value)
	if !known || len(arm.Statements) == 0 {
		return nil, 0
	}

	i := len(arm.Statements) - 1
	stmt := arm.Statements[i]

	if stmt.Background || stmt.Next == shellsyntax.Background || stmt.Negated || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 ||
		state.lookupUnknown || state.hasFunction("shift") {
		return nil, 0
	}

	count := hookShiftCount(stmt.Commands[0])
	if count == 0 || !w.plainOptionArm(&shellsyntax.File{Statements: arm.Statements[:i]}, state, root, nil) {
		return nil, 0
	}

	return arm, count
}

func hookShiftCount(cmd *shellsyntax.Command) int {
	if len(cmd.Words) == 0 || len(cmd.Words) > 2 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return 0
	}

	name, _ := cmd.Words[0].Literal()
	if name != "shift" {
		return 0
	}

	if len(cmd.Words) == 1 {
		return 1
	}

	value, literal := cmd.Words[1].Literal()
	if !literal || !decimalDigits(value) {
		return 0
	}

	count, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}

	return count
}

func hookPositionalLoopTest(t *shellsyntax.File, state hookSourceState) (recognized, maySplit bool) {
	if len(t.Statements) != 1 {
		return false, false
	}

	stmt := t.Statements[0]
	if stmt.Background || stmt.Negated || hookAndOrLink(stmt.Next) || len(stmt.Commands) != 1 {
		return false, false
	}

	test := stmt.Commands[0]

	if test.PositionalNonempty && hookPlainCompound(test) {
		return true, false
	}

	expr, ok := hookBracketExpression(test, state)
	if !ok || len(expr) != 3 || len(test.Redirects) != 0 {
		return false, false
	}

	left := expr[0]
	if left.Writes || left.Expands || len(left.Parts) != 1 || left.Parts[0].Kind != shellsyntax.PartParameter || left.Parts[0].Text != "#" {
		return false, false
	}

	op, _ := expr[1].Literal()
	right, _ := expr[2].Literal()

	return op == "-gt" && right == "0", !left.Parts[0].Quoted
}

func positionalCase(body *shellsyntax.File, name string) *shellsyntax.Command {
	if len(body.Statements) != 1 {
		return nil
	}

	stmt := body.Statements[0]
	if len(stmt.Commands) != 1 || stmt.Background || stmt.Negated {
		return nil
	}

	cmd := stmt.Commands[0]
	if cmd.Case == nil || !hookPlainCompound(cmd) || !quotedGlobVariable(cmd.Case.Word, name) {
		return nil
	}

	return cmd
}

func (w *hookSourceWalk) positionalCaseArm(view source.View, cmd *shellsyntax.Command, value string) (*shellsyntax.File, bool) {
	for i, choices := range cmd.Case.Patterns {
		for _, pattern := range choices {
			if !w.plugin.b.step() {
				return nil, false
			}

			match, known := casePattern(view, pattern, value)
			if !known {
				return nil, false
			}

			if match {
				return cmd.Alternatives[i], true
			}
		}
	}

	return cmd.Alternatives[len(cmd.Case.Patterns)], true
}

func (w *hookSourceWalk) plainOptionArm(arm *shellsyntax.File, state hookSourceState, root string, effects *hookLoopEffects) bool {
	for _, stmt := range arm.Statements {
		if !w.plugin.b.step() || len(stmt.Commands) != 1 || stmt.Background || stmt.Negated || hookAndOrLink(stmt.Next) {
			return false
		}

		if hookKnownStatus(stmt, state, ":") {
			continue
		}

		cmd := stmt.Commands[0]
		if cmd.ExclusiveBranches && hookPlainCompound(cmd) && hookOptionGuard(cmd.Prelude, state, effects) {
			for _, branch := range cmd.Alternatives {
				if !w.plainOptionArm(branch, state, root, effects) {
					return false
				}
			}

			continue
		}

		if len(cmd.Assignments) == 0 || len(cmd.Words) != 0 || len(cmd.Redirects) != 0 ||
			cmd.Declaration != "" || hookCommandWritesDuringExpansion(cmd) {
			return false
		}

		for _, assignment := range cmd.Assignments {
			if !hookLocalVariable(assignment.Name, root) {
				return false
			}
		}

		if effects != nil && (hookLoopSubstitutions(cmd) || !w.recordLoopWrites(cmd, effects, state, root)) {
			return false
		}
	}

	return true
}

func hookOptionGuard(prelude *shellsyntax.File, state hookSourceState, effects *hookLoopEffects) bool {
	if prelude == nil || len(prelude.Statements) != 1 {
		return false
	}

	stmt := prelude.Statements[0]
	if stmt.Background || stmt.Next == shellsyntax.Background || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]

	return hookReadOnlyBracket(cmd, state) && (effects == nil || !hookLoopSubstitutions(cmd))
}

func hookStaticCasePatterns(selection *shellsyntax.CaseSelection) bool {
	for _, patterns := range selection.Patterns {
		for _, pattern := range patterns {
			if !hookStaticCasePattern(pattern) {
				return false
			}
		}
	}

	return true
}

func hookStaticCasePattern(pattern *shellsyntax.Word) bool {
	return !pattern.Writes && !slices.ContainsFunc(pattern.Parts, func(part shellsyntax.Part) bool {
		switch part.Kind {
		case shellsyntax.PartLiteral, shellsyntax.PartParameter, shellsyntax.PartParameterDefaultDot, shellsyntax.PartParameterDefaultEmpty, shellsyntax.PartParameterTrimNewline,
			shellsyntax.PartParameterScriptDir, shellsyntax.PartParameterReplaceAll, shellsyntax.PartParameterBashSource:
			return false
		default:
			return true
		}
	})
}

func (w *hookSourceWalk) replaceArguments(words []*shellsyntax.Word, state *hookSourceState) bool {
	if state.lookupUnknown || len(words) == 0 {
		return false
	}

	separator, _ := words[0].Literal()
	if separator != "--" {
		return false
	}

	// Following words are operands even when their runtime contents start
	// with a dash. A splitting expansion leaves the resulting argv unknown.
	state.positional = w.arguments(words[1:], *state)

	return true
}
