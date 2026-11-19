package harness

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

const (
	maxHookVariableFacts = 128
)

type hookVariableKind uint8

type hookVariableFact struct {
	fixedArraySize int
	kind           hookVariableKind
	notifierAction bool
	nonemptyArray  bool
}

const (
	hookDecimalScalar hookVariableKind = iota + 1
	hookIndexedArray
	hookDecimalArray
	hookFreshTemporary
	hookBunExecutable
)

func (fact hookVariableFact) indexedArray() bool {
	return fact.kind == hookIndexedArray || fact.kind == hookDecimalArray
}

func (s *hookSourceState) forgetAppendedArray(name string) {
	fact := s.kinds[name]
	if fact.indexedArray() {
		s.kinds[name] = hookVariableFact{kind: hookIndexedArray, nonemptyArray: fact.nonemptyArray}
	}
}

func (w *hookSourceWalk) hookSafeTest(cmd *shellsyntax.Command, state hookSourceState) bool {
	if !cmd.ReadOnlyTest || slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) }) {
		return false
	}

	return w.safeArithmeticOperands(cmd.NumericTest, state) && !slices.ContainsFunc(cmd.IndirectTest, func(name string) bool {
		return !w.plainIndirectReferent(name, state)
	})
}

func (w *hookSourceWalk) safeArithmeticOperands(operands []*shellsyntax.Word, state hookSourceState) bool {
	for _, operand := range operands {
		if len(operand.Parts) == 1 && operand.Parts[0].Kind == shellsyntax.PartParameterLength {
			if !state.kinds[operand.Parts[0].Text].nonemptyArray {
				return false
			}

			continue
		}

		if len(operand.Parts) == 1 && operand.Parts[0].Kind == shellsyntax.PartSubstitution {
			if !hookDecimalOutput(operand.Parts[0].Tree, state) {
				return false
			}

			continue
		}

		if len(operand.Parts) == 2 && operand.Parts[0].Kind == shellsyntax.PartLiteral && operand.Parts[0].Text == "10#" {
			if !hookDecimalClockField(operand.Parts[1].Tree, state) {
				return false
			}

			continue
		}

		part := operand.Parts[0]
		if part.Kind == shellsyntax.PartArithmeticVariable && strings.HasPrefix(state.vars[part.Text], "-") &&
			hookLocalVariable(part.Text, pluginRootParameters[w.plugin.host]) &&
			!state.lookupUnknown && decimalDigits(strings.TrimPrefix(state.vars[part.Text], "-")) {
			continue
		}

		if !w.decimalBinding(part.Text, state) {
			return false
		}
	}

	return true
}

func (w *hookSourceWalk) decimalBinding(name string, state hookSourceState) bool {
	return !state.lookupUnknown && hookLocalVariable(name, pluginRootParameters[w.plugin.host]) &&
		(state.kinds[name].kind == hookDecimalScalar || decimalDigits(state.vars[name]))
}

func (w *hookSourceWalk) hasUnverifiedExpansion(cmd *shellsyntax.Command, state hookSourceState) bool {
	if !hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	if len(cmd.Words) != 0 && len(cmd.Assignments) == 0 && cmd.Declaration == "" &&
		!slices.ContainsFunc(cmd.Redirects, func(redirect *shellsyntax.Redirect) bool { return !hookDiscardedOutput(redirect) }) {
		return slices.ContainsFunc(cmd.Words, func(word *shellsyntax.Word) bool {
			return word.Writes && !w.safeIndirectWord(word, state) && !w.safeArithmeticText(word, state) &&
				!(word.Quoted && w.safeArrayLookup(word, state))
		})
	}

	if len(cmd.Words) != 0 || len(cmd.Redirects) != 0 {
		return true
	}

	if cmd.Declaration == "local" && w.canBindLocals(cmd, state) {
		return slices.ContainsFunc(cmd.Assignments, func(a shellsyntax.Assignment) bool {
			return a.Value != nil && a.Value.Writes && !w.safeAssignmentExpansion(a, state)
		})
	}

	return len(cmd.Assignments) != 1 || cmd.Declaration != "" || !w.safeAssignmentExpansion(cmd.Assignments[0], state)
}

func (w *hookSourceWalk) safeAssignmentExpansion(assignment shellsyntax.Assignment, state hookSourceState) bool {
	if state.lookupUnknown || !hookLocalVariable(assignment.Name, pluginRootParameters[w.plugin.host]) {
		return false
	}

	operands := arithmeticOperands(assignment.Value)
	if operands != nil {
		return w.safeArithmeticOperands(operands, state)
	}

	return w.safeArrayLookup(assignment.Value, state) || w.safeIndirectWord(assignment.Value, state)
}

func (w *hookSourceWalk) safeArithmeticText(word *shellsyntax.Word, state hookSourceState) bool {
	hasArithmetic := false

	for _, part := range word.Parts {
		switch part.Kind {
		case shellsyntax.PartLiteral:
		case shellsyntax.PartParameter:
			if !part.Quoted || !part.PlainParameter || !hookVariableName(part.Text) || !w.decimalBinding(part.Text, state) {
				return false
			}
		case shellsyntax.PartArithmetic:
			if !part.Quoted || part.ArithmeticOperands == nil || !w.safeArithmeticOperands(part.ArithmeticOperands, state) {
				return false
			}

			hasArithmetic = true
		default:
			return false
		}
	}

	return hasArithmetic
}

func (w *hookSourceWalk) safeIndirectWord(word *shellsyntax.Word, state hookSourceState) bool {
	if word == nil || word.Expands {
		return false
	}

	found := false

	for _, part := range word.Parts {
		switch part.Kind {
		case shellsyntax.PartLiteral, shellsyntax.PartParameter:
		case shellsyntax.PartParameterIndirect:
			if !w.plainIndirectReferent(part.Text, state) {
				return false
			}

			found = true
		default:
			return false
		}
	}

	return found
}

func (w *hookSourceWalk) plainIndirectReferent(name string, state hookSourceState) bool {
	referent, known := state.vars[name]

	return !state.lookupUnknown && known && hookVariableName(referent) && hookLocalVariable(referent, pluginRootParameters[w.plugin.host])
}

func (w *hookSourceWalk) safeArrayLookup(word *shellsyntax.Word, state hookSourceState) bool {
	if word == nil || len(word.Parts) != 1 || word.Parts[0].ArrayIndex == nil {
		return false
	}

	part := word.Parts[0]
	if part.ArrayIndex.Decimal {
		return hookLocalVariable(part.Text, pluginRootParameters[w.plugin.host])
	}

	kind := state.kinds[part.Text].kind

	return (kind == hookIndexedArray || kind == hookDecimalArray) && w.safeArrayIndex(part.ArrayIndex, state)
}

func (w *hookSourceWalk) safeArrayIndex(index *shellsyntax.ArithmeticIndex, state hookSourceState) bool {
	if index.Inner != nil {
		return state.kinds[index.Name].kind == hookDecimalArray && w.safeArrayIndex(index.Inner, state)
	}

	return index.Decimal || w.decimalBinding(index.Name, state)
}

func arithmeticOperands(word *shellsyntax.Word) []*shellsyntax.Word {
	if word == nil || len(word.Parts) != 1 {
		return nil
	}

	return word.Parts[0].ArithmeticOperands
}

func (w *hookSourceWalk) refineDecimalGuard(stmt *shellsyntax.Statement, state *hookSourceState, success bool) {
	if len(stmt.Commands) != 1 || stmt.Background || stmt.Next == shellsyntax.Background || state.lookupUnknown {
		return
	}

	cmd := stmt.Commands[0]
	if success {
		w.refineIntegerComparison(cmd, state)
	}

	guard := cmd.DecimalGuard
	if guard == nil || len(cmd.Redirects) > 0 || success == guard.MatchOnFailure ||
		!hookLocalVariable(guard.Name, pluginRootParameters[w.plugin.host]) {
		return
	}

	if guard.RequiresC && state.vars["LC_ALL"] != "C" && state.vars["LC_ALL"] != "POSIX" {
		return
	}

	state.markDecimal(guard.Name)
}

// Bash's [ builtin accepts integer arguments for these operators. A successful
// comparison proves the contents can be reused as arithmetic data.
func (w *hookSourceWalk) refineIntegerComparison(cmd *shellsyntax.Command, state *hookSourceState) {
	if !state.explicitBash || len(cmd.Redirects) != 0 {
		return
	}

	expr, ok := hookBracketExpression(cmd, *state)
	if !ok || len(expr) != 3 || !hookSingleBracketWord(expr[0]) || !hookSingleBracketWord(expr[2]) {
		return
	}

	op, _ := expr[1].Literal()
	w.refineNonemptyArray(expr, op, state)

	switch op {
	case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
		w.markQuotedDecimal(expr[0], state)
		w.markQuotedDecimal(expr[2], state)
	}
}

func (w *hookSourceWalk) refineNonemptyArray(expr []*shellsyntax.Word, operator string, state *hookSourceState) {
	if operator != "-gt" || len(expr[0].Parts) != 1 || expr[0].Parts[0].Kind != shellsyntax.PartParameterLength {
		return
	}

	limit, _ := expr[2].Literal()
	name := expr[0].Parts[0].Text

	fact := state.kinds[name]
	if limit == "0" && (fact.kind == hookIndexedArray || fact.kind == hookDecimalArray) {
		fact.nonemptyArray = true
		state.kinds[name] = fact
	}
}

func (s *hookSourceState) markDecimal(name string) {
	s.markVariable(name, hookVariableFact{kind: hookDecimalScalar})
}

func (s *hookSourceState) markAssignmentKind(assignment shellsyntax.Assignment, kind hookVariableKind) {
	fact := hookVariableFact{kind: kind}
	if assignment.Value != nil && assignment.Value.IndexedArray {
		fact.fixedArraySize = assignment.Value.FixedArraySize
		fact.notifierAction = hookNotifierAction(assignment.Value.ArrayWords)
	}

	s.markVariable(assignment.Name, fact)
}

func (s *hookSourceState) markVariable(name string, fact hookVariableFact) {
	if s.readonly[name] || len(s.kinds) >= maxHookVariableFacts {
		return
	}

	if s.kinds == nil {
		s.kinds = make(map[string]hookVariableFact)
	}

	s.kinds[name] = fact
}

// Called after unaryTest has verified the builtin and its two operands.
func (w *hookSourceWalk) refineEmptyTest(cmd *shellsyntax.Command, state *hookSourceState, success bool) {
	operator, _ := cmd.Words[1].Literal()
	// A failed runtime lookup can already be empty. Preserve that fact so
	// it can merge with a branch that fills in the same runtime's path.
	if success == (operator == "-z") && !hookKnownBunVariable(cmd.Words[2], *state) {
		w.markQuotedDecimal(cmd.Words[2], state)
	}
}

func (w *hookSourceWalk) markQuotedDecimal(word *shellsyntax.Word, state *hookSourceState) {
	if len(word.Parts) != 1 {
		return
	}

	name := word.Parts[0].Text
	if quotedGlobVariable(word, name) && hookVariableName(name) && hookLocalVariable(name, pluginRootParameters[w.plugin.host]) {
		state.markDecimal(name)
	}
}

func decimalDigits(value string) bool {
	return value != "" && strings.Trim(value, "0123456789") == ""
}

func (w *hookSourceWalk) assignmentKind(word *shellsyntax.Word, state hookSourceState) hookVariableKind {
	if word == nil {
		return 0
	}

	if value, literal := word.Literal(); literal && (value == "" || decimalDigits(value)) {
		return hookDecimalScalar
	}

	if hookBunAssignment(word, state) {
		return hookBunExecutable
	}

	if word.IndexedArray {
		if word.DecimalElements {
			return hookDecimalArray
		}

		return hookIndexedArray
	}

	if !word.Expands && !word.Writes && len(word.Parts) == 1 {
		part := word.Parts[0]
		if part.Kind == shellsyntax.PartSubstitution && hookFreshTemporaryCommand(part.Tree, state) {
			return hookFreshTemporary
		}

		if part.Kind == shellsyntax.PartParameter && part.Text == "?" {
			return hookDecimalScalar
		}

		if part.Kind == shellsyntax.PartParameter && part.PlainParameter && w.decimalBinding(part.Text, state) {
			return hookDecimalScalar
		}
	}

	if arithmeticOperands(word) != nil || hookLengthExpansion(word) || !word.Expands && !word.Writes && w.hookNumericSubstitution(word, state) {
		return hookDecimalScalar
	}

	return 0
}

func hookFreshTemporaryCommand(tree *shellsyntax.File, state hookSourceState) bool {
	cmd, simple := simpleShellCommand(tree)
	if !simple || tree.OmittedExecution || state.lookupUnknown || state.hasFunction("mktemp") {
		return false
	}

	stmt := tree.Statements[0]
	if stmt.Negated || stmt.Background || len(cmd.Words) != 1 {
		return false
	}

	name, _ := cmd.Words[0].Literal()

	return name == "mktemp"
}

func hookLengthExpansion(word *shellsyntax.Word) bool {
	return !word.Writes && len(word.Parts) == 1 && word.Parts[0].Kind == shellsyntax.PartParameterLength
}

// A modeled wc -l pipeline produces a decimal count with optional leading
// blanks. An empty result also has no arithmetic side effects.
func (w *hookSourceWalk) hookNumericSubstitution(word *shellsyntax.Word, state hookSourceState) bool {
	var tree *shellsyntax.File

	for _, part := range word.Parts {
		switch {
		case part.Kind == shellsyntax.PartSubstitution && part.Tree != nil && tree == nil:
			tree = part.Tree
		case part.Kind == shellsyntax.PartLiteral && part.Text == "":
		default:
			return false
		}
	}

	return hookDecimalOutput(tree, state) || w.hookGrepCount(tree, state) || hookDecimalFunction(tree, state)
}

func (w *hookSourceWalk) hookGrepCount(tree *shellsyntax.File, state hookSourceState) bool {
	if tree == nil || len(tree.Statements) == 0 || len(tree.Statements) > 2 || state.lookupUnknown || state.hasFunction("grep") {
		return false
	}

	stmt := tree.Statements[0]
	if stmt.Background || stmt.Negated || len(stmt.Commands) != 1 {
		return false
	}

	if len(tree.Statements) == 2 && (stmt.Next != shellsyntax.OrElse || (!hookGrepZeroFallback(tree.Statements[1], state) && !hookKnownStatus(tree.Statements[1], state, "true"))) {
		return false
	}

	cmd := stmt.Commands[0]

	return w.hookGrepCountCommand(cmd, state)
}

func (w *hookSourceWalk) hookGrepCountCommand(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) < 4 || len(cmd.Words) > 5 || len(cmd.Assignments) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	option, _ := cmd.Words[1].Literal()

	if name != "grep" || (option != "-c" && option != "-cE" && option != "-Ec" && option != "-cF" && option != "-Fc") {
		return false
	}

	if len(cmd.Words) == 5 {
		separator, _ := cmd.Words[2].Literal()
		if separator != "--" || !hookTestOperand(cmd.Words[3]) || !hookTestOperand(cmd.Words[4]) {
			return false
		}
	} else if !w.hookGrepOperands(cmd.Words[2:], state) {
		return false
	}

	for _, redirect := range cmd.Redirects {
		if redirect.FD != shellsyntax.StderrFD || redirect.Op != shellsyntax.RedirectOutput || !hookDiscardedOutput(redirect) {
			return false
		}
	}

	return true
}

func (w *hookSourceWalk) hookGrepOperands(words []*shellsyntax.Word, state hookSourceState) bool {
	for _, word := range words {
		value, known := w.value(word, state, false)
		if !known || strings.HasPrefix(value, "-") {
			return false
		}
	}

	return true
}

func hookGrepZeroFallback(stmt *shellsyntax.Statement, state hookSourceState) bool {
	if stmt.Background || stmt.Negated || len(stmt.Commands) != 1 || state.hasFunction("echo") {
		return false
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) != 2 || len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	value, _ := cmd.Words[1].Literal()

	return name == "echo" && value == "0"
}

func hookCountPipeline(tree *shellsyntax.File, state hookSourceState) bool {
	if tree == nil || len(tree.Statements) != 1 || state.lookupUnknown || state.hasFunction("wc") {
		return false
	}

	stmt := tree.Statements[0]
	if stmt.Background || len(stmt.Commands) != 2 || len(stmt.Pipes) != 1 || stmt.Pipes[0] != shellsyntax.Pipe ||
		!hookCountInput(stmt.Commands[0], state) {
		return false
	}

	cmd := stmt.Commands[1]
	if len(cmd.Words) != 2 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	flag, _ := cmd.Words[1].Literal()

	return name == "wc" && flag == "-l"
}

func hookCountInput(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.hasFunction("printf") || len(cmd.Words) != 3 || len(cmd.Redirects) != 0 || len(cmd.Assignments) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	format, _ := cmd.Words[1].Literal()

	return name == "printf" && format == `%s\n` && hookTestOperand(cmd.Words[2])
}
