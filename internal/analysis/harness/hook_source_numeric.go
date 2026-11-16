package harness

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

type hookVariableKind uint8

type hookVariableFact struct {
	kind           hookVariableKind
	fixedArraySize int
}

const (
	hookDecimalScalar hookVariableKind = iota + 1
	hookIndexedArray
	hookDecimalArray
)

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
		if len(operand.Parts) == 1 && operand.Parts[0].Kind == "substitution" {
			if !hookDecimalOutput(operand.Parts[0].Tree, state) {
				return false
			}

			continue
		}

		if len(operand.Parts) == 2 && operand.Parts[0].Kind == "literal" && operand.Parts[0].Text == "10#" {
			if !hookDecimalClockField(operand.Parts[1].Tree, state) {
				return false
			}

			continue
		}

		if !w.decimalBinding(operand.Parts[0].Text, state) {
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
			return word.Writes && !w.safeIndirectWord(word, state) && !w.safeArithmeticText(word, state)
		})
	}

	if len(cmd.Assignments) != 1 || len(cmd.Words) != 0 || len(cmd.Redirects) != 0 || cmd.Declaration != "" {
		return true
	}

	assignment := cmd.Assignments[0]
	if state.lookupUnknown || !hookLocalVariable(assignment.Name, pluginRootParameters[w.plugin.host]) {
		return true
	}

	operands := arithmeticOperands(assignment.Value)
	if operands != nil {
		return !w.safeArithmeticOperands(operands, state)
	}

	return !w.safeArrayLookup(assignment.Value, state) && !w.safeIndirectWord(assignment.Value, state)
}

func (w *hookSourceWalk) safeArithmeticText(word *shellsyntax.Word, state hookSourceState) bool {
	hasArithmetic := false

	for _, part := range word.Parts {
		switch part.Kind {
		case "literal":
		case "parameter":
			if !part.Quoted || !part.PlainParameter || !hookVariableName(part.Text) || !w.decimalBinding(part.Text, state) {
				return false
			}
		case "arithmetic":
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
		case "literal", "parameter":
		case "parameter_indirect":
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
	if len(stmt.Commands) != 1 || stmt.Background || stmt.Next == "&" || state.lookupUnknown {
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
	switch op {
	case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
		w.markQuotedDecimal(expr[0], state)
		w.markQuotedDecimal(expr[2], state)
	}
}

func (s *hookSourceState) markDecimal(name string) {
	s.markVariable(name, hookVariableFact{kind: hookDecimalScalar})
}

func (s *hookSourceState) markAssignmentKind(assignment shellsyntax.Assignment, kind hookVariableKind) {
	fact := hookVariableFact{kind: kind}
	if assignment.Value != nil && assignment.Value.IndexedArray {
		fact.fixedArraySize = assignment.Value.FixedArraySize
	}

	s.markVariable(assignment.Name, fact)
}

func (s *hookSourceState) markVariable(name string, fact hookVariableFact) {
	if s.readonly[name] || len(s.kinds) >= 128 {
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
	if success == (operator == "-z") {
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

	if word.IndexedArray {
		if word.DecimalElements {
			return hookDecimalArray
		}

		return hookIndexedArray
	}

	if !word.Expands && !word.Writes && len(word.Parts) == 1 {
		part := word.Parts[0]
		if part.Kind == "parameter" && part.Text == "?" {
			return hookDecimalScalar
		}
	}

	if arithmeticOperands(word) != nil || hookLengthExpansion(word) || !word.Expands && !word.Writes && w.hookNumericSubstitution(word, state) {
		return hookDecimalScalar
	}

	return 0
}

func hookLengthExpansion(word *shellsyntax.Word) bool {
	return !word.Writes && len(word.Parts) == 1 && word.Parts[0].Kind == "parameter_length"
}

// A modeled wc -l pipeline produces a decimal count with optional leading
// blanks. An empty result also has no arithmetic side effects.
func (w *hookSourceWalk) hookNumericSubstitution(word *shellsyntax.Word, state hookSourceState) bool {
	var tree *shellsyntax.File

	for _, part := range word.Parts {
		switch {
		case part.Kind == "substitution" && part.Tree != nil && tree == nil:
			tree = part.Tree
		case part.Kind == "literal" && part.Text == "":
		default:
			return false
		}
	}

	return hookDecimalOutput(tree, state) || w.hookGrepCount(tree, state)
}

func (w *hookSourceWalk) hookGrepCount(tree *shellsyntax.File, state hookSourceState) bool {
	if tree == nil || len(tree.Statements) == 0 || len(tree.Statements) > 2 || state.lookupUnknown || state.hasFunction("grep") {
		return false
	}

	stmt := tree.Statements[0]
	if stmt.Background || stmt.Negated || len(stmt.Commands) != 1 {
		return false
	}

	if len(tree.Statements) == 2 && (stmt.Next != "||" || (!hookGrepZeroFallback(tree.Statements[1], state) && !hookKnownStatus(tree.Statements[1], state, "true"))) {
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
		if redirect.FD != "2" || redirect.Op != ">" || !hookDiscardedOutput(redirect) {
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
	if stmt.Background || len(stmt.Commands) != 2 || len(stmt.Pipes) != 1 || stmt.Pipes[0] != "|" ||
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
