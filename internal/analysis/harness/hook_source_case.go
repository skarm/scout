package harness

import (
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

// Keep a constant fallback separate from the unvalidated input arm when an
// immediately following arithmetic assignment reads the selector.
func (w *hookSourceWalk) numericCaseContinuation(e *entry, view source.View, stmts []*shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool) (hookSourceState, bool) {
	if w.splitNumericCase || !state.explicitBash || state.lookupUnknown || len(stmts) < 2 {
		return state, false
	}

	if !hookNumericCaseStatement(stmts[0]) || !hookNumericCaseStatement(stmts[1]) {
		return state, false
	}

	cmd, arith := stmts[0].Commands[0], stmts[1].Commands[0]
	if !hookPlainCompound(cmd) || cmd.Case == nil || len(cmd.Case.Patterns) != 1 || len(cmd.Alternatives) != 2 ||
		len(cmd.Alternatives[1].Statements) != 0 || len(arith.Assignments) != 1 || len(arith.Words) != 0 {
		return state, false
	}

	name := arith.Assignments[0].Name
	if !quotedGlobVariable(cmd.Case.Word, name) || !hookLocalVariable(name, pluginRootParameters[w.plugin.host]) ||
		w.decimalBinding(name, state) || state.readonly[name] {
		return state, false
	}

	operands := arithmeticOperands(arith.Assignments[0].Value)
	if !slices.ContainsFunc(operands, func(operand *shellsyntax.Word) bool {
		return len(operand.Parts) == 1 && operand.Parts[0].Kind == shellsyntax.PartArithmeticVariable && operand.Parts[0].Text == name
	}) || !hookStaticCasePatterns(cmd.Case) || !numericCaseFallback(cmd, name) {
		return state, false
	}

	if !slices.ContainsFunc(cmd.Case.Patterns[0], func(pattern *shellsyntax.Word) bool {
		value, literal := pattern.Literal()
		return literal && value == ""
	}) {
		return state, false
	}

	if _, known := w.value(cmd.Case.Word, state, true); known {
		return state, false
	}

	w.splitNumericCase = true
	defer func() { w.splitNumericCase = false }()

	arms := cmd.Alternatives
	fallback := w.commands(e, view, arms[0], state.clone(), chain, entrypoint)
	rest := &shellsyntax.File{Statements: stmts[1:]}
	matched := w.commands(e, view, rest, fallback, chain, entrypoint)
	unmatched := w.commands(e, view, rest, state, chain, entrypoint)

	return matched.join(unmatched), true
}

func hookNumericCaseStatement(stmt *shellsyntax.Statement) bool {
	return !stmt.Background && !stmt.Negated && stmt.Next != shellsyntax.Background && len(stmt.Commands) == 1
}

func numericCaseFallback(cmd *shellsyntax.Command, name string) bool {
	body := cmd.Alternatives[0].Statements
	if len(body) != 1 || body[0].Background || body[0].Negated || body[0].Next == shellsyntax.Background ||
		hookAndOrLink(body[0].Next) || len(body[0].Commands) != 1 {
		return false
	}

	set := body[0].Commands[0]
	if len(set.Words) != 0 || len(set.Assignments) != 1 || set.Assignments[0].Name != name ||
		len(set.Redirects) != 0 || set.Declaration != "" {
		return false
	}

	value, known := set.Assignments[0].Value.Literal()

	return known && decimalDigits(strings.TrimPrefix(value, "-"))
}

func (w *hookSourceWalk) caseStatement(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	if cmd.Case.Word.Writes {
		w.commandGap(e, view, cmd.Span, "hook_source_control_unverified", "The shell case selector has unverified effects.")
		return state.blockTrace()
	}

	w.traceWordSubstitutions(e, view, cmd.Case.Word, state, chain)

	value, known := w.value(cmd.Case.Word, state, true)
	if !known {
		return w.unknownCase(e, view, cmd, state, chain, entrypoint)
	}

	for i, patterns := range cmd.Case.Patterns {
		for _, pattern := range patterns {
			if !w.plugin.b.step() {
				return state.blockTrace()
			}

			matched, supported := casePattern(view, pattern, value)
			if !supported {
				return w.unknownCase(e, view, cmd, state, chain, entrypoint)
			}

			if matched {
				return w.commands(e, view, cmd.Alternatives[i], state, chain, entrypoint)
			}
		}
	}

	return state
}

func (w *hookSourceWalk) unknownCase(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	count := len(cmd.Alternatives)
	for i, patterns := range cmd.Case.Patterns {
		alwaysMatches := false

		for _, pattern := range patterns {
			if !w.plugin.b.step() {
				return state.blockTrace()
			}

			if !hookStaticCasePattern(pattern) {
				w.commandGap(e, view, pattern.Span, "hook_source_control_unverified", "The shell case pattern could not be determined statically.")
				return state.blockTrace()
			}

			alwaysMatches = alwaysMatches || view.Text()[pattern.Span.Start:pattern.Span.End] == "*"
		}

		if alwaysMatches {
			// A bare star also matches empty selectors. There is no path
			// past this arm, including the projected no-match alternative.
			count = i + 1
			break
		}
	}

	var merged *hookSourceState

	for _, arm := range cmd.Alternatives[:count] {
		next := w.commands(e, view, arm, state.clone(), chain, entrypoint)
		merged = mergeHookPath(merged, next)
	}

	return *merged
}

func casePattern(view source.View, word *shellsyntax.Word, value string) (bool, bool) {
	// Shell patterns treat slash as an ordinary character. Go's path.Match
	// has different semantics, so only infer the deliberately modeled forms.
	raw := view.Text()[word.Span.Start:word.Span.End]

	symbol := strings.IndexByte(value, 0)

	switch raw {
	case "*":
		return true, true
	case "-*":
		return strings.HasPrefix(value, "-"), symbol != 0
	case "*/*":
		contains := strings.ContainsRune(value, '/')
		return contains, contains || symbol < 0
	case `*\\*`:
		contains := strings.ContainsRune(value, '\\')
		return contains, contains || symbol < 0
	}

	if prefix, found := strings.CutSuffix(raw, "*"); found && prefix != "" && strings.Trim(prefix,
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._=-/") == "" {
		if symbol >= 0 && symbol < len(prefix) {
			return false, false
		}

		if strings.HasPrefix(value, prefix) {
			return true, true
		}

		size := min(len(value), len(prefix))

		head := value[:size]

		return false, strings.IndexFunc(head, func(r rune) bool { return r > 127 }) < 0 && !strings.EqualFold(head, prefix)
	}

	if suffix, found := strings.CutPrefix(raw, "*"); found && suffix != "" && strings.Trim(suffix,
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._=-/") == "" {
		if strings.HasSuffix(value, suffix) {
			return true, true
		}

		tail := value[max(0, len(value)-len(suffix)):]

		return false, (symbol < 0 || len(tail) == len(suffix) && !strings.ContainsRune(tail, 0)) &&
			strings.IndexFunc(tail, func(r rune) bool { return r > 127 }) < 0 && !strings.EqualFold(tail, suffix)
	}

	literal, known := word.Literal()
	if !known || symbol >= 0 {
		return false, false
	}

	if value == literal {
		return true, true
	}
	// An inherited nocasematch setting can affect literal comparisons.
	return false, !strings.EqualFold(value, literal)
}

func (w *hookSourceWalk) execShell(e *entry, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef) bool {
	if state.lookupUnknown || len(cmd.Words) < 2 {
		return false
	}

	name, known := w.value(cmd.Words[1], state, false)
	if !known && w.singleFieldRoot(e, state) && w.unquotedPluginPath(cmd.Words[1], state) {
		name, known = w.value(cmd.Words[1], state, true)
	}

	if !known || !hookSourceInterpreter(name) && !hookLocalLaunchPath(name, state.cwd) {
		return false
	}

	// Strip exec and use the existing local interpreter resolution. Keep
	// the original span so the edge points to the physical wrapper command.
	launch := *cmd
	launch.Words = cmd.Words[1:]

	if len(hookSourceOperands(launch.Words, name)) == 0 {
		return false
	}

	w.resolveCommand(e, view, &launch, name, state, chain)

	return true
}
