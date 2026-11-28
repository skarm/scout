package hooktrace

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

func (s hookSourceState) clone() hookSourceState {
	if !s.work.Spend(len(s.vars) + len(s.kinds) + len(s.locals) + len(s.readonly) + len(s.functions) + len(s.trapFunctions)) {
		return hookSourceState{work: s.work}.blockTrace()
	}

	s.vars = maps.Clone(s.vars)
	s.kinds = maps.Clone(s.kinds)
	s.locals = maps.Clone(s.locals)
	s.readonly = maps.Clone(s.readonly)
	s.functions = maps.Clone(s.functions)
	s.trapFunctions = maps.Clone(s.trapFunctions)

	return s
}

func (s hookSourceState) child() hookSourceState {
	s = s.clone()
	s.returned, s.returns = false, nil

	return s
}

func (s hookSourceState) resume(caller hookSourceState) hookSourceState {
	if s.returns != nil {
		if s.exited || s.traceBlocked {
			s = s.returns.clone()
		} else {
			s = s.joinBindings(*s.returns)
		}
	}

	s.returned, s.returns = false, caller.returns

	return s
}

func (s hookSourceState) join(other hookSourceState) hookSourceState {
	if s.work.Stopped() {
		return hookSourceState{work: s.work}.blockTrace()
	}

	returns := s.returns
	if other.returns != nil && other.returns != returns {
		returns = mergeHookReturn(returns, other.returns.clone())
	}

	s.returns, other.returns = returns, returns
	switch {
	case s.traceBlocked != other.traceBlocked:
		// The blocked branch already leaves a coverage diagnostic. Its
		// unknown state cannot invalidate a separately traced path.
		if s.traceBlocked {
			return other
		}

		return s
	case s.exited != other.exited:
		if s.exited {
			return other
		}

		return s
	case s.returned != other.returned:
		if s.returned {
			s, other = other, s
		}

		s.returns = mergeHookReturn(returns, other)

		return s
	default:
		return s.joinBindings(other)
	}
}

func mergeHookReturn(previous *hookSourceState, next hookSourceState) *hookSourceState {
	next.returns = nil
	if previous != nil {
		next = next.joinBindings(*previous)
	}

	return &next
}

func (s hookSourceState) joinBindings(other hookSourceState) hookSourceState {
	// Reserve all map passes before mutating either branch's bindings.
	cost := len(s.vars) + len(s.kinds) + len(s.functions) + len(other.functions) + len(other.trapFunctions) + len(other.readonly)
	if !s.lookupUnknown && !other.lookupUnknown && s.locals != nil && other.locals != nil {
		cost += len(s.locals) + len(other.locals)
	}

	if !s.work.Spend(cost) {
		return hookSourceState{work: s.work}.blockTrace()
	}

	if s.cwd != other.cwd {
		s.cwd = ""
	}

	if s.scriptPath != other.scriptPath {
		s.scriptPath = ""
	}

	if s.sourcePath != other.sourcePath {
		s.sourcePath = ""
	}

	s.explicitBash = s.explicitBash && other.explicitBash
	s.noglob = s.noglob && other.noglob
	s.hookOutput = s.hookOutput && other.hookOutput

	if !slices.Equal(s.positional.values, other.positional.values) {
		s.positional = hookSourceArguments{}
	} else {
		s.positional.exact = s.positional.exact && other.positional.exact
	}

	s.lookupUnknown = s.lookupUnknown || other.lookupUnknown

	s.rootUnknown = s.rootUnknown || other.rootUnknown

	s.trapCommands |= other.trapCommands
	if s.trapFunctions == nil {
		s.trapFunctions = maps.Clone(other.trapFunctions)
	} else {
		maps.Copy(s.trapFunctions, other.trapFunctions)
	}

	for key, value := range s.vars {
		if next, ok := other.vars[key]; !ok || next != value {
			delete(s.vars, key)
		}
	}

	for key, kind := range s.kinds {
		next := other.kinds[key]
		if merged, known := mergeNotifierOptions(kind, next); known {
			s.kinds[key] = merged
		} else if next != kind {
			delete(s.kinds, key)
		}
	}

	s.joinFunctions(other)
	s.joinLocals(other)
	s.joinReadonly(other.readonly)

	return s
}

func (s *hookSourceState) joinReadonly(other map[string]bool) {
	if s.readonly == nil {
		s.readonly = maps.Clone(other)
		return
	}

	maps.Copy(s.readonly, other)

	if len(s.readonly) > maxHookLocals {
		*s = s.opaque()
	}
}

func (s *hookSourceState) joinFunctions(other hookSourceState) {
	for name, definitions := range s.functions {
		s.functions[name] = joinHookFunctionChoices(definitions, other.functions[name])
	}

	for name := range other.functions {
		if _, ok := s.functions[name]; !ok {
			if s.functions == nil {
				s.functions = make(map[string][]hookSourceFunction)
			}

			// A branch may leave the name unbound. It could then invoke
			// an external command, so its dispatch is still unresolved.
			s.functions[name] = nil
		}
	}
}

func (s hookSourceState) hasFunction(name string) bool {
	_, defined := s.functions[name]

	return defined
}

func (s hookSourceState) singleFunction(name string) (hookSourceFunction, bool) {
	if definitions := s.functions[name]; len(definitions) == 1 {
		return definitions[0], true
	}

	return hookSourceFunction{}, false
}

func mergeHookPath(previous *hookSourceState, state hookSourceState) *hookSourceState {
	if previous != nil {
		state = state.join(*previous)
	}

	return &state
}

func hookAndOrLink(next string) bool {
	return next == "&&" || next == "||"
}

func hookAndOrEnd(stmts []*shellsyntax.Statement) int {
	end := 0
	for end+1 < len(stmts) && hookAndOrLink(stmts[end].Next) {
		end++
	}

	return end
}

type hookOutcomes struct {
	success, failure, stopped *hookSourceState
}

func (o hookOutcomes) merged() *hookSourceState {
	merged := o.stopped
	if o.success != nil {
		merged = mergeHookPath(merged, *o.success)
	}

	if o.failure != nil {
		merged = mergeHookPath(merged, *o.failure)
	}

	return merged
}

// The shell evaluates && and || left to right. A bypassed operand retains
// the status and bindings of the last command actually evaluated on that path.
func (w *hookSourceWalk) andOr(e *File, view source.View, stmts []*shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookOutcomes {
	out := hookOutcomes{success: &state}
	link := "&&"

	for _, stmt := range stmts {
		active := &out.success
		if link == "||" {
			active = &out.failure
		}

		link = stmt.Next

		if *active == nil {
			continue
		}

		current := **active
		*active = nil

		if !w.trace.work.Spend(1) {
			out.stopped = mergeHookPath(out.stopped, current.blockTrace())
			break
		}

		w.routeOperand(e, view, stmt, current, chain, entrypoint, &out)
	}

	return out
}

func (w *hookSourceWalk) routeOperand(e *File, view source.View, stmt *shellsyntax.Statement, state hookSourceState, chain []report.SourceRef, entrypoint bool, out *hookOutcomes) {
	if stmt.Negated {
		operand := *stmt
		operand.Negated = false

		var inverted hookOutcomes

		w.routeOperand(e, view, &operand, state, chain, entrypoint, &inverted)

		if inverted.success != nil {
			out.failure = mergeHookPath(out.failure, *inverted.success)
		}

		if inverted.failure != nil {
			out.success = mergeHookPath(out.success, *inverted.failure)
		}

		if inverted.stopped != nil {
			out.stopped = mergeHookPath(out.stopped, *inverted.stopped)
		}

		return
	}

	next := state.clone()
	if next.traceBlocked {
		out.stopped = mergeHookPath(out.stopped, next)
		return
	}

	if truth, supported, known := w.unaryTest(stmt, state); supported {
		if !known || truth {
			success := next.clone()
			w.refineEmptyTest(stmt.Commands[0], &success, true)
			out.success = mergeHookPath(out.success, success)
		}

		if !known || !truth {
			w.refineEmptyTest(stmt.Commands[0], &next, false)
			out.failure = mergeHookPath(out.failure, next)
		}

		return
	}

	if equal, known := w.stringComparison(stmt, state); known {
		if equal {
			out.success = mergeHookPath(out.success, next)
		} else {
			out.failure = mergeHookPath(out.failure, next)
		}

		return
	}

	if hookKnownStatus(stmt, state, "cd") && !hookCommandWritesDuringExpansion(stmt.Commands[0]) {
		next.changeDirectory(w.directory(stmt.Commands[0].Words[1:], state))
		out.success = mergeHookPath(out.success, next)
		out.failure = mergeHookPath(out.failure, state)

		return
	}

	if !w.statement(e, view, stmt, chain, entrypoint, &next) {
		out.stopped = mergeHookPath(out.stopped, next)
		return
	}

	if !hookKnownStatus(stmt, state, "false") {
		success := next.clone()
		w.refineDecimalGuard(stmt, &success, true)
		out.success = mergeHookPath(out.success, success)
	}

	switch {
	case hookKnownStatus(stmt, state, "true"), hookKnownStatus(stmt, state, ":"):
	default:
		w.refineDecimalGuard(stmt, &next, false)
		out.failure = mergeHookPath(out.failure, next)
	}
}

func (w *hookSourceWalk) unaryTest(stmt *shellsyntax.Statement, state hookSourceState) (truth, supported, known bool) {
	if len(stmt.Commands) != 1 || stmt.Background || stmt.Next == shellsyntax.Background {
		return false, false, false
	}

	expr, ok := hookBracketExpression(stmt.Commands[0], state)
	if !ok || len(expr) != 2 || !hookTestOperand(expr[1]) {
		return false, false, false
	}

	operator, _ := expr[0].Literal()
	if operator != "-n" && operator != "-z" {
		return false, false, false
	}

	// Redirect failure can change the exit status even for a known operand.
	if len(stmt.Commands[0].Redirects) != 0 {
		return false, false, false
	}

	value, known := w.value(expr[1], state, false)
	truth = (value != "") == (operator == "-n")

	return truth != stmt.Negated, true, known
}

func (w *hookSourceWalk) stringComparison(stmt *shellsyntax.Statement, state hookSourceState) (truth, known bool) {
	if !state.explicitBash || len(stmt.Commands) != 1 || stmt.Background || stmt.Next == shellsyntax.Background || len(stmt.Commands[0].Redirects) != 0 {
		return false, false
	}

	expr, ok := hookBracketExpression(stmt.Commands[0], state)
	if !ok || len(expr) != 3 || !hookTestOperand(expr[0]) || !hookTestOperand(expr[2]) {
		return false, false
	}

	op, _ := expr[1].Literal()
	if op != "=" && op != "!=" {
		return false, false
	}

	left, leftKnown := w.value(expr[0], state, false)
	right, rightKnown := w.value(expr[2], state, false)

	return (left == right) == (op == "="), leftKnown && rightKnown &&
		strings.IndexByte(left, 0) < 0 && strings.IndexByte(right, 0) < 0
}

func hookBracketExpression(cmd *shellsyntax.Command, state hookSourceState) ([]*shellsyntax.Word, bool) {
	if state.lookupUnknown || len(cmd.Words) < 2 || len(cmd.Assignments) != 0 || state.hasFunction("[") ||
		slices.ContainsFunc(cmd.Redirects, func(r *shellsyntax.Redirect) bool { return !hookDiscardedOutput(r) }) {
		return nil, false
	}

	// The declaration projection marks an unquoted '[' as a potential glob.
	head, tail := cmd.Words[0], cmd.Words[len(cmd.Words)-1]
	end, _ := tail.Literal()

	if len(head.Parts) != 1 || head.Parts[0].Kind != shellsyntax.PartLiteral || head.Parts[0].Text != "[" || end != "]" {
		return nil, false
	}

	return cmd.Words[1 : len(cmd.Words)-1], true
}

func hookReadOnlyBracket(cmd *shellsyntax.Command, state hookSourceState) bool {
	expr, ok := hookBracketExpression(cmd, state)
	if !ok {
		return false
	}

	if len(expr) > 1 {
		if leading, _ := expr[0].Literal(); leading == "!" {
			expr = expr[1:]
		}
	}

	switch len(expr) {
	case 0:
		return true
	case 1:
		return hookSingleBracketWord(expr[0])
	case 2:
		op, _ := expr[0].Literal()

		switch op {
		case "-n", "-z", "-e", "-a", "-f", "-d", "-r", "-w", "-x", "-L", "-h", "-s", "-p", "-S",
			"-b", "-c", "-g", "-G", "-k", "-N", "-O", "-t", "-u":
			return hookSingleBracketWord(expr[1])
		}

	case 3:
		op, _ := expr[1].Literal()

		switch op {
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			// Length, argument count and status expansions supply only
			// digits. Splitting cannot introduce another test operator.
			if hookUnsignedExpansion(expr[0]) && hookLiteralDecimal(expr[2]) ||
				hookLiteralDecimal(expr[0]) && hookUnsignedExpansion(expr[2]) {
				return true
			}

			return hookSingleBracketWord(expr[0]) && hookSingleBracketWord(expr[2])
		case "=", "==", "!=", "-nt", "-ot", "-ef":
			return hookSingleBracketWord(expr[0]) && hookSingleBracketWord(expr[2])
		}
	}

	return false
}

func hookUnsignedExpansion(word *shellsyntax.Word) bool {
	if hookLengthExpansion(word) {
		return true
	}

	if word.Writes || word.Expands || len(word.Parts) != 1 {
		return false
	}

	part := word.Parts[0]

	return part.Kind == shellsyntax.PartParameter && part.PlainParameter && (part.Text == "?" || part.Text == "#")
}

func hookLiteralDecimal(word *shellsyntax.Word) bool {
	value, known := word.Literal()
	return known && decimalDigits(value)
}

func hookSingleBracketWord(word *shellsyntax.Word) bool {
	if word.Writes {
		return false
	}

	// One argument is a string test. Do not use that rule for expansions
	// that can introduce more than one field.
	_, literal := word.Literal()

	return literal || hookFixedArgument(word) || hookQuotedScalarOperand(word)
}

func hookQuotedScalarOperand(word *shellsyntax.Word) bool {
	if word.Writes || len(word.Parts) == 0 {
		return false
	}

	for _, part := range word.Parts {
		if part.Kind == shellsyntax.PartLiteral {
			if !part.Quoted && strings.ContainsAny(part.Text, "*?[~{}") {
				return false
			}

			continue
		}

		if !part.Quoted {
			return false
		}

		switch part.Kind {
		case shellsyntax.PartParameter, shellsyntax.PartParameterDefaultEmpty, shellsyntax.PartParameterDefaultDot, shellsyntax.PartParameterScriptDir, shellsyntax.PartParameterBashSource, shellsyntax.PartParameterLength, shellsyntax.PartSubstitution:
			if part.Text == "@" || part.Text == "*" || part.Kind == shellsyntax.PartParameter && word.Expands {
				return false
			}
		case shellsyntax.PartParameterValue:
			if !part.SingleField {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func hookGitProbe(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("git") || len(cmd.Assignments) != 0 ||
		(len(cmd.Words) != 3 && len(cmd.Words) != 5) {
		return false
	}

	verb, _ := cmd.Words[0].Literal()
	if verb != "git" || slices.ContainsFunc(cmd.Redirects, func(redirect *shellsyntax.Redirect) bool { return !hookDiscardedOutput(redirect) }) {
		return false
	}

	first, _ := cmd.Words[1].Literal()
	second, _ := cmd.Words[2].Literal()

	if len(cmd.Words) == 3 {
		return first == "rev-parse" && second == "--git-dir"
	}

	third, _ := cmd.Words[3].Literal()

	switch first {
	case "-C":
		last, _ := cmd.Words[4].Literal()
		return hookTestOperand(cmd.Words[2]) && third == "rev-parse" && last == "--git-dir"
	case "rev-parse":
		return second == "--verify" && third == "--quiet" && hookTestOperand(cmd.Words[4])
	default:
		return false
	}
}

func hookReadOnlyPipeline(stmt *shellsyntax.Statement, state hookSourceState) bool {
	if state.lookupUnknown || len(stmt.Commands) < 2 || len(stmt.Pipes) != len(stmt.Commands)-1 {
		return false
	}

	// The final stage may execute in the caller under lastpipe. Only
	// classify commands that cannot change its shell bindings.
	for _, cmd := range stmt.Commands {
		if !hookPipelineStage(cmd, state) {
			return false
		}
	}

	return true
}

func hookPipelineStage(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || hookCommandWritesDuringExpansion(cmd) {
		return false
	}

	name, known := cmd.Words[0].Literal()
	if !known || state.hasFunction(name) {
		return false
	}

	switch name {
	case "cat", "cut", "echo", "grep", "head", "ls", "tail", "tr", "wc":
	case "cmp":
		if len(cmd.Words) != 4 {
			return false
		}

		option, _ := cmd.Words[1].Literal()
		if option != "-s" || !hookTestOperand(cmd.Words[2]) || !hookTestOperand(cmd.Words[3]) {
			return false
		}
	case "jq":
		if !hookJQReadOnlyPredicate(cmd.Words[1:], state) {
			return false
		}
	case "git":
		return hookGitProbe(cmd, state) || hookGitNameOnlyDiff(cmd)
	case "printf":
		if len(cmd.Words) < 2 {
			return false
		}

		format, constant := cmd.Words[1].Literal()
		if !constant || !hookReadOnlyPrintf(format) {
			return false
		}
	default:
		return false
	}

	for _, redirect := range cmd.Redirects {
		if !hookDiscardedOutput(redirect) {
			return false
		}
	}

	return true
}

func hookGitNameOnlyDiff(cmd *shellsyntax.Command) bool {
	words := cmd.Words[1:]
	if len(words) == 4 {
		option, _ := words[0].Literal()
		if option != "-C" || !hookTestOperand(words[1]) {
			return false
		}

		words = words[2:]
	}

	if len(words) != 2 || !hookDecimalRedirects(cmd, false) {
		return false
	}

	verb, _ := words[0].Literal()
	format, _ := words[1].Literal()

	return verb == "diff" && format == "--name-only"
}

var hookJQHasKeys = regexp.MustCompile(`^has\("[A-Za-z_][A-Za-z_0-9]*"\)(?: and has\("[A-Za-z_][A-Za-z_0-9]*"\))*$`)

func hookJQReadOnlyPredicate(words []*shellsyntax.Word, state hookSourceState) bool {
	if len(words) < 2 || len(words) > 3 {
		return false
	}

	option, _ := words[0].Literal()
	filter, _ := words[1].Literal()

	return option == "-e" && (filter == "." || hookJQHasKeys.MatchString(filter)) &&
		(len(words) == 2 || hookKnownFileOperand(words[2], state))
}

func hookPrintfMayWrite(args []*shellsyntax.Word) bool {
	if len(args) == 0 {
		return false
	}

	format, known := args[0].Literal()
	if format == "--" {
		if len(args) == 1 {
			return false
		}

		format, known = args[1].Literal()
	}

	return !known || !hookReadOnlyPrintf(format)
}

// Bash printf can write a variable through its -v option or a %n
// conversion. Allow only formats whose conversions are known to emit data.
func hookReadOnlyPrintf(format string) bool {
	if strings.HasPrefix(format, "-") {
		return false
	}

	for {
		_, suffix, hasConversion := strings.Cut(format, "%")
		if !hasConversion {
			return true
		}

		conversion := strings.TrimLeft(suffix, "0123456789")
		if conversion == "" || !strings.ContainsRune("%sbqdiouxX", rune(conversion[0])) {
			return false
		}

		format = conversion[1:]
	}
}

func hookTestOperand(word *shellsyntax.Word) bool {
	if word.Expands || word.Writes {
		return false
	}

	for _, part := range word.Parts {
		switch part.Kind {
		case shellsyntax.PartLiteral:
		case shellsyntax.PartParameter, shellsyntax.PartParameterDefaultDot, shellsyntax.PartParameterDefaultEmpty, shellsyntax.PartParameterScriptDir:
			if !part.Quoted || part.Text == "@" || part.Text == "*" {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func simpleHookCommand(stmt *shellsyntax.Statement, name string) bool {
	if stmt.Negated || len(stmt.Commands) != 1 {
		return false
	}

	cmd := stmt.Commands[0]
	if len(cmd.Words) == 0 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	head, _ := cmd.Words[0].Literal()

	return head == name && (name == "cd" || len(cmd.Words) == 1)
}

func hookKnownStatus(stmt *shellsyntax.Statement, state hookSourceState, name string) bool {
	return !state.lookupUnknown && !state.hasFunction(name) && !stmt.Background && stmt.Next != shellsyntax.Background && simpleHookCommand(stmt, name)
}

func (w *hookSourceWalk) conditional(e *File, view source.View, cmd *shellsyntax.Command, state hookSourceState, chain []report.SourceRef, entrypoint bool) hookSourceState {
	if len(cmd.Alternatives) != 2 || cmd.Prelude == nil || len(cmd.Prelude.Statements) == 0 {
		return state.opaque()
	}

	predicate := cmd.Prelude.Statements

	last := len(predicate) - 1
	for last > 0 && hookAndOrLink(predicate[last-1].Next) {
		last--
	}

	state = w.commands(e, view, &shellsyntax.File{Statements: predicate[:last]}, state, chain, entrypoint)
	if state.returned || state.exited || state.traceBlocked {
		return state
	}

	out := w.andOr(e, view, predicate[last:], state, chain, entrypoint)

	merged := out.stopped
	for i, branch := range []*hookSourceState{out.success, out.failure} {
		if branch != nil {
			next := w.commands(e, view, cmd.Alternatives[i], *branch, chain, entrypoint)
			merged = mergeHookPath(merged, next)
		}
	}

	return *merged
}

func (s *hookSourceState) changeDirectory(cwd string) {
	s.cwd = cwd
	delete(s.vars, "PWD")
	delete(s.vars, "OLDPWD")
	delete(s.kinds, "PWD")
	delete(s.kinds, "OLDPWD")
}
