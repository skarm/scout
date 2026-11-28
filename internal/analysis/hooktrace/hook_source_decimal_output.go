package hooktrace

import (
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/syntax/shellsyntax"
)

// A count or clock substitution supplies data to Bash arithmetic. The proof
// requires decimal output on every arm, including a fallback after failure.
func hookDecimalOutput(tree *shellsyntax.File, state hookSourceState) bool {
	if tree == nil || state.lookupUnknown || len(tree.Statements) == 0 {
		return false
	}

	for i, stmt := range tree.Statements {
		if stmt.Background || stmt.Negated || stmt.Next == shellsyntax.Background || (i+1 < len(tree.Statements) && stmt.Next != shellsyntax.OrElse) ||
			!hookDecimalStage(stmt, state, i != 0) {
			return false
		}
	}

	return true
}

// An isolated two-argument function can print a validated first argument or
// a literal fallback. Every other function body remains opaque as a producer.
func hookDecimalFunction(tree *shellsyntax.File, state hookSourceState) bool {
	call, simple := SimpleShellCommand(tree)
	if !simple || tree.Statements[0].Background || tree.Statements[0].Negated || state.lookupUnknown ||
		!state.explicitBash || state.hasFunction("printf") || len(call.Words) != 3 || !hookFixedArgument(call.Words[1]) {
		return false
	}

	name, known := call.Words[0].Literal()
	value, fixed := call.Words[2].Literal()
	fn, single := state.singleFunction(name)

	if !known || !fixed || value != "" && !decimalDigits(value) || !single {
		return false
	}

	branch := hookOnlyDecimalCompound(fn.body)
	if branch != nil && branch.Group != nil {
		branch = hookOnlyDecimalCompound(branch.Group)
	}

	if branch == nil || !branch.ExclusiveBranches || branch.Prelude == nil ||
		len(branch.Prelude.Statements) != 1 || len(branch.Alternatives) != 2 {
		return false
	}

	test := hookOnlyDecimalCompound(branch.Prelude)
	if test == nil {
		return false
	}

	guard := test.DecimalGuard
	if guard == nil || guard.Name != "1" || guard.MatchOnFailure ||
		guard.RequiresC && state.vars["LC_ALL"] != "C" && state.vars["LC_ALL"] != "POSIX" {
		return false
	}

	return hookPrintDecimalArgument(branch.Alternatives[0], "1") && hookPrintDecimalArgument(branch.Alternatives[1], "2")
}

func hookOnlyDecimalCompound(body *shellsyntax.File) *shellsyntax.Command {
	if body == nil || len(body.Statements) != 1 {
		return nil
	}

	stmt := body.Statements[0]
	if stmt.Negated || stmt.Background || len(stmt.Commands) != 1 || stmt.Next == shellsyntax.Background || hookAndOrLink(stmt.Next) ||
		!hookPlainCompound(stmt.Commands[0]) {
		return nil
	}

	return stmt.Commands[0]
}

func hookPrintDecimalArgument(tree *shellsyntax.File, name string) bool {
	cmd, simple := SimpleShellCommand(tree)
	if !simple || tree.Statements[0].Background || tree.Statements[0].Negated || len(cmd.Words) != 3 {
		return false
	}

	exe, _ := cmd.Words[0].Literal()
	format, _ := cmd.Words[1].Literal()
	arg := cmd.Words[2]

	return exe == "printf" && format == "%s" && len(arg.Parts) == 1 && arg.Parts[0].Kind == shellsyntax.PartParameter &&
		arg.Parts[0].Quoted && arg.Parts[0].PlainParameter && arg.Parts[0].Text == name
}

func hookDecimalStage(stmt *shellsyntax.Statement, state hookSourceState, fallback bool) bool {
	if len(stmt.Commands) == 0 || len(stmt.Commands) > 3 {
		return false
	}

	commands := stmt.Commands
	if len(commands) == 1 && fallback &&
		(hookGrepZeroFallback(stmt, state) || hookKnownStatus(stmt, state, "true") || hookKnownStatus(stmt, state, ":")) {
		return true
	}

	last := commands[len(commands)-1]
	digitsOnly := len(commands) >= 2 && hookDigitFilter(last, state)

	if len(commands) >= 2 && hookTrimDecimal(last, state) {
		commands = commands[:len(commands)-1]
		last = commands[len(commands)-1]
	}

	// Restrict producers to stages whose standard output remains in the
	// pipe. A redirect could otherwise bypass the decimal-producing stage.
	for _, upstream := range commands[:len(commands)-1] {
		if !hookDecimalRedirects(upstream, false) || !hookPipelineStage(upstream, state) {
			return false
		}
	}

	return digitsOnly || hookDecimalCommand(last, state)
}

func hookDecimalCommand(cmd *shellsyntax.Command, state hookSourceState) bool {
	if len(cmd.Words) < 2 || len(cmd.Assignments) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	arg, _ := cmd.Words[1].Literal()

	if state.hasFunction(name) {
		return false
	}

	if name == "jq" {
		return hookJQCount(cmd, state)
	}

	if name == "date" && arg == "-u" && len(cmd.Words) == 3 {
		format, _ := cmd.Words[2].Literal()
		return format == "+%s" && hookDecimalRedirects(cmd, false)
	}

	if len(cmd.Words) != 2 {
		return false
	}

	switch name {
	case "date":
		return arg == "+%s" && hookDecimalRedirects(cmd, false)
	case "wc":
		return (arg == "-l" || arg == "-c" || arg == "-w") && hookDecimalRedirects(cmd, true)
	default:
		return false
	}
}

// jqCountFilter recognizes a literal array construction followed by length.
var jqCountFilter = regexp.MustCompile(`^\[\s*\.[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\[\](?:\s*\|\s*select\(\s*\.[A-Za-z_][A-Za-z_0-9]*\s*==\s*(?:true|false|null)\s*\))?\s*\]\s*\|\s*length$`)

var jqArrayLengthFilter = regexp.MustCompile(`^arrays\s*\|\s*length$`)

func hookJQCount(cmd *shellsyntax.Command, state hookSourceState) bool {
	if !hookDecimalRedirects(cmd, true) {
		return false
	}

	words := cmd.Words[1:]
	for len(words) > 0 {
		option, _ := words[0].Literal()
		if option != "-r" && option != "-e" && option != "-c" && option != "-M" {
			break
		}

		words = words[1:]
	}

	if len(words) == 0 || len(words) > 3 {
		return false
	}

	filter, literal := words[0].Literal()
	filter = strings.TrimSpace(filter)

	if !literal || (!jqCountFilter.MatchString(filter) && !jqArrayLengthFilter.MatchString(filter)) {
		return false
	}

	switch len(words) {
	case 1:
		return true
	case 2:
		return hookKnownFileOperand(words[1], state)
	default:
		separator, _ := words[1].Literal()
		return separator == "--" && hookSingleBracketWord(words[2])
	}
}

func hookKnownFileOperand(word *shellsyntax.Word, state hookSourceState) bool {
	if !hookSingleBracketWord(word) || len(word.Parts) == 0 {
		return false
	}

	part := word.Parts[0]
	switch part.Kind {
	case shellsyntax.PartLiteral:
		return part.Text != "" && !strings.HasPrefix(part.Text, "-")
	case shellsyntax.PartParameter:
		value, known := state.vars[part.Text]
		return part.Quoted && known && value != "" && !strings.HasPrefix(value, "-")
	default:
		return false
	}
}

func hookDigitFilter(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.hasFunction("tr") || len(cmd.Words) != 3 || len(cmd.Assignments) != 0 || !hookDecimalRedirects(cmd, false) {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	option, _ := cmd.Words[1].Literal()
	set, _ := cmd.Words[2].Literal()

	return name == "tr" && (option == "-cd" || option == "-dc") && set == "0123456789"
}

func hookDecimalRedirects(cmd *shellsyntax.Command, input bool) bool {
	for _, r := range cmd.Redirects {
		switch {
		case r.Op == shellsyntax.RedirectOutput && r.FD == shellsyntax.StderrFD && hookDiscardedOutput(r):
		case input && r.Op == shellsyntax.RedirectInput && (r.FD == "" || r.FD == shellsyntax.StdinFD) && hookSingleBracketWord(r.Target):
		default:
			return false
		}
	}

	return true
}

func hookTrimDecimal(cmd *shellsyntax.Command, state hookSourceState) bool {
	if state.hasFunction("tr") || len(cmd.Words) != 3 || len(cmd.Assignments) != 0 || len(cmd.Redirects) != 0 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	opt, _ := cmd.Words[1].Literal()
	set, _ := cmd.Words[2].Literal()

	return name == "tr" && opt == "-d" && (set == " " || set == "[:space:]")
}

func hookDecimalClockField(tree *shellsyntax.File, state hookSourceState) bool {
	if state.lookupUnknown || state.hasFunction("date") {
		return false
	}

	cmd, simple := SimpleShellCommand(tree)
	if !simple || tree.Statements[0].Negated || tree.Statements[0].Background || len(cmd.Words) != 2 {
		return false
	}

	name, _ := cmd.Words[0].Literal()
	format, _ := cmd.Words[1].Literal()

	return name == "date" && (format == "+%H" || format == "+%M" || format == "+%S")
}
