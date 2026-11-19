// Package shellsyntax parses a deliberately bounded shell grammar without
// expansion or execution. It is NOT a complete POSIX/Bash parser. Unsupported
// grammar fails explicitly; preceding complete statements remain available.
package shellsyntax

import (
	"iter"
	"strings"

	"github.com/skarm/scout/internal/syntax/source"
)

// Standard shell file descriptors.
const (
	StderrFD = "2"
	StdinFD  = "0"
	StdoutFD = "1"
)

// Shell operators and internal lexer tokens.
const (
	AndThen                 = "&&"
	Background              = "&"
	OrElse                  = "||"
	Pipe                    = "|"
	PipeWithStderr          = "|&"
	RedirectAppend          = ">>"
	RedirectAppendBoth      = "&>>"
	RedirectBoth            = "&>"
	RedirectClobber         = ">|"
	RedirectDuplicateInput  = "<&"
	RedirectDuplicateOutput = ">&"
	RedirectHereDoc         = "<<"
	RedirectHereString      = "<<<"
	RedirectInput           = "<"
	RedirectOutput          = ">"
	RedirectReadWrite       = "<>"
	RedirectStripHereDoc    = "<<-"
	sequence                = ";"
	tokenCloseParen         = ")"
	tokenEOF                = "eof"
	tokenEndCase            = ";;"
	tokenNewline            = "newline"
	tokenOpenParen          = "("
	tokenWord               = "word"
)

const (
	MaxBytes = 128 << 10
	MaxDepth = 32
	MaxNodes = 16384
)

type File struct {
	Statements []*Statement
	// OmittedExecution records syntax that the Bash projection cannot represent
	// for a shell execution check. The bounded parser reports errors directly.
	OmittedExecution bool
}

type Statement struct {
	Span       source.Span
	Commands   []*Command // a pipeline; commands are in source order
	Pipes      []string   // | or |&
	Next       string     // ;, newline, &&, ||, &, or empty at EOF
	Negated    bool       // ! reverses the success edge
	Background bool       // the whole list runs in a subshell
}

type Command struct {
	Span               source.Span
	Words              []*Word
	Assignments        []Assignment
	Redirects          []*Redirect
	Subshell           *File
	Group              *File
	Prelude            *File
	Alternatives       []*File
	Loop               bool     // the prelude or alternatives may be evaluated repeatedly
	Until              bool     // invert the loop condition before evaluating the body
	WhileAssignments   []string // variables written by a read-only while with an assignment-only body
	ExclusiveBranches  bool     // at most one alternative runs after the prelude
	Case               *CaseSelection
	FunctionName       string
	FunctionBody       *File
	Declaration        string  // declaration builtin, when projected by the broader grammar
	DeclarationArgs    []*Word // options and unresolved arguments in a declaration
	ComplexLocal       bool    // a local operand is not a plain scalar declaration
	Invalidates        []string
	ReadOnlyTest       bool
	RegexTest          bool     // evaluation may change BASH_REMATCH
	ExpansionWords     []*Word  // substitutions in projected control operands
	NumericTest        []*Word  // arithmetic operands requiring proven numeric values
	ArithmeticUpdate   string   // scalar changed by a standalone increment or decrement
	IndirectTest       []string // variables whose contents must name a plain parameter
	PositionalNonempty bool     // exact Bash test [[ $# -gt 0 ]]
	NonemptyParameter  string   // exact Bash test [[ -n "$name" ]]
	DecimalGuard       *DecimalGuard
	ForFileGlob        *ForFileGlob
	ForArguments       string // loop variable for a projected word list
	ForWords           []*Word
	ForPositional      bool   // the list is the shell positional parameters
	ForArray           string // exact quoted all-elements expansion of an indexed array
	ForArraySlice      *ForArraySlice
}

// DecimalGuard describes an anchored decimal regex and the branch that
// establishes the digit constraint.
type DecimalGuard struct {
	Name           string
	RequiresC      bool
	MatchOnFailure bool
}

// ForFileGlob describes a single-level loop over a quoted root and a literal directory.
type ForFileGlob struct {
	Name, Root, Directory string
}

// ForArraySlice describes a quoted all-elements slice with no length.
type ForArraySlice struct {
	Name, OffsetVariable string
}

// CaseSelection retains ordered patterns for a bounded, non-fallthrough case.
// Patterns[i] selects Alternatives[i] on the command.
type CaseSelection struct {
	Word     *Word
	Patterns [][]*Word
}

type Assignment struct {
	Name  string
	Value *Word
	Span  source.Span
}

type Redirect struct {
	Span            source.Span
	Op, FD          string
	Target          *Word
	Body            *Word // heredoc contents, never treated as shell statements
	QuotedDelimiter bool
	BodyVerified    bool // The raw heredoc boundary was checked against its delimiter.
}
type Word struct {
	Span            source.Span
	Parts           []Part
	Quoted          bool
	Expands         bool    // unquoted glob/tilde/brace expansion: value is not a static word
	Writes          bool    // expansion may change a variable in the current shell
	IndexedArray    bool    // complete replacement with an indexed array
	ArrayAppend     bool    // append to an already indexed array
	ArrayWords      []*Word // indexed array replacement words before shell expansion
	DecimalElements bool    // every element is a literal decimal digit string
	FixedArraySize  int     // number of elements plus one, or zero if unknown
}

type Part struct {
	Span               source.Span
	Kind               string // literal, parameter, specialized parameter expansion, or substitution
	Text               string // syntax-owned literal or parameter name; never emitted in reports
	Tree               *File
	Operand            *Word  // operand of a read-only parameter expansion
	SingleField        bool   // a quoted parameter transformation cannot expand to multiple fields
	DefaultIfUnset     bool   // scalar default expansion for an unset or empty parameter
	TrimPrefix         string // literal prefix removed by a parameter expansion
	Quoted             bool
	PlainParameter     bool // exact $name or ${name} without a transformation or subscript
	Replacement        *LiteralReplacement
	ArithmeticOperands []*Word // non-nil only for projected arithmetic expansions
	ArrayIndex         *ArithmeticIndex
}

// ArithmeticIndex is one subscript atom, which may itself read an indexed array.
type ArithmeticIndex struct {
	Name    string
	Inner   *ArithmeticIndex
	Decimal bool
}

// Substitutions yields child shell bodies, each of which runs in an isolated
// shell. An operand of a parameter expansion may itself contain substitutions.
func (w *Word) Substitutions() iter.Seq[*File] {
	return w.SubstitutionsExcept(nil)
}

// SubstitutionsExcept omits the children of parts that a caller has proved inactive.
func (w *Word) SubstitutionsExcept(skip func(Part) bool) iter.Seq[*File] {
	return func(yield func(*File) bool) { yieldSubstitutions(w, skip, yield) }
}

func yieldSubstitutions(w *Word, skip func(Part) bool, yield func(*File) bool) bool {
	if w == nil {
		return true
	}

	for _, part := range w.Parts {
		if skip != nil && skip(part) {
			continue
		}

		if part.Tree != nil && !yield(part.Tree) || !yieldSubstitutions(part.Operand, skip, yield) {
			return false
		}

		for _, operand := range part.ArithmeticOperands {
			if !yieldSubstitutions(operand, skip, yield) {
				return false
			}
		}
	}

	return true
}

// LiteralReplacement is a global Bash substitution with literal operands.
type LiteralReplacement struct {
	Pattern, Value string
}

// HasQuotedPluginRootPrefix identifies a quoted plugin-root expansion
// followed by a path separator, with or without a current-directory fallback.
func (w *Word) HasQuotedPluginRootPrefix(name string) bool {
	if w == nil || w.Expands || name == "" {
		return false
	}

	for i, part := range w.Parts {
		if part.Kind == PartLiteral && part.Text == "" {
			continue
		}

		return (part.Kind == PartParameter || part.Kind == PartParameterDefaultDot) && part.Quoted && part.Text == name &&
			i+1 < len(w.Parts) && w.Parts[i+1].Kind == PartLiteral && strings.HasPrefix(w.Parts[i+1].Text, "/")
	}

	return false
}

// HasUnquotedPluginRootPath recognizes an unquoted root and a literal suffix.
// The shell can still split or glob the expanded root.
func (w *Word) HasUnquotedPluginRootPath(name string) bool {
	if w == nil || name == "" || w.Expands || w.Writes || len(w.Parts) < 2 {
		return false
	}

	root, suffix := w.Parts[0], w.Parts[1]
	if root.Kind != PartParameter || root.Quoted || root.Text != name || !strings.HasPrefix(suffix.Text, "/") {
		return false
	}

	for _, part := range w.Parts[1:] {
		if part.Kind != PartLiteral {
			return false
		}
	}

	return true
}

// Literal returns a quote-removed, escape-processed word only when it has no
// dynamic expansion. It never consults host environment/filesystem/processes.
func (w *Word) Literal() (string, bool) {
	if w == nil || w.Expands {
		return "", false
	}

	n := 0

	for _, p := range w.Parts {
		if p.Kind != PartLiteral {
			return "", false
		}

		n += len(p.Text)
	}

	b := make([]byte, 0, n)
	for _, p := range w.Parts {
		b = append(b, p.Text...)
	}

	return string(b), true
}
