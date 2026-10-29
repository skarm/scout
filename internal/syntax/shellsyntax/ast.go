// Package shellsyntax parses a deliberately bounded shell grammar without
// expansion or execution. It is NOT a complete POSIX/Bash parser. Unsupported
// grammar fails explicitly; preceding complete statements remain available.
package shellsyntax

import "github.com/skarm/scout/internal/syntax/source"

const (
	MaxBytes = 128 << 10
	MaxDepth = 32
	MaxNodes = 16384
)

type File struct {
	Statements []*Statement
}

type Statement struct {
	Span     source.Span
	Commands []*Command // a pipeline; commands are in source order
	Pipes    []string   // | or |&
	Next     string     // ;, newline, &&, ||, &, or empty at EOF
}

type Command struct {
	Span         source.Span
	Words        []*Word
	Assignments  []Assignment
	Redirects    []*Redirect
	Subshell     *File
	Group        *File
	Prelude      *File
	Alternatives []*File
	FunctionName string
	FunctionBody *File
	Invalidates  []string
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
}
type Word struct {
	Span    source.Span
	Parts   []Part
	Quoted  bool
	Expands bool // unquoted glob/tilde/brace expansion: value is not a static word
}

type Part struct {
	Span   source.Span
	Kind   string // literal, parameter, substitution
	Text   string // syntax-owned literal or parameter name; never emitted in reports
	Tree   *File
	Quoted bool
}

// Literal returns a quote-removed, escape-processed word only when it has no
// dynamic expansion. It never consults host environment/filesystem/processes.
func (w *Word) Literal() (string, bool) {
	if w == nil || w.Expands {
		return "", false
	}

	n := 0

	for _, p := range w.Parts {
		if p.Kind != "literal" {
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
