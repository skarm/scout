// Package source maps analysis views and coordinates to original source bytes.
// It never normalizes, executes or reopens the captured content.
package source

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// A sparse index avoids eight bytes of metadata for every byte of an input
// consisting entirely of newlines. A lookup scans at most one 64-line block.
const indexStride = 64

// Span is a zero-based, half-open byte interval.
type Span struct {
	// Start is the inclusive byte offset.
	Start int
	// End is the exclusive byte offset.
	End int
}

// Index is immutable and safe for concurrent readers. Line endings remain in
// the original text; columns count Unicode code points, not bytes or UTF-16.
type Index struct {
	// text retains unchanged source bytes for coordinate lookup.
	text string
	// lines stores one byte offset per 64-line block to bound index memory.
	lines []int
}

type segment struct {
	viewStart int
	original  Span
	replaced  bool
}

// View is an immutable concatenation of original source spans. Its mapping is
// piecewise, not an assumed constant offset: Markdown indentation may differ
// between lines. A mapped multi-line span encloses intervening original bytes.
type View struct {
	// text stores the immutable analysis representation.
	text string
	// segments maps pieces of the representation to their enclosing source
	// intervals.
	segments []segment
	// parent chains transformed views back to original captured bytes.
	parent *View
}

// Replacement projects trusted scanner text onto an enclosing original span.
// It never assigns invented per-character coordinates to expanded Unicode.
type Replacement struct {
	// Span selects the nonempty interval in the current view to replace.
	Span Span
	// Text contains trusted scanner-generated UTF-8 projected onto Span.
	Text string
}

// NewIndex builds a sparse line index over the unchanged source text.
func NewIndex(text string) Index {
	lines := make([]int, 1, strings.Count(text, "\n")/indexStride+1)
	line := 0

	for at := 0; at < len(text); {
		n := strings.IndexByte(text[at:], '\n')
		if n < 0 {
			break
		}

		at += n + 1

		line++
		if line%indexStride == 0 {
			lines = append(lines, at)
		}
	}

	return Index{text: text, lines: lines}
}

// Position maps a valid byte offset to one-based line and Unicode code-point
// column coordinates. Invalid offsets or an uninitialized index return an
// error.
func (i Index) Position(offset int) (line, column int, err error) {
	if offset < 0 || offset > len(i.text) || (offset < len(i.text) && !utf8.RuneStart(i.text[offset])) {
		return 0, 0, errors.New("invalid source offset")
	}

	n := sort.Search(len(i.lines), func(n int) bool { return i.lines[n] > offset }) - 1
	if n < 0 {
		return 0, 0, errors.New("uninitialized source index")
	}

	block := i.text[i.lines[n]:offset]

	return n*indexStride + strings.Count(block, "\n") + 1,
		utf8.RuneCountInString(block[strings.LastIndexByte(block, '\n')+1:]) + 1, nil
}

// NewView concatenates ordered, nonoverlapping source spans and retains their
// original coordinates.
func NewView(original string, spans []Span) (View, error) {
	var b strings.Builder

	last := 0
	total := 0

	for _, s := range spans {
		if s.Start < last || !validSpan(original, s) {
			return View{}, errors.New("invalid or overlapping source spans")
		}

		last = s.End
		total += s.End - s.Start
	}

	b.Grow(total)

	segments := make([]segment, 0, len(spans))
	for _, s := range spans {
		if s.Start == s.End {
			continue
		}

		segments = append(segments, segment{viewStart: b.Len(), original: s})
		b.WriteString(original[s.Start:s.End])
	}

	return View{text: b.String(), segments: segments}, nil
}

// Replace returns a derived view with validated, nonoverlapping substitutions.
// Replacement bytes map to their enclosing original span rather than invented
// character offsets.
func (v View) Replace(replacements []Replacement) (View, error) {
	var b strings.Builder

	segments := make([]segment, 0)
	last := 0

	appendPart := func(s Span, text string, replaced bool) {
		if text == "" {
			return
		}

		start := b.Len()
		b.WriteString(text)

		segments = append(segments, segment{viewStart: start, original: s, replaced: replaced})
	}
	for _, r := range replacements {
		s := r.Span
		if s.Start < last || s.End <= s.Start || s.End > len(v.text) ||
			!utf8.RuneStart(v.text[s.Start]) || (s.End < len(v.text) && !utf8.RuneStart(v.text[s.End])) || !utf8.ValidString(r.Text) {
			return View{}, errors.New("invalid projected source span")
		}

		appendPart(Span{Start: last, End: s.Start}, v.text[last:s.Start], false)
		appendPart(s, r.Text, true)
		last = s.End
	}

	appendPart(Span{Start: last, End: len(v.text)}, v.text[last:], false)

	return View{text: b.String(), segments: segments, parent: &v}, nil
}

// Text returns the immutable analysis representation.
func (v View) Text() string { return v.text }

// Original maps a nonempty analysis span through all parent views to an
// enclosing original byte span.
func (v View) Original(s Span) (Span, error) {
	if s.Start == s.End || len(v.segments) == 0 || !validSpan(v.text, s) {
		return Span{}, errors.New("invalid analysis span")
	}

	lookup := func(offset int, end bool) int {
		n := sort.Search(len(v.segments), func(n int) bool { return v.segments[n].viewStart > offset }) - 1
		return v.segments[n].originalOffset(offset, end)
	}

	result := Span{Start: lookup(s.Start, false), End: lookup(s.End-1, true)}
	if v.parent != nil {
		return v.parent.Original(result)
	}

	return result, nil
}

func validSpan(text string, s Span) bool {
	if s.Start < 0 || s.End < s.Start || s.End > len(text) {
		return false
	}

	return (s.Start == len(text) || utf8.RuneStart(text[s.Start])) && (s.End == len(text) || utf8.RuneStart(text[s.End]))
}

func (s segment) originalOffset(offset int, end bool) int {
	if s.replaced {
		if end {
			return s.original.End
		}

		return s.original.Start
	}

	if end {
		return s.original.Start + offset - s.viewStart + 1
	}

	return s.original.Start + offset - s.viewStart
}
