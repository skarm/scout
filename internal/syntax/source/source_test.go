package source_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

func TestJoinedViewMapsOnlySelectedSourceFragments(t *testing.T) {
	const text = "middle AA ZZ"
	build := func(start, end int) source.View {
		t.Helper()
		view, err := source.NewView(text, []source.Span{{Start: start, End: end}})
		if err != nil {
			t.Fatal(err)
		}
		return view
	}
	joined := source.Concat(build(7, 9), build(0, 6), build(10, 12))
	selected, err := joined.Select([]source.Span{{End: 2}, {Start: 8, End: 10}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := selected.Original(source.Span{End: len(selected.Text())})
	if want := (source.Span{Start: 7, End: 12}); got != want || err != nil {
		t.Fatalf("original span = %v, %v, want %v", got, err, want)
	}
	if selected.ContainsMappedEndpoints(source.Span{End: 6}) || selected.ContainsMappedEndpoints(source.Span{Start: 9, End: 10}) || !selected.ContainsMappedEndpoints(got) {
		t.Fatalf("selection included a skipped fragment or excluded its own endpoints")
	}
	joinedAgain := source.Concat(selected, build(1, 2))
	if joinedAgain.ContainsMappedEndpoints(source.Span{Start: 3, End: 5}) {
		t.Fatalf("second join included a skipped fragment")
	}
}

func TestIndex(t *testing.T) {
	text := "Привет🙂\r\nabc\n"
	index := source.NewIndex(text)
	for _, tc := range []struct{ offset, line, column int }{
		{offset: 0, line: 1, column: 1}, {offset: 12, line: 1, column: 7}, {offset: 16, line: 1, column: 8}, {
			offset: 18,
			line:   2,
			column: 1,
		}, {
			offset: 21,
			line:   2,
			column: 4,
		}, {
			offset: 22,
			line:   3,
			column: 1,
		},
	} {
		line, column, err := index.Position(tc.offset)
		if err != nil || line != tc.line || column != tc.column {
			t.Fatalf("%+v: %d:%d %v", tc, line, column, err)
		}
	}
	for _, offset := range []int{-1, 1, 13, 100} {
		if _, _, err := index.Position(offset); err == nil {
			t.Fatalf("accepted offset %d", offset)
		}
	}
	var zero source.Index
	if _, _, err := zero.Position(0); err == nil {
		t.Fatal("zero index accepted")
	}
}

func TestPiecewiseMapping(t *testing.T) {
	original := "  α\r\n x\n"
	spans := []source.Span{{Start: 2, End: 6}, {Start: 7, End: 9}}
	view, err := source.NewView(original, spans)
	if err != nil {
		t.Fatal(err)
	}
	spans[0].Start = 0 // caller mutation must not change the mapping
	if view.Text() != "α\r\nx\n" {
		t.Fatalf("text=%q", view.Text())
	}
	for _, tc := range []struct{ view, original source.Span }{
		{view: source.Span{Start: 0, End: 2}, original: source.Span{Start: 2, End: 4}},
		{view: source.Span{Start: 0, End: 4}, original: source.Span{Start: 2, End: 6}},
		{view: source.Span{Start: 4, End: 5}, original: source.Span{Start: 7, End: 8}},
		{view: source.Span{Start: 0, End: 6}, original: source.Span{Start: 2, End: 9}},
	} {
		got, err := view.Original(tc.view)
		if err != nil || got != tc.original {
			t.Fatalf("%+v => %+v %v", tc.view, got, err)
		}
	}
	for _, bad := range []source.Span{{Start: -1, End: 1}, {Start: 0, End: 0}, {Start: 1, End: 2}, {Start: 0, End: 1}, {
		Start: 0,
		End:   7,
	}} {
		if _, err := view.Original(bad); err == nil {
			t.Fatalf("accepted invalid span %+v", bad)
		}
	}
}

func TestRejectSourceSpans(t *testing.T) {
	for _, spans := range [][]source.Span{
		{{Start: -1, End: 1}},
		{{Start: 0, End: 99}},
		{{Start: 2, End: 1}},
		{{Start: 0, End: 3}, {Start: 2, End: 3}},
		{{Start: 1, End: 2}},
	} {
		if _, err := source.NewView("αbc", spans); err == nil {
			t.Fatalf("accepted %+v", spans)
		}
	}
	empty, err := source.NewView("", nil)
	if err != nil || empty.Text() != "" {
		t.Fatal(err)
	}
	if _, err := empty.Original(source.Span{}); err == nil {
		t.Fatal("empty mapped span accepted")
	}
}

func FuzzIndex(f *testing.F) {
	for _, seed := range []struct {
		text   string
		offset uint16
	}{
		{text: "", offset: 0},
		{text: "abc", offset: 3},           // EOF after ordinary characters.
		{text: "🙂\r\nПривет\n", offset: 5}, // Between CR and LF.
		{text: "🙂\r\nПривет\n", offset: 8}, // After a multibyte character on the second line.
		{text: "a\nb\nc", offset: 4},
		{text: "a\rb\rc", offset: 4},
	} {
		f.Add(seed.text, seed.offset)
	}
	f.Fuzz(func(t *testing.T, text string, offset uint16) {
		if len(text) > 64<<10 || !utf8.ValidString(text) {
			return
		}
		at := int(offset) % (len(text) + 1)
		if at < len(text) && !utf8.RuneStart(text[at]) {
			return
		}
		line, column, err := source.NewIndex(text).Position(at)
		if err != nil {
			t.Fatal(err)
		}
		// Mark complete CRLF pairs before converting bare CR. When the
		// queried offset is inside a CRLF pair, CR still occupies a column.
		normalized := strings.ReplaceAll(text, "\r\n", "\x00\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")
		prefix := normalized[:at]
		if line != strings.Count(prefix, "\n")+1 || column != utf8.RuneCountInString(prefix[strings.LastIndexByte(prefix, '\n')+1:])+1 {
			t.Fatal("coordinate mismatch")
		}
	})
}

func BenchmarkIndexLookup(b *testing.B) {
	for _, tc := range []struct{ name, text string }{
		{name: "short-lines", text: strings.Repeat("word слово\n", 20000)},
		{name: "long-ascii-line", text: strings.Repeat("a", 1<<20)},
		{name: "long-unicode-line", text: strings.Repeat("слово🙂", 1<<16)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			index := source.NewIndex(tc.text)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := index.Position(len(tc.text)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIndexCoordinatesAcrossLongUnicodeLines(t *testing.T) {
	text := strings.Repeat("a", 1023) + "🙂" + strings.Repeat("слово", 15000) + "\r\n" + strings.Repeat("🙂", 2000) + "\n"
	index := source.NewIndex(text)
	for at := 0; at <= len(text); at += 127 {
		if at < len(text) && !utf8.RuneStart(text[at]) {
			continue
		}
		prefix := text[:at]
		wantLine := strings.Count(prefix, "\n") + 1
		wantColumn := utf8.RuneCountInString(prefix[strings.LastIndexByte(prefix, '\n')+1:]) + 1
		line, column, err := index.Position(at)
		if err != nil || line != wantLine || column != wantColumn {
			t.Fatalf("offset %d: got %d:%d, want %d:%d (%v)", at, line, column, wantLine, wantColumn, err)
		}
	}
	line, column, err := index.Position(len(text))
	if err != nil || line != 3 || column != 1 {
		t.Fatalf("EOF coordinate: %d:%d (%v)", line, column, err)
	}
}

func TestSparseIndexBoundaries(t *testing.T) {
	text := strings.Repeat("α\r\n", 200) + "end"
	index := source.NewIndex(text)
	for offset := 0; offset <= len(text); offset++ {
		if offset < len(text) && !utf8.RuneStart(text[offset]) {
			continue
		}
		line, col, err := index.Position(offset)
		prefix := text[:offset]
		if err != nil || line != strings.Count(prefix, "\n")+1 || col != utf8.RuneCountInString(prefix[strings.LastIndexByte(prefix, '\n')+1:])+1 {
			t.Fatalf("offset %d: %d:%d %v", offset, line, col, err)
		}
	}
}

func TestProjectionExpansionAndComposition(t *testing.T) {
	original := "🙂 ﬃ end"
	v, e := source.NewView(original, []source.Span{{Start: 0, End: len(original)}})
	if e != nil {
		t.Fatal(e)
	}
	v, e = v.Replace([]source.Replacement{{Span: source.Span{Start: 5, End: 8}, Text: "ffi"}})
	if e != nil {
		t.Fatal(e)
	}
	at, e := v.Original(source.Span{Start: 6, End: 7})
	if e != nil || at != (source.Span{Start: 5, End: 8}) {
		t.Fatal("expanded character must cite enclosing original rune", at, e)
	}
	v, e = v.Replace([]source.Replacement{{Span: source.Span{Start: 5, End: 7}, Text: "X"}})
	if e != nil {
		t.Fatal(e)
	}
	at, e = v.Original(source.Span{Start: 5, End: 6})
	if e != nil || at != (source.Span{Start: 5, End: 8}) {
		t.Fatal("composition lost source identity", at, e)
	}
	if _, e = v.Replace([]source.Replacement{{Span: source.Span{Start: 1, End: 2}, Text: "x"}}); e == nil {
		t.Fatal("split UTF-8 rune accepted")
	}
}

func TestViewSelectComposesAcrossDisjointAndReplacedSource(t *testing.T) {
	const original = "> αX\n> βY\n"
	parent, err := source.NewView(original, []source.Span{{Start: 2, End: 6}, {Start: 8, End: 12}})
	if err != nil {
		t.Fatal(err)
	}
	parent, err = parent.Replace([]source.Replacement{{Span: source.Span{Start: 2, End: 3}, Text: "foo"}})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := parent.Select([]source.Span{{Start: 3, End: 5}, {Start: 6, End: 8}})
	if err != nil || projected.Text() != "ooβ" {
		t.Fatalf("selected view = %q (%v)", projected.Text(), err)
	}
	for _, tc := range []struct{ selected, original source.Span }{
		{source.Span{End: 2}, source.Span{Start: 4, End: 5}},
		{source.Span{Start: 2, End: 4}, source.Span{Start: 8, End: 10}},
		{source.Span{End: 4}, source.Span{Start: 4, End: 10}},
	} {
		if got, err := projected.Original(tc.selected); err != nil || got != tc.original {
			t.Fatalf("mapping %+v = %+v (%v), want %+v", tc.selected, got, err, tc.original)
		}
	}
	if _, err := parent.Select([]source.Span{{Start: 7, End: 8}}); err == nil {
		t.Fatal("selection split a UTF-8 rune")
	}
}

func TestIndexCountsBareCRAndCRLFAsSingleBreaks(t *testing.T) {
	const text = "α\rβ\r\nγ\n"
	index := source.NewIndex(text)
	for _, want := range []struct{ offset, line, column int }{
		{2, 1, 2}, {3, 2, 1}, {5, 2, 2}, {6, 2, 3}, {7, 3, 1}, {9, 3, 2}, {10, 4, 1},
	} {
		line, column, err := index.Position(want.offset)
		if err != nil || line != want.line || column != want.column {
			t.Fatalf("byte %d: got %d:%d, %v, want %d:%d", want.offset, line, column, err, want.line, want.column)
		}
	}
}
