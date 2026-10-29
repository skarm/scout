package source_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

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
	for _, s := range []string{"", "abc", "🙂\r\nПривет\n", "a\nb\nc"} {
		f.Add(s, uint16(0))
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
		prefix := text[:at]
		if line != strings.Count(prefix, "\n")+1 || column != utf8.RuneCountInString(prefix[strings.LastIndexByte(prefix, '\n')+1:])+1 {
			t.Fatal("coordinate mismatch")
		}
	})
}

func BenchmarkIndexLookup(b *testing.B) {
	text := strings.Repeat("word слово\n", 20000)
	index := source.NewIndex(text)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := index.Position(len(text)); err != nil {
			b.Fatal(err)
		}
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
