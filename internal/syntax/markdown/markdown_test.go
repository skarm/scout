package markdown_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/scout/internal/syntax/markdown"
	"github.com/skarm/scout/internal/syntax/source"
)

func TestConcurrentParserReusePreservesSourceAndHTMLPolicy(t *testing.T) {
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for iteration := range 32 {
				marker := fmt.Sprintf("marker_%d_%d", worker, iteration)
				input := "```go\n" + marker + "\n```\n"
				for _, result := range []markdown.Result{
					markdown.Parse(context.Background(), input, 0),
					markdown.ParseOpaque(context.Background(), input, source.Span{End: len(input)}),
				} {
					if result.Failure != "" || len(result.Blocks) != 1 || result.Blocks[0].View.Text() != marker+"\n" {
						t.Errorf("source leaked across parser sessions: %+v", result)
					}
				}
				limited := markdown.Parse(context.Background(), strings.Repeat("> ", 128)+"deep\n", 0)
				if limited.Failure != "markdown_structure_limit" {
					t.Errorf("structure limit lost: %+v", limited)
				}
				html := "<div>\ntext\n</div>\n"
				if !markdown.Parse(context.Background(), html, 0).HTML || markdown.ParseOpaque(context.Background(), html, source.Span{End: len(html)}).HTML {
					t.Error("parser session reused with the wrong HTML policy")
				}
			}
		})
	}
	workers.Wait()
}

func TestCommonMarkContainerProjection(t *testing.T) {
	for _, wrapper := range []struct{ opening, prefix, closing string }{
		{"> ```go", "> ", "> ```"},
		{"- ```go", "  ", "  ```"},
		{"> - ```go", ">   ", ">   ```"},
		{"1. ```go", "   ", "   ```"},
		{"\tpackage p", "\t", ""},
	} {
		for _, newline := range []string{"\n", "\r\n"} {
			code := "func f() { println(\"ANCHOR\") }"
			input := "# Example🙂" + newline + newline + wrapper.opening + newline + wrapper.prefix + code + newline + wrapper.closing + newline
			result := markdown.Parse(context.Background(), input, 0)
			if result.Failure != "" || len(result.Blocks) != 1 || result.Blocks[0].Failure != "" || result.Blocks[0].Unclosed {
				t.Fatalf("%q: %+v", input, result)
			}
			view := result.Blocks[0].View
			at := strings.Index(view.Text(), "ANCHOR")
			span, err := view.Original(source.Span{Start: at, End: at + len("ANCHOR")})
			if err != nil || input[span.Start:span.End] != "ANCHOR" || span.Start != strings.Index(input, "ANCHOR") {
				t.Fatalf("container source mapping lost: %+v %v", span, err)
			}
		}
	}
}

func TestContainerExitDoesNotAbsorbFollowingProse(t *testing.T) {
	input := "> ```sh\n> echo FIRST\n\nFollowing paragraph\n\n```sh\necho SECOND\n```\n"
	result := markdown.Parse(context.Background(), input, 0)
	if result.Failure != "" || len(result.Blocks) != 2 || !result.Blocks[0].Unclosed || result.Blocks[1].Unclosed || strings.Contains(result.Blocks[0].View.Text(), "Following") {
		t.Fatalf("container boundary lost: %+v", result)
	}
}

func TestMarkdownLimitsPreserveEarlierBlocks(t *testing.T) {
	input := "```sh\necho RETAINED\n```\n\n" + strings.Repeat("> ", 128) + "nested\n"
	result := markdown.Parse(context.Background(), input, 0)
	if result.Failure != "markdown_structure_limit" || len(result.Blocks) != 1 || !strings.Contains(result.Blocks[0].View.Text(), "RETAINED") {
		t.Fatalf("limit lost prior evidence: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := markdown.Parse(ctx, input, 0); got.Failure != "preparation_cancelled" {
		t.Fatal(got.Failure)
	}
}

func FuzzMarkdownSourceMapping(f *testing.F) {
	for _, seed := range []string{"", "> - ```go\r\n>   package p\r\n>   ```", "-\t```sh\n\techo x\n\t```", "<!-- ```go -->", "    package p\n", strings.Repeat(">", 128)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 32<<10 {
			return
		}
		result := markdown.Parse(context.Background(), input, 0)
		if len(result.Blocks) > markdown.MaxBlocks {
			t.Fatal("block budget exceeded")
		}
		for _, block := range result.Blocks {
			if block.Span.Start < 0 || block.Span.End < block.Span.Start || block.Span.End > len(input) {
				t.Fatalf("invalid physical region: %+v", block.Span)
			}
			if block.Failure == "" && len(block.View.Text()) != 0 {
				span, err := block.View.Original(source.Span{Start: 0, End: len(block.View.Text())})
				if err != nil || span.Start < block.Span.Start || span.End > block.Span.End {
					t.Fatalf("view escaped physical region: %+v %v", span, err)
				}
			}
		}
	})
}

func TestCommonMarkBareCarriageReturnFences(t *testing.T) {
	const input = "header\r\r> ```sh\r> printf ready\r> ```\r"
	result := markdown.Parse(t.Context(), input, 0)
	if result.Failure != "" || len(result.Blocks) != 1 {
		t.Fatalf("fence after CR-only lines lost: %+v", result)
	}

	block := result.Blocks[0]
	if block.Failure != "" || block.Unclosed || block.Info != "sh" || block.View.Text() != "printf ready\n" {
		t.Fatalf("incorrect fenced projection: %+v, code=%q", block, block.View.Text())
	}

	at := strings.Index(input, "printf")
	span, err := block.View.Original(source.Span{End: len(block.View.Text())})
	if err != nil || span != (source.Span{Start: at, End: at + len("printf ready\r")}) {
		t.Fatalf("original span = %+v, err = %v", span, err)
	}
}

// CommonMark 0.31.2 example 278, with CRLF line endings.
func TestCommonMarkEmptyListMarkersWithCRLF(t *testing.T) {
	const input = "-\r\n  foo\r\n-\r\n  ```\r\n  bar\r\n  ```\r\n-\r\n      baz\r\n"
	result := markdown.Parse(t.Context(), input, 0)
	if result.Failure != "" || len(result.Blocks) != 2 {
		t.Fatalf("expected both code blocks: %+v", result)
	}
	for i, want := range []string{"bar\r\n", "baz\r\n"} {
		block := result.Blocks[i]
		at := strings.Index(input, want)
		span, err := block.View.Original(source.Span{End: len(want)})
		if block.View.Text() != want || span != (source.Span{Start: at, End: at + len(want)}) || err != nil {
			t.Fatalf("block %d: %q, %+v, %v", i, block.View.Text(), span, err)
		}
	}
}
