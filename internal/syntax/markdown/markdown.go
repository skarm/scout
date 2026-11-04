// Package markdown projects CommonMark code blocks onto captured source bytes.
// It never renders HTML, loads extensions or follows document references.
package markdown

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/skarm/scout/internal/syntax/source"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

const (
	MaxSourceBytes = 1 << 20
	MaxBlocks      = 512
	MaxSegments    = 8192
	MaxUnitBytes   = 256 << 10
	maxDepth       = 64
	maxNodes       = 8192
	maxOperations  = 1 << 20
)

type Block struct {
	Kind, Info, Failure string
	Span                source.Span
	View                source.View
	Unclosed            bool
}

type Result struct {
	Blocks  []Block
	Opaque  []source.Span
	HTML    bool
	Failure string
}

type rawBlock struct {
	node   ast.Node
	span   source.Span
	closed bool
}

type preparation struct {
	ctx         context.Context
	buffer      []byte
	blocks      []*rawBlock
	opaque      []*rawBlock
	fences      map[ast.Node]*rawBlock
	operations  int
	nodes       int
	inspectHTML bool
}

type stopped struct{ code string }

type parserSession struct {
	grammar parser.Parser
	blocks  []*boundedParser
}

//nolint:gochecknoglobals // Exclusive parser sessions, separated by HTML policy; no source state is retained.
var parserSessions [2]sync.Pool

func borrowParser(inspectHTML bool) (*parserSession, *sync.Pool) {
	index := 0
	if inspectHTML {
		index = 1
	}

	pool := &parserSessions[index]
	if cached := pool.Get(); cached != nil {
		return cached.(*parserSession), pool //nolint:forcetypeassert // This private pool owns only parser sessions.
	}

	session := &parserSession{}
	blocks := parser.DefaultBlockParsers()

	bounded := make([]util.PrioritizedValue, 0, len(blocks))
	for _, value := range blocks {
		if !inspectHTML && value.Value == parser.NewHTMLBlockParser() {
			continue
		}

		block := &boundedParser{BlockParser: value.Value.(parser.BlockParser)} //nolint:forcetypeassert // Goldmark's default list contains block parsers.
		session.blocks = append(session.blocks, block)
		bounded = append(bounded, util.Prioritized(block, value.Priority))
	}

	session.grammar = parser.NewParser(parser.WithBlockParsers(bounded...), parser.WithParagraphTransformers(parser.DefaultParagraphTransformers()...))

	return session, pool
}

// Parse retains completed code blocks if a later block exhausts a limit. The
// start offset skips already inspected frontmatter without changing coordinates.
func Parse(ctx context.Context, original string, start int) Result {
	return parseRange(ctx, original, source.Span{Start: start, End: len(original)}, true)
}

// ParseOpaque inspects code containers inside an HTML block as untrusted raw
// text. HTML visibility never exempts a fence from security analysis. This pass
// has the same bounds, and cannot recursively create more opaque projections.
func ParseOpaque(ctx context.Context, original string, span source.Span) Result {
	return parseRange(ctx, original, span, false)
}

func parseRange(ctx context.Context, original string, span source.Span, inspectHTML bool) Result {
	if ctx == nil || ctx.Err() != nil {
		return Result{Failure: "preparation_cancelled"}
	}

	if span.Start < 0 || span.End < span.Start || span.End > len(original) || span.End-span.Start > MaxSourceBytes {
		return Result{Failure: "markdown_source_limit"}
	}

	p := preparation{ctx: ctx, buffer: []byte(original[span.Start:span.End]), fences: map[ast.Node]*rawBlock{}, inspectHTML: inspectHTML}
	result := Result{Failure: p.parse()}

	result.HTML = len(p.opaque) != 0
	for _, raw := range p.blocks {
		result.Blocks = append(result.Blocks, project(original, span.Start, p.buffer, raw))
	}

	for _, raw := range p.opaque {
		region := blockSpan(raw)
		region.Start += span.Start
		region.End += span.Start
		result.Opaque = append(result.Opaque, region)
	}

	return result
}

func (p *preparation) parse() (failure string) {
	defer func() {
		if value := recover(); value != nil {
			failure = "markdown_parser_failed"
			if limit, ok := value.(stopped); ok {
				failure = limit.code
			}
		}
	}()

	session, pool := borrowParser(p.inspectHTML)
	for _, block := range session.blocks {
		block.owner = p
	}

	completed := false

	defer func() {
		for _, block := range session.blocks {
			block.owner = nil
		}
		// A recovered parser panic can leave initialization or parse state incomplete.
		if completed {
			pool.Put(session)
		}
	}()
	// Only block structure is needed. Inline rendering and extension grammars
	// cannot affect code-block boundaries and are intentionally not installed.
	session.grammar.Parse(text.NewReader(p.buffer))
	p.check(0)

	completed = true

	return ""
}

func (p *preparation) check(depth int) {
	if p.ctx.Err() != nil {
		panic(stopped{code: "preparation_cancelled"})
	}

	p.operations++
	if p.operations > maxOperations || depth >= maxDepth || p.nodes > maxNodes {
		panic(stopped{code: "markdown_structure_limit"})
	}
}

type boundedParser struct {
	parser.BlockParser
	owner *preparation
}

func (b *boundedParser) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	p := b.owner
	p.check(len(pc.OpenedBlocks()))

	_, segment := reader.Position()

	node, state := b.BlockParser.Open(parent, reader, pc)
	if node == nil {
		return node, state
	}

	p.nodes++
	p.check(0)

	switch node.(type) {
	case *ast.HTMLBlock:
		if len(p.blocks)+len(p.opaque) >= MaxBlocks {
			panic(stopped{code: "document_region_limit"})
		}

		start := bytes.LastIndexByte(p.buffer[:segment.Start], '\n') + 1
		p.opaque = append(p.opaque, &rawBlock{node: node, span: source.Span{Start: start, End: segment.Stop}})
	case *ast.CodeBlock, *ast.FencedCodeBlock:
		if len(p.blocks)+len(p.opaque) >= MaxBlocks {
			panic(stopped{code: "document_region_limit"})
		}
		// Include the physical opening line in the region, while code views
		// below retain only the parser's exact content segments.
		start := bytes.LastIndexByte(p.buffer[:segment.Start], '\n') + 1
		end := segment.Stop
		raw := &rawBlock{node: node, span: source.Span{Start: start, End: end}}

		p.blocks = append(p.blocks, raw)
		if _, fenced := node.(*ast.FencedCodeBlock); fenced {
			p.fences[node] = raw
		}
	}

	return node, state
}

func (b *boundedParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	b.owner.check(len(pc.OpenedBlocks()))

	_, segment := reader.PeekLine()

	state := b.BlockParser.Continue(node, reader, pc)
	if raw := b.owner.fences[node]; raw != nil && state&parser.Close != 0 {
		raw.closed = true
		raw.span.End = segment.Stop
	}

	return state
}

func (b *boundedParser) Close(node ast.Node, reader text.Reader, pc parser.Context) {
	b.owner.check(len(pc.OpenedBlocks()))
	b.BlockParser.Close(node, reader, pc)
}

func project(original string, offset int, buffer []byte, raw *rawBlock) Block {
	block := Block{Kind: "indented-code", Span: blockSpan(raw)}
	if fence, ok := raw.node.(*ast.FencedCodeBlock); ok {
		block.Kind, block.Info, block.Unclosed = "fenced-code", string(fence.Language(buffer)), !raw.closed
	}

	lines := raw.node.Lines()
	block.Span.Start += offset
	block.Span.End += offset
	block.View, block.Failure = projectLines(original, offset, lines)

	return block
}

func blockSpan(raw *rawBlock) source.Span {
	span := raw.span

	lines := raw.node.Lines()
	if lines.Len() > 0 {
		span.End = max(span.End, lines.At(lines.Len()-1).Stop)
	}

	if html, ok := raw.node.(*ast.HTMLBlock); ok && html.HasClosure() {
		span.End = max(span.End, html.ClosureLine.Stop)
	}

	return span
}

func projectLines(original string, offset int, lines *text.Segments) (source.View, string) {
	if lines.Len() > MaxSegments {
		return source.View{}, "document_segment_limit"
	}

	spans := make([]source.Span, 0, lines.Len())

	var replacements []source.Replacement

	bytes := 0

	for i := range lines.Len() {
		line := lines.At(i)

		span := source.Span{Start: line.Start + offset, End: line.Stop + offset}
		if span.Start < 0 || span.End < span.Start || span.End > len(original) || line.Padding < 0 || line.Padding > 4 {
			return source.View{}, "source_map_error"
		}

		if line.Padding != 0 {
			// CommonMark may consume only part of a tab's indentation. Map
			// its remaining spaces to that original tab, never invented bytes.
			if span.Start == 0 || original[span.Start-1] != '\t' {
				return source.View{}, "source_map_error"
			}

			span.Start--
			replacements = append(replacements, source.Replacement{Span: source.Span{Start: bytes, End: bytes + 1}, Text: strings.Repeat(" ", line.Padding)})
		}

		bytes += span.End - span.Start
		if bytes+len(replacements)*3 > MaxUnitBytes {
			return source.View{}, "source_limit"
		}

		spans = append(spans, span)
	}

	view, err := source.NewView(original, spans)
	if err == nil && len(replacements) != 0 {
		view, err = view.Replace(replacements)
	}

	if err != nil {
		return source.View{}, "source_map_error"
	}

	return view, ""
}
