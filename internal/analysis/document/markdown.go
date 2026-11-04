package document

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/markdown"
)

func (f *filePreparation) markdownBody(ctx context.Context, text string, at int) {
	if len(text)-at > MaxScanBytes-f.budget.markdownBytes {
		f.issue("markdown_scan_budget", "Aggregate Markdown parsing budget exhausted; raw checks remain available.")
		return
	}

	f.budget.markdownBytes += len(text) - at

	result := markdown.Parse(ctx, text, at)
	if !f.publishMarkdown(ctx, result) {
		return
	}

	for _, span := range result.Opaque {
		if span.End-span.Start > MaxScanBytes-f.budget.markdownBytes {
			f.issue("markdown_scan_budget", "Aggregate Markdown parsing budget exhausted; raw checks remain available.")
			return
		}

		f.budget.markdownBytes += span.End - span.Start
		if !f.publishMarkdown(ctx, markdown.ParseOpaque(ctx, text, span)) {
			return
		}
	}
}

func (f *filePreparation) publishMarkdown(ctx context.Context, result markdown.Result) bool {
	if result.Failure != "" {
		f.issue(result.Failure, "Markdown preparation stopped at a cancellation, parser failure or structural budget; available code blocks and raw checks remain available.")
	}

	if result.HTML {
		f.issue("markdown_container_unsupported", "HTML block boundaries were parsed, but HTML and embedded runtime semantics remain unverified; raw checks still run.")
	}

	for _, block := range result.Blocks {
		if ctx.Err() != nil {
			f.issue("preparation_cancelled", "Document preparation was cancelled.")
			return false
		}

		lang := fenceLanguage(block.Info)
		if block.Kind == "indented-code" {
			lang = indentedLanguage(block.View.Text())
		}

		if !f.region(region{Kind: block.Kind, Language: lang, Span: block.Span}) {
			return false
		}

		if block.Unclosed {
			f.issue("unclosed_fence", "A fence has no explicit closing delimiter before its container or file ends; its content remains subject to analysis.")
		}

		if block.Failure != "" {
			code := block.Failure
			if code == "source_limit" {
				code = lang + "_source_limit"
			}

			f.issue(code, "An embedded source view exceeded a byte/segment budget or could not be mapped to captured bytes.")

			continue
		}

		if strings.TrimSpace(block.View.Text()) != "" {
			f.addUnit(ctx, lang, block.Kind, block.Span, block.View)
		}
	}

	return true
}

func indentedLanguage(text string) string {
	id := language.Unknown

	for _, hint := range language.Detect("", text) {
		if !language.Structured(hint.Language) {
			continue
		}

		if id != language.Unknown && id != hint.Language {
			return language.Unknown
		}

		id = hint.Language
	}

	return id
}
