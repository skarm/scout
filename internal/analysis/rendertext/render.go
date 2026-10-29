// Package rendertext inspects finite hidden and rendered-URL carriers without rendering content.
package rendertext

import (
	"context"
	"errors"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/languages/literals"
	"github.com/skarm/scout/internal/analysis/securitytext"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

var (
	hiddenStyle         = regexp.MustCompile(`(?i)(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0*)?|font-size\s*:\s*0(?:px|em|rem|pt|%)?)\s*(?:!important\s*)?(?:;|$)`)
	hiddenDirective     = regexp.MustCompile(`(?i)\b(?:ignore|disregard|override)\b.{0,100}\b(?:instructions?|rules?|system|previous)\b|\b(?:send|upload|transmit|reveal|collect)\b.{0,160}\b(?:api[ _-]?keys?|credentials?|secrets?|tokens?|private|conversation)\b|\b(?:execute|run|install|eval|exec)\b.{0,160}\b(?:curl|wget|bash|shell|script|command|payload)\b|\b(?:curl|wget)\b.{0,256}\|\s*(?:ba)?sh\b`)
	markdownDestination = regexp.MustCompile(`!?\[[^\]\r\n]{0,512}\]\([\t ]*(https?://[^\t\r\n )]+)`)
	templateValue       = regexp.MustCompile(`\$\{([^}]{1,256})\}|\{\{([^}]{1,256})\}\}`)
)

var frontmatterBoundary = regexp.MustCompile(`(?m)^---[\t ]*\r?$`)

type (
	match  = check.Match
	result = check.Result
)

type renderCheck struct{ id string }

type renderCollector struct {
	result result
	limit  int
}

type renderAttr struct {
	value string
	span  source.Span
}
type renderTag struct {
	name            string
	span            source.Span
	attrs           map[string]renderAttr
	closing, hidden bool
}

func Rules() []check.Analyzer {
	return []check.Analyzer{renderCheck{id: ruleHI001}, renderCheck{id: ruleRX001}}
}

// Visible masks comments, hidden HTML and frontmatter for declaration comparison.
// It confers no trust and never suppresses raw artifact checks.
func Visible(ctx context.Context, text string) (string, error) {
	_, hidden, err := renderRegions(ctx, text)
	masked := []byte(text)

	for _, s := range hidden {
		for i := s.Start; i < s.End; i++ {
			masked[i] = ' '
		}
	}

	if strings.HasPrefix(text, "---\n") || strings.HasPrefix(text, "---\r\n") {
		if loc := frontmatterBoundary.FindAllStringIndex(text, 3); len(loc) > 1 {
			for i := 0; i < loc[1][1]; i++ {
				masked[i] = ' '
			}
		}
	}

	return string(masked), err
}

func (a renderCheck) Rule() report.Rule {
	title, category := "Hidden HTML contains an active instruction", "hidden-instructions"
	if a.id == ruleRX001 {
		title, category = "Rendered URL interpolates sensitive data", "credential-egress"
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       title,
		Description: title,
		Severity:    report.High,
		Category:    category,
		Method:      "bounded-render-carrier-analysis",
		Limitation:  "Selected HTML attributes/CSS, comments and inline Markdown/HTML URLs; not a browser, CSS cascade or full CommonMark interpreter. Template sensitivity is a lexical observation, not proof of substitution or a network request. No documentation/fence/path exemptions. Raw text checks remain active.",
	}
}
func (renderCheck) AppliesTo(document.File) bool { return true }
func (a renderCheck) Find(ctx context.Context, d document.File, budget int) (result, error) {
	text := d.Artifact().Content()
	tags, hidden, err := renderRegions(ctx, text)

	out := renderCollector{limit: budget}
	if a.id == ruleHI001 {
		err = errors.Join(err, inspectHidden(ctx, text, hidden, &out))
	} else {
		inspectHTMLURLs(tags, &out)
		err = errors.Join(err, inspectMarkdownURLs(ctx, text, &out))
	}

	return out.result, errors.Join(err, ctx.Err())
}

func (c *renderCollector) add(s source.Span) {
	if len(c.result.Matches) >= c.limit {
		c.result.Truncated = true
		return
	}

	c.result.Matches = append(c.result.Matches, match{Start: s.Start, End: s.End})
}

func inspectHidden(ctx context.Context, text string, spans []source.Span, out *renderCollector) error {
	var err error

	for _, s := range spans {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		v := html.UnescapeString(text[s.Start:s.End])
		matched := hiddenDirective.MatchString(v)

		views, limited := securitytext.Views(ctx, v)
		for _, view := range views {
			matched = matched || hiddenDirective.MatchString(view.Text())
		}

		if matched {
			out.add(s)
		}

		if limited {
			err = errors.New("hidden HTML reconstruction limit")
		}

		if out.result.Truncated {
			break
		}
	}

	return err
}

func inspectHTMLURLs(tags []renderTag, out *renderCollector) {
	for _, t := range tags {
		if t.name != "img" && t.name != "a" && t.name != "image" && t.name != "source" {
			continue
		}

		for _, key := range []string{"src", "href", "srcset"} {
			if attr, ok := t.attrs[key]; ok && sensitiveTemplateURL(attr.value) {
				out.add(attr.span)
			}
		}

		if out.result.Truncated {
			return
		}
	}
}

func inspectMarkdownURLs(ctx context.Context, text string, out *renderCollector) error {
	for candidate, loc := range markdownDestination.FindAllStringSubmatchIndex(text, -1) {
		if candidate >= 4096 {
			return errors.New("render destination candidate limit")
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if sensitiveTemplateURL(text[loc[2]:loc[3]]) {
			out.add(source.Span{Start: loc[2], End: loc[3]})
		}

		if out.result.Truncated {
			return nil
		}
	}

	return nil
}

func sensitiveTemplateURL(value string) bool {
	v := html.UnescapeString(value)
	if decoded, e := url.QueryUnescape(v); e == nil {
		v = decoded
	}

	if !strings.Contains(strings.ToLower(v), "http://") && !strings.Contains(strings.ToLower(v), "https://") {
		return false
	}

	for _, m := range templateValue.FindAllStringSubmatch(v, 128) {
		name := m[1] + m[2]
		if literals.SensitiveName(name) || strings.Contains(strings.ToLower(name), "conversation") || strings.Contains(strings.ToLower(name), "private") {
			return true
		}
	}

	return false
}

// This lexer owns only its finite attribute grammar. It does not declare an
// unsupported HTML document fully parsed; document preparation owns that gap.
func renderRegions(ctx context.Context, text string) ([]renderTag, []source.Span, error) {
	if len(text) > securitytext.MaxBytes {
		return nil, nil, errors.New("render carrier byte limit")
	}

	var (
		tags   []renderTag
		hidden []source.Span
		stack  []renderTag
	)

	for at := 0; at < len(text); {
		if ctx.Err() != nil || !analysisbudget.Consume(ctx, 1) {
			return tags, hidden, errors.New("render carrier operation limit")
		}

		n := strings.IndexByte(text[at:], '<')
		if n < 0 {
			break
		}

		at += n
		if strings.HasPrefix(text[at:], "<!--") {
			end := strings.Index(text[at+4:], "-->")
			if end < 0 {
				hidden = append(hidden, source.Span{Start: at, End: len(text)})
				break
			}

			end += at + 7
			hidden = append(hidden, source.Span{Start: at, End: end})
			at = end

			continue
		}

		end := renderTagEnd(text, at)
		if end == 0 {
			at++
			continue
		}

		t := parseRenderTag(text, at, end)
		at = end

		if t.name == "" {
			continue
		}

		tags = append(tags, t)
		if len(tags) > 4096 {
			return tags, hidden, errors.New("render tag limit")
		}

		if t.closing {
			var regions []source.Span

			stack, regions = closeRenderStack(stack, t.name, end)
			hidden = append(hidden, regions...)
		} else if !strings.HasSuffix(strings.TrimSpace(text[t.span.Start:t.span.End-1]), "/") && !voidRenderTag(t.name) {
			if len(stack) >= 64 {
				return tags, hidden, errors.New("render nesting limit")
			}

			stack = append(stack, t)
		}
	}

	for _, open := range stack {
		if open.hidden {
			hidden = append(hidden, source.Span{Start: open.span.Start, End: len(text)})
		}
	}

	return tags, hidden, nil
}

func voidRenderTag(name string) bool {
	return name == "img" || name == "br" || name == "hr" || name == "input" || name == "meta" || name == "link" || name == "source" || name == "wbr" || name == "area" || name == "base" || name == "embed" || name == "param" || name == "track" || name == "col"
}

func renderTagEnd(text string, start int) int {
	quote := byte(0)

	for at := start + 1; at < min(len(text), start+8192); at++ {
		c := text[at]
		if quote != 0 {
			if c == quote {
				quote = 0
			}

			continue
		}

		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return at + 1
		case '<':
			return 0
		}
	}

	return 0
}

func parseRenderTag(text string, start, end int) renderTag {
	t := renderTag{span: source.Span{Start: start, End: end}, attrs: map[string]renderAttr{}}

	i := start + 1
	if i < end && text[i] == '/' {
		t.closing = true
		i++
	}

	begin := i
	for i < end && (text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z' || text[i] >= '0' && text[i] <= '9') {
		i++
	}

	t.name = strings.ToLower(text[begin:i])
	if t.name == "" {
		return t
	}

	for i < end-1 {
		for i < end-1 && (unicode.IsSpace(rune(text[i])) || text[i] == '/') {
			i++
		}

		begin = i
		for i < end-1 && !unicode.IsSpace(rune(text[i])) && !strings.ContainsRune("=/>\"'", rune(text[i])) {
			i++
		}

		if begin == i {
			i++
			continue
		}

		key := strings.ToLower(text[begin:i])

		var value string

		value, i = renderAttributeValue(text, i, end)
		// Duplicate hidden attributes cannot cancel an earlier hidden value.
		if key == "hidden" || key == "aria-hidden" && strings.EqualFold(value, "true") || key == "style" && hiddenStyle.MatchString(value) {
			t.hidden = true
		}

		if previous, ok := t.attrs[key]; ok {
			value = previous.value + "\n" + value
			begin = previous.span.Start
		}

		t.attrs[key] = renderAttr{value: html.UnescapeString(value), span: source.Span{Start: begin, End: i}}
	}

	return t
}

func closeRenderStack(stack []renderTag, name string, end int) ([]renderTag, []source.Span) {
	for i, s := range slices.Backward(stack) {
		if s.name != name {
			continue
		}

		var hidden []source.Span
		for _, open := range stack[i:] {
			if open.hidden {
				hidden = append(hidden, source.Span{Start: open.span.Start, End: end})
			}
		}

		return stack[:i], hidden
	}

	return stack, nil
}

func renderAttributeValue(text string, at, end int) (string, int) {
	at = renderSpaceEnd(text, at, end)
	if at >= end-1 || text[at] != '=' {
		return "", at
	}

	at = renderSpaceEnd(text, at+1, end)

	start := at
	if at < end-1 && (text[at] == '\'' || text[at] == '"') {
		quote := text[at]
		at++

		start = at
		for at < end-1 && text[at] != quote {
			at++
		}

		value := text[start:at]
		if at < end-1 {
			at++
		}

		return value, at
	}

	for at < end-1 && !unicode.IsSpace(rune(text[at])) {
		at++
	}

	return text[start:at], at
}

func renderSpaceEnd(text string, at, end int) int {
	for at < end-1 && unicode.IsSpace(rune(text[at])) {
		at++
	}

	return at
}
