package main

import (
	"bytes"
	"context"
	"go/token"
	"slices"
	"strings"
	"unicode"
)

const (
	suppressionJS     = "JavaScript"
	suppressionTS     = "TypeScript"
	suppressionTSX    = "TSX"
	suppressionPython = "Python"
)

type sourceSpan struct{ start, end uint }

type suppressionSyntax struct {
	comments, tokens []sourceSpan
}

func suppressionLanguage(ext string) string {
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return suppressionJS
	case ".ts", ".mts", ".cts":
		return suppressionTS
	case ".tsx":
		return suppressionTSX
	case ".py", ".pyi":
		return suppressionPython
	default:
		return ""
	}
}

func (i inventory) readScriptSuppressions(ctx context.Context, name, lang string, data []byte) {
	if !mayHaveScriptSuppression(lang, data) {
		return
	}

	syntax, err := scanScriptSuppressionSyntax(ctx, lang, data)
	if err != nil {
		i.suppressionGaps[name] = err.Error()
		return
	}

	lines := token.NewFileSet().AddFile(name, -1, len(data))
	lines.SetLinesForContent(data)

	var directives []scriptDirective

	for _, comment := range syntax.comments {
		line := lines.Line(lines.Pos(int(comment.start)))
		endLine := lines.Line(lines.Pos(int(comment.end - 1)))
		text := string(data[comment.start:comment.end])

		directives = append(directives, scriptDirectives(lang, text, line, endLine)...)
	}

	if len(directives) == 0 {
		return
	}

	anchors := scriptCodeLines(lines, data, syntax.tokens)
	for _, directive := range directives {
		key := lintSuppression{name, directive.name, scriptAnchor(anchors, directive)}
		i.suppressions[key] = append(i.suppressions[key], location{name, directive.line})
	}
}

func mayHaveScriptSuppression(lang string, data []byte) bool {
	if lang != suppressionPython {
		return bytes.Contains(data, []byte("@ts-ignore")) || bytes.Contains(data, []byte("eslint-disable"))
	}

	for index := 0; index+4 <= len(data); index++ {
		if data[index]|0x20 == 'n' && bytes.EqualFold(data[index:index+4], []byte("noqa")) {
			return true
		}
	}

	return false
}

type scriptDirective struct {
	name         string
	line, target int
	exactLine    bool
}

func scriptDirectives(lang, text string, line, endLine int) []scriptDirective {
	if lang == suppressionPython {
		return pythonNoqa(text, line)
	}

	body, inline := strings.CutPrefix(text, "//")
	if !inline {
		body = strings.TrimSuffix(strings.TrimPrefix(text, "/*"), "*/")
	}

	lastLine := body[strings.LastIndexByte(body, '\n')+1:]
	if inline {
		lastLine = strings.TrimPrefix(lastLine, "/")
	} else {
		lastLine = strings.TrimLeft(strings.TrimSpace(lastLine), "*/")
	}

	if directiveWord(strings.TrimSpace(lastLine)) == "@ts-ignore" {
		return []scriptDirective{{"@ts-ignore", endLine, endLine + 1, false}}
	}

	return eslintDirectives(body, line, endLine, inline)
}

func eslintDirectives(body string, line, endLine int, inline bool) []scriptDirective {
	words := strings.Fields(body)
	if len(words) == 0 {
		return nil
	}

	name := words[0]
	target, exact := endLine+1, true

	switch name {
	case "eslint-disable":
		if inline {
			return nil
		}

		target, exact = line, false
	case "eslint-disable-line":
		if line != endLine {
			return nil
		}

		target = line
	case "eslint-disable-next-line":
	default:
		return nil
	}

	var rules []string

	for _, word := range words[1:] {
		if strings.HasPrefix(word, "--") {
			break
		}

		rules = append(rules, strings.Split(word, ",")...)
	}

	return scriptDirectivesAt(scriptDirective{name, line, target, exact}, rules)
}

func pythonNoqa(comment string, line int) []scriptDirective {
	for field := range strings.SplitSeq(comment, "#") {
		text := strings.TrimSpace(field)
		if !strings.EqualFold(directiveWord(text), "noqa") {
			continue
		}

		var rules []string

		if codes, ok := strings.CutPrefix(strings.TrimSpace(text[4:]), ":"); ok {
			for _, code := range strings.FieldsFunc(codes, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
				if !noqaCode(code) {
					break
				}

				rules = append(rules, code)
			}
		}

		return scriptDirectivesAt(scriptDirective{"# noqa", line, line, true}, rules)
	}

	return nil
}

func scriptDirectivesAt(directive scriptDirective, rules []string) []scriptDirective {
	scoped := scopedDirectives(directive.name, rules)

	result := make([]scriptDirective, len(scoped))
	for index, name := range scoped {
		directive.name = name
		result[index] = directive
	}

	return result
}

func directiveWord(text string) string {
	if end := strings.IndexFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r == ':' }); end >= 0 {
		return text[:end]
	}

	return text
}

func noqaCode(code string) bool {
	digit := strings.IndexFunc(code, asciiDigit)

	return digit > 0 && !strings.ContainsFunc(code[:digit], func(r rune) bool { return r < 'A' || r > 'Z' }) &&
		!strings.ContainsFunc(code[digit:], func(r rune) bool { return !asciiDigit(r) })
}

type scriptCodeLine struct {
	line   int
	anchor string
}

func scriptCodeLines(file *token.File, data []byte, tokens []sourceSpan) []scriptCodeLine {
	var (
		lines  []scriptCodeLine
		anchor strings.Builder
	)

	line := 0

	for _, span := range tokens {
		start := file.Line(file.Pos(int(span.start)))
		if start != line {
			if line != 0 {
				lines = append(lines, scriptCodeLine{line, anchor.String()})
			}

			anchor.Reset()

			line = start
		}

		text := data[span.start:span.end]
		anchor.Write(text)
		anchor.WriteByte('\x00')

		if end := file.Line(file.Pos(int(span.end - 1))); end > line {
			lines = append(lines, scriptCodeLine{line, anchor.String()})
			anchor.Reset()
			anchor.Write(text[bytes.LastIndexByte(text, '\n')+1:])
			anchor.WriteByte('\x00')

			line = end
		}
	}

	if line != 0 {
		lines = append(lines, scriptCodeLine{line, anchor.String()})
	}

	return lines
}

func scriptAnchor(lines []scriptCodeLine, directive scriptDirective) string {
	index, found := slices.BinarySearchFunc(lines, directive.target, func(line scriptCodeLine, target int) int {
		return line.line - target
	})
	if index < len(lines) && (found || !directive.exactLine) {
		return lines[index].anchor
	}

	return ""
}
