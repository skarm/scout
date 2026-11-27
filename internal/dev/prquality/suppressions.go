package main

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"slices"
	"strings"
)

type lintSuppression struct {
	path, directive, anchor string
}

type suppressionComment struct {
	line       int
	directives []string
}

func (i inventory) readGoSuppressions(name string, data []byte) {
	if !bytes.Contains(data, []byte("nolint")) && !bytes.Contains(data, []byte("lint:")) &&
		!bytes.Contains(data, []byte("#nosec")) && !bytes.Contains(data, []byte("gosec:disable")) {
		return
	}

	file := token.NewFileSet().AddFile(name, -1, len(data))
	comments, code, commentStarts := scanGoSuppressions(file, data)
	anchors := make(map[int]string)

	for _, comment := range comments {
		idx, _ := slices.BinarySearch(code, comment.line)
		for _, directive := range comment.directives {
			anchor := ""

			if idx < len(code) && !strings.HasPrefix(directive, "lint:file-ignore ") {
				line := code[idx]
				if _, ok := anchors[line]; !ok {
					anchors[line] = goLineAnchor(file, data, line, commentStarts[line])
				}

				anchor = anchors[line]
			}

			key := lintSuppression{name, directive, anchor}
			i.suppressions[key] = append(i.suppressions[key], location{name, comment.line})
		}
	}
}

func scanGoSuppressions(file *token.File, data []byte) ([]suppressionComment, []int, map[int]int) {
	var lexer scanner.Scanner
	lexer.Init(file, data, nil, scanner.ScanComments)

	var (
		comments []suppressionComment
		code     []int
	)

	commentStarts := map[int]int{}

	for pos, kind, lit := lexer.Scan(); kind != token.EOF; pos, kind, lit = lexer.Scan() {
		position := file.PositionFor(pos, false)
		if kind == token.COMMENT {
			if _, found := commentStarts[position.Line]; !found {
				commentStarts[position.Line] = position.Offset
			}

			if directives := goSuppressionDirectives(lit); len(directives) != 0 {
				comments = append(comments, suppressionComment{position.Line, directives})
			}
		} else if !(kind == token.SEMICOLON && lit == "\n") && (len(code) == 0 || code[len(code)-1] != position.Line) {
			code = append(code, position.Line)
		}
	}

	return comments, code, commentStarts
}

func goLineAnchor(file *token.File, data []byte, line, commentStart int) string {
	start := file.Offset(file.LineStart(line))

	text := data[start:]
	if end := bytes.IndexByte(text, '\n'); end >= 0 {
		text = text[:end]
	}

	if commentStart > start {
		text = text[:commentStart-start]
	}

	var lexer scanner.Scanner
	lexer.Init(token.NewFileSet().AddFile("", -1, len(text)), text, nil, 0)

	var anchor strings.Builder

	for _, kind, lit := lexer.Scan(); kind != token.EOF; _, kind, lit = lexer.Scan() {
		if kind == token.SEMICOLON && lit == "\n" {
			continue
		}

		if lit == "" {
			lit = kind.String()
		}

		anchor.WriteString(lit)
		anchor.WriteByte('\x00')
	}

	return anchor.String()
}

func goSuppressionDirectives(comment string) []string {
	text, lineComment := strings.CutPrefix(comment, "//")
	if !lineComment {
		text = strings.TrimSuffix(strings.TrimPrefix(comment, "/*"), "*/")
	}

	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil
	}

	name, ids := fields[0], fields[1:]
	switch {
	case lineComment && name == "nolint":
		return []string{name}
	case lineComment && strings.HasPrefix(name, "nolint:"):
		targets, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "nolint:")), "//")
		return scopedDirectives("nolint", strings.Split(targets, ","))
	case lineComment && (name == "lint:ignore" || name == "lint:file-ignore"):
		if len(ids) != 0 {
			return scopedDirectives(name, strings.Split(ids[0], ","))
		}
	case name == "#nosec" || name == "gosec:disable":
		var rules []string

		for _, field := range ids {
			if strings.HasPrefix(field, "--") {
				break
			}

			for rule := range strings.SplitSeq(field, ",") {
				if len(rule) == 4 && rule[0] == 'G' && asciiDigit(rune(rule[1])) && asciiDigit(rune(rule[2])) && asciiDigit(rune(rule[3])) {
					rules = append(rules, rule)
				}
			}
		}

		return scopedDirectives(name, rules)
	}

	return nil
}

func scopedDirectives(name string, rules []string) []string {
	var directives []string

	seen := make(map[string]bool)

	for _, rule := range rules {
		if rule = strings.TrimSpace(rule); rule != "" && !seen[rule] {
			seen[rule] = true
			directives = append(directives, name+" "+rule)
		}
	}

	if len(directives) == 0 {
		return []string{name}
	}

	return directives
}

func addedSuppressions(before, after inventory) []warning {
	var warnings []warning

	for name, reason := range before.suppressionGaps {
		if after.suppressionGaps[name] == "" {
			warnings = append(warnings, warning{location{name, 0}, true, "Lint suppression check incomplete", reason})
		}
	}

	for name, reason := range after.suppressionGaps {
		warnings = append(warnings, warning{location{name, 0}, false, "Lint suppression check incomplete", reason})
	}

	for key, locations := range after.suppressions {
		count := priorSuppressionCount(key, before.suppressions, after.suppressions)
		if count >= len(locations) || before.suppressionGaps[key.path] != "" || after.suppressionGaps[key.path] != "" {
			continue
		}

		category, detail := "Lint suppression added", fmt.Sprintf("New lint directive %q.", key.directive)
		if strings.HasSuffix(key.path, ".go") {
			category, detail = "Go lint suppression added", fmt.Sprintf("New Go lint directive %q.", key.directive)
		}

		for _, loc := range locations[count:] {
			warnings = append(warnings, warning{loc, false, category, detail})
		}
	}

	return warnings
}

func priorSuppressionCount(key lintSuppression, before, after map[lintSuppression][]location) int {
	count := len(before[key])

	space := strings.LastIndexByte(key.directive, ' ')
	if space < 0 {
		return count
	}

	name := key.directive[:space]
	switch name {
	case "nolint", "#nosec", "gosec:disable", "eslint-disable", "eslint-disable-line", "eslint-disable-next-line", "# noqa":
		key.directive = name
		return count + max(0, len(before[key])-len(after[key]))
	default:
		return count
	}
}
