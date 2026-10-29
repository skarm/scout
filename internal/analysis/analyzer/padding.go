// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted P9 padding thresholds/guards; all offsets remain original UTF-8 bytes.

package analyzer

import (
	"context"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/textmatch"
)

type paddingLine struct {
	text       string
	start, end int
}

func paddingMatches(ctx context.Context, name, text string, budget int) (Result, error) {
	out := Result{}

	if budget < 1 {
		return Result{Truncated: true}, nil
	}

	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	if paddingExcluded(name, text) {
		return out, nil
	}

	emit := paddingEmitter(&out, budget)

	lines := paddingLines(text)
	if err := paddingLineRuns(ctx, lines, emit); err != nil {
		return out, err
	}

	markdown := strings.EqualFold(path.Ext(name), ".md") || strings.EqualFold(path.Ext(name), ".markdown")

	aligned := map[int]map[int]bool{}
	if markdown {
		aligned = paddingTableAlignment(lines)
	}

	if err := paddingColumns(ctx, lines, markdown, aligned, emit); err != nil {
		return out, err
	}

	if err := paddingRuneRuns(ctx, text, emit); err != nil {
		return out, err
	}

	paddingDuplicateLines(lines, emit)

	return out, ctx.Err()
}

func paddingEmitter(out *Result, budget int) func(int, int) {
	return func(start, end int) {
		if start >= end {
			return
		}

		for _, m := range out.Matches {
			if start < m.End && end > m.Start {
				return
			}
		}

		if len(out.Matches) >= budget {
			out.Truncated = true
			return
		}

		out.Matches = append(out.Matches, Match{Start: start, End: end})
	}
}

func paddingChar(r rune) bool {
	return r == ' ' || strings.ContainsRune("\t\n\r\v\f\u200b\u200c\u200d\u2060\ufeff\u0085\u180e", r) || unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp)
}

func paddingOnly(s string) bool {
	for _, r := range s {
		if !paddingChar(r) {
			return false
		}
	}

	return true
}

func paddingTablePipes(s string) ([]int, bool) {
	sTrim := strings.TrimSpace(s)
	if !strings.HasPrefix(sTrim, "|") || !strings.HasSuffix(sTrim, "|") {
		return nil, false
	}

	var out []int

	column := 0

	for _, r := range s {
		if r == '|' {
			out = append(out, column)
		}

		column++
	}

	return out, true
}

func paddingLines(text string) []paddingLine {
	lines := make([]paddingLine, 0, strings.Count(text, "\n")+1)

	start := 0
	for end, r := range text {
		if end < start {
			continue // The LF half of a CRLF separator was already consumed.
		}

		switch r {
		case '\r', '\n', '\u0085', '\u2028', '\u2029':
			width := utf8.RuneLen(r)
			if r == '\r' && end+1 < len(text) && text[end+1] == '\n' {
				width++
			}

			lines = append(lines, paddingLine{text: text[start:end], start: start, end: end + width})
			start = end + width
		}
	}

	lines = append(lines, paddingLine{text: text[start:], start: start, end: len(text)})

	return lines
}

func paddingLineRuns(ctx context.Context, lines []paddingLine, emit func(int, int)) error {
	for i := 0; i < len(lines); {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if !paddingOnly(lines[i].text) {
			i++
			continue
		}

		j := i + 1
		for j < len(lines) && paddingOnly(lines[j].text) {
			j++
		}

		if j-i >= 20 {
			emit(lines[i].start, lines[j-1].end)
		}

		i = j
	}

	return nil
}

// A table layout is admitted only by a header plus delimiter row. Pipe
// positions become alignment exemptions only for rows of that same shape.
type paddingTableLayout struct{ pipes []int }

func readPaddingTable(header, delimiter string) *paddingTableLayout {
	headerPipes, headerOK := paddingTablePipes(header)

	delimiterPipes, delimiterOK := paddingTablePipes(delimiter)
	if !headerOK || !delimiterOK || len(headerPipes) != len(delimiterPipes) {
		return nil
	}

	cells := strings.Split(strings.TrimSpace(delimiter), "|")
	for _, cell := range cells[1 : len(cells)-1] {
		if !paddingDelimiter(cell) {
			return nil
		}
	}

	return &paddingTableLayout{pipes: delimiterPipes}
}

func (t paddingTableLayout) row(text string) (map[int]bool, bool) {
	pipes, ok := paddingTablePipes(text)
	if !ok || len(pipes) != len(t.pipes) {
		return nil, false
	}

	aligned := map[int]bool{}

	for i, position := range pipes {
		if position == t.pipes[i] {
			aligned[position] = true
		}
	}

	return aligned, true
}

func paddingTableAlignment(lines []paddingLine) map[int]map[int]bool {
	aligned := map[int]map[int]bool{}

	for i := 0; i+1 < len(lines); i++ {
		table := readPaddingTable(lines[i].text, lines[i+1].text)
		if table == nil {
			continue
		}

		aligned[i], _ = table.row(lines[i].text)

		j := i + 2
		for j < len(lines) {
			row, ok := table.row(lines[j].text)
			if !ok {
				break
			}

			aligned[j] = row
			j++
		}

		i = j - 1
	}

	return aligned
}

func paddingColumns(ctx context.Context, lines []paddingLine, markdown bool, aligned map[int]map[int]bool, emit func(int, int)) error {
	fence := paddingFence{}

	for i, line := range lines {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if markdown && fence.observe(strings.TrimSpace(line.text)) {
			continue
		}

		paddingColumnRuns(line, aligned[i], emit)
	}

	return nil
}

func paddingColumnRuns(line paddingLine, aligned map[int]bool, emit func(int, int)) {
	runStart, count, column := -1, 0, 0
	onlySpaces := true

	flush := func(at int) {
		if count >= 80 && !(onlySpaces && aligned[column]) {
			emit(line.start+runStart, line.start+at)
		}

		runStart = -1
		count = 0
		onlySpaces = true
	}
	for at, r := range line.text {
		if paddingChar(r) {
			if runStart < 0 {
				runStart = at
			}

			count++
			onlySpaces = onlySpaces && r == ' '
		} else {
			flush(at)
		}

		column++
	}

	flush(len(line.text))
}

// Byte padding and repeated glyphs are separate run grammars. Each owns its
// start/count and flush rule; both retain original UTF-8 byte coordinates.
type paddingByteRun struct{ start, bytes int }

func (r *paddingByteRun) consume(at, size int, padding bool, emit func(int, int)) {
	if padding {
		if r.start < 0 {
			r.start = at
		}

		r.bytes += size

		return
	}

	r.flush(at, emit)
}

func (r *paddingByteRun) flush(end int, emit func(int, int)) {
	if r.bytes > 2048 {
		emit(r.start, end)
	}

	r.start, r.bytes = -1, 0
}

type paddingGlyphRun struct {
	last         rune
	start, count int
}

func (r *paddingGlyphRun) consume(at int, char rune, emit func(int, int)) {
	if char != r.last {
		r.flush(at, emit)
		r.start, r.count = at, 0
	}

	r.last, r.count = char, r.count+1
}

func (r *paddingGlyphRun) flush(end int, emit func(int, int)) {
	if r.count >= 512 && !paddingChar(r.last) {
		emit(r.start, end)
	}
}

func paddingRuneRuns(ctx context.Context, text string, emit func(int, int)) error {
	padding := paddingByteRun{start: -1}
	repeated := paddingGlyphRun{last: -1}
	paddingBytes := 0

	for at, char := range text {
		if at%4096 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		size, isPadding := utf8.RuneLen(char), paddingChar(char)
		if isPadding {
			paddingBytes += size
		}

		padding.consume(at, size, isPadding, emit)
		repeated.consume(at, char, emit)
	}

	padding.flush(len(text), emit)
	repeated.flush(len(text), emit)

	if len(text) > 4096 && paddingBytes*10 > len(text)*9 {
		emit(0, len(text))
	}

	return nil
}

func paddingExcluded(name, text string) bool {
	for _, glob := range []string{"*.min.js", "*.min.css", "*.lock", "package-lock.json", "yarn.lock", "*.svg", "*.map"} {
		if match, _ := path.Match(glob, name); match {
			return true
		}
	}

	chars := utf8.RuneCountInString(text)

	return chars == 0 || strings.Count(text, "\ufffd")*10 > chars*3
}

func paddingDuplicateLines(lines []paddingLine, emit func(int, int)) {
	for i := 0; i < len(lines); {
		j := i + 1
		for j < len(lines) && lines[j].text == lines[i].text && strings.TrimSpace(lines[i].text) != "" {
			j++
		}

		if j-i >= 64 {
			emit(lines[i].start, lines[j-1].end)
		}

		i = j
	}
}

type paddingFence struct {
	marker byte
	width  int
}

func (f *paddingFence) observe(line string) bool {
	fenced := f.marker != 0

	marker, width := textmatch.FencePrefix(line)
	if width == 0 {
		return fenced
	}

	fenced = true

	if f.marker == 0 {
		f.marker, f.width = marker, width
	} else if f.marker == marker && width >= f.width {
		f.marker = 0
	}

	return fenced
}
