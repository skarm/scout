// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified Go implementation of SkillSpector security views. Source mapping,
// aggregate budgets and conservative marker grammar are specific to Scout.

// Package securitytext builds bounded, source-mapped views of security-relevant text.
package securitytext

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/source"
)

const (
	MaxBytes     = 1 << 20
	MaxChanges   = 16384
	MaxScanBytes = 16 << 20
)

// Security words are reconstructed only with bounded separator runs. This
// handles letter spacing, line wraps and punctuation without rewriting prose
// arbitrarily or granting exemptions to quoted examples.
//
//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var reconstruction = func() []reconstructionPattern {
	words := strings.Fields("instructions instruction previous forget you must disregard restrictions restriction constraints constraint security system developer override jailbreak ignore reveal disclose transmit credentials credential passwords password environment memory exfiltrate bypass safety prompt prompts refuse never upload execute hidden send user data secret token tokens private access api key keys collect history conversation external remote endpoint server all every the your their with to via run shell bash curl wget do not")
	sort.SliceStable(words, func(i, j int) bool { return len(words[i]) > len(words[j]) })

	out := make([]reconstructionPattern, 0, len(words))

	for _, word := range words {
		letters := strings.Split(word, "")
		out = append(out, reconstructionPattern{
			word:       word,
			expression: regexp.MustCompile(`(?i)\b` + strings.Join(letters, `[\s\p{Z}\p{P}\p{S}\p{M}\p{Nd}\x{115F}-\x{1160}\x{3164}\x{FFA0}]{0,8}`) + `\b\p{M}{0,8}`),
		})
	}

	return out
}()

//nolint:gochecknoglobals // Read-only Unicode control-name metadata shared by text projections.
var controlOverrides = map[rune]string{0x130: "i", 0x85: "\n", 0x2028: "\n", 0x2029: "\n", 0: "", 0x034f: ""}

type reconstructionPattern struct {
	word       string
	expression *regexp.Regexp
}

// Views excludes raw text, which all callers must continue to inspect.
// A limited result always requires an incomplete inspection outcome.
func Views(ctx context.Context, text string) (views []source.View, limited bool) {
	if ctx.Err() != nil || len(text) > MaxBytes || !utf8.ValidString(text) {
		return nil, true
	}

	base, err := source.NewView(text, []source.Span{{Start: 0, End: len(text)}})
	if err != nil {
		return nil, true
	}

	views, limited = normalizedViews(ctx, base, views)
	if limited {
		return views, true
	}

	changes, limited := encodedReplacements(ctx, text)
	if limited {
		return views, true
	}

	if len(changes) == 0 {
		return views, false
	}

	decoded, err := base.Replace(changes)
	if err != nil {
		return views, true
	}

	views = append(views, decoded)

	return normalizedViews(ctx, decoded, views)
}

func normalizedViews(ctx context.Context, base source.View, views []source.View) ([]source.View, bool) {
	changes, limited := controlReplacements(ctx, base.Text())
	if limited {
		return views, true
	}

	if len(changes) > 0 {
		var err error

		base, err = base.Replace(changes)
		if err != nil || len(base.Text()) > MaxBytes {
			return views, true
		}

		views = append(views, base)
	}

	return derivedViews(ctx, base, views)
}

func controlReplacements(ctx context.Context, text string) ([]source.Replacement, bool) {
	changes := make([]source.Replacement, 0)

	for at, r := range text {
		if at%1024 == 0 && ctx.Err() != nil {
			return changes, true
		}

		n := utf8.RuneLen(r)

		replacement, ok := securityRuneReplacement(r)

		if ok {
			changes = append(changes, source.Replacement{Span: source.Span{Start: at, End: at + n}, Text: replacement})
		}

		if len(changes) > MaxChanges {
			return changes, true
		}
	}

	return changes, false
}

func securityRuneReplacement(r rune) (string, bool) {
	if value, ok := controlOverrides[r]; ok {
		return value, true
	}
	// Token-bridging controls never suppress the raw inspection view.
	if unicode.Is(unicode.Cf, r) || variationSelector(r) {
		return "", true
	}

	value, ok := skeleton[r]

	return value, ok
}

func variationSelector(r rune) bool {
	return r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0100 && r <= 0xe01ef
}

func derivedViews(ctx context.Context, base source.View, views []source.View) ([]source.View, bool) {
	for _, transform := range []func(context.Context, string) []source.Replacement{markup, reconstruct} {
		changes := transform(ctx, base.Text())
		if ctx.Err() != nil || len(changes) > MaxChanges {
			return views, true
		}

		if len(changes) > 0 {
			v, err := base.Replace(changes)
			if err != nil {
				return views, true
			}

			base = v
			views = append(views, base)
		}
	}

	changes, limited := declaredMarkers(ctx, base.Text())
	if limited {
		return views, true
	}

	if len(changes) > 0 {
		v, e := base.Replace(changes)
		if e != nil {
			return views, true
		}

		views = append(views, v)
	}

	return views, false
}

// Strip balanced inline Markdown emphasis/code markers in a derived view only.
// Delimiters inside identifiers and fenced blocks are not guessed as markup.
func markup(ctx context.Context, text string) []source.Replacement {
	out := make([]source.Replacement, 0)

	for at := 0; at < len(text); {
		if at%1024 == 0 && ctx.Err() != nil {
			return out
		}

		marker := markupMarker(text[at:])

		if marker == "" {
			_, size := utf8.DecodeRuneInString(text[at:])
			at += size

			continue
		}

		start, valid := markupOpening(text, at, marker)
		if !valid {
			at = start
			continue
		}

		end, valid := markupClosing(text, start, marker)
		if !valid {
			at = start
			continue
		}

		out = append(out, source.Replacement{Span: source.Span{Start: at, End: start}}, source.Replacement{Span: source.Span{
			Start: end,
			End:   end + len(marker),
		}})
		if len(out) > MaxChanges {
			return out
		}

		at = end + len(marker)
	}

	return out
}

func markupMarker(text string) string {
	for _, marker := range []string{"**", "__", "~~", "`", "*", "_"} {
		if strings.HasPrefix(text, marker) {
			return marker
		}
	}

	return ""
}

func markupOpening(text string, at int, marker string) (int, bool) {
	before := ' '
	if at > 0 {
		before, _ = utf8.DecodeLastRuneInString(text[:at])
	}

	start := at + len(marker)
	if start >= len(text) || unicode.IsLetter(before) || unicode.IsDigit(before) || text[start] == marker[0] || unicode.IsSpace(rune(text[start])) {
		return start, false
	}

	return start, true
}

func markupClosing(text string, start int, marker string) (int, bool) {
	bound := min(len(text), start+1024)

	end := strings.Index(text[start:bound], marker)
	if end < 0 {
		return start, false
	}

	end += start
	if strings.ContainsAny(text[start:end], "\r\n") || end == start {
		return start, false
	}

	after := ' '
	if end+len(marker) < len(text) {
		after, _ = utf8.DecodeRuneInString(text[end+len(marker):])
	}

	if unicode.IsLetter(after) || unicode.IsDigit(after) {
		return start, false
	}

	return end, true
}

func reconstruct(ctx context.Context, text string) []source.Replacement {
	changes := make([]source.Replacement, 0)
	letters, ascii := reconstructionLetters(text)

	for _, p := range reconstruction {
		if ctx.Err() != nil {
			return changes
		}

		if ascii && !strings.Contains(letters, p.word) {
			continue
		}

		matches := p.expression.FindAllStringIndex(text, MaxChanges+1)
		if len(matches) > MaxChanges {
			return make([]source.Replacement, MaxChanges+1)
		}

		for _, loc := range matches {
			matched := text[loc[0]:loc[1]]

			normalized := reconstructedWord(matched)

			if normalized != matched {
				changes = append(changes, source.Replacement{
					Span: source.Span{Start: loc[0], End: loc[1]},
					Text: normalized,
				})
			}

			if len(changes) > MaxChanges {
				return changes
			}
		}
	}

	return nonOverlappingChanges(changes)
}

// On ASCII inputs every allowed separator is a non-letter. A regex match
// therefore implies the word occurs in this letter stream. Boundaries and gap
// lengths are still checked by RE2; Unicode/folding inputs bypass this filter.
func reconstructionLetters(text string) (string, bool) {
	for i := range len(text) {
		if text[i] >= utf8.RuneSelf {
			return "", false
		}
	}

	var letters strings.Builder
	letters.Grow(len(text))

	for i := range len(text) {
		c := text[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}

		if c >= 'a' && c <= 'z' {
			letters.WriteByte(c)
		}
	}

	return letters.String(), true
}

func reconstructedWord(matched string) string {
	var b strings.Builder

	for _, r := range matched {
		if unicode.IsLetter(r) && !letterFiller(r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

func nonOverlappingChanges(changes []source.Replacement) []source.Replacement {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Span.Start != changes[j].Span.Start {
			return changes[i].Span.Start < changes[j].Span.Start
		}

		return changes[i].Span.End > changes[j].Span.End
	})

	out := changes[:0]
	for _, c := range changes {
		if len(out) == 0 || c.Span.Start >= out[len(out)-1].Span.End {
			out = append(out, c)
		}
	}

	return out
}

// Default-ignorable letter fillers are gaps only inside a recognized security
// word. Ordinary Hangul text is retained. Pinned upstream artifacts.py ranges.
func letterFiller(r rune) bool { return r == 0x115f || r == 0x1160 || r == 0x3164 || r == 0xffa0 }
