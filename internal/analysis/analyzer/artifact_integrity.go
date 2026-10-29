// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified SkillSpector artifact integrity/SC8 signals with bounded Go views.

package analyzer

import (
	"context"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/securitytext"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var separatedInstruction = func() *regexp.Regexp {
	parts := make([]string, 0, 19)

	for _, word := range []string{"ignore", "bypass", "reveal", "system", "send", "upload", "transmit", "never", "warn", "always", "forget", "previous", "you", "conversation", "instructions", "prompt", "execute", "delete", "steal"} {
		letters := strings.Split(word, "")
		parts = append(parts, strings.Join(letters, `[\s\p{Z}\x{85}._*·\p{M}\p{Nd}-]+`))
	}

	return regexp.MustCompile(`(?i)\b(?:` + strings.Join(parts, "|") + `)\b`)
}()

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var integrityProbes = map[string]integrityProbe{
	ruleAE2: artifactLanguageConflict, ruleAE3: artifactEmbeddedNUL, ruleAE4: artifactUnicode,
	ruleAE5: artifactReconstructionLimit, ruleAE6: artifactSeparatedInstruction, ruleSC8: artifactPythonBytecode,
	ruleAE7: artifactVariationPayload,
}

type integrityCheck struct{ id string }

// Each integrity rule has an independent observation grammar. The adapter
// applies the common context/finding boundary after the selected probe returns.
type integrityProbe func(context.Context, document.File) (source.Span, error)

func (a integrityCheck) Rule() report.Rule {
	title := map[string]string{
		ruleAE2: "Artifact content conflicts with filename/language hints",
		ruleAE3: "Instruction-capable text contains embedded NUL bytes",
		ruleAE4: "Suspicious Unicode controls or mixed-script token",
		ruleAE5: "Instruction text exceeds security reconstruction limits",
		ruleAE6: "Security instruction uses inter-character separators",
		ruleSC8: "Bundled Python bytecode or cache artifact",
	}[a.id]
	if a.id == ruleAE7 {
		title = "Repeated Unicode variation selectors can carry hidden bytes"
	}

	severity := report.Medium
	if a.id == ruleAE3 || a.id == ruleAE5 || a.id == ruleAE6 || a.id == ruleSC8 {
		severity = report.High
	}

	version := "2"
	if a.id == ruleAE2 || a.id == ruleAE6 {
		version = "3"
	}

	return report.Rule{
		ID:          rulePrefixNVIDIA + a.id,
		Version:     version,
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    "artifact-integrity",
		Method:      "bounded-artifact-integrity",
		Limitation:  "Adapted artifact signals, not proof of evasion or malicious intent. Unicode density and mixed-token scripts can have legitimate uses. Author filename/type hints are candidates; scanner-generated JSON labels are not author filename claims. No opaque payload is executed, decompiled or declared safe.",
	}
}

func (integrityCheck) AppliesTo(document.File) bool { return true }

func (a integrityCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}

	probe := integrityProbes[a.id]
	if probe == nil {
		return Result{}, nil
	}

	at, err := probe(ctx, d)
	if err != nil || at.Start >= at.End {
		return Result{}, err
	}

	if budget < 1 {
		return Result{Truncated: true}, nil
	}

	return Result{Matches: []Match{{Start: at.Start, End: at.End}}}, ctx.Err()
}

func artifactLanguageConflict(_ context.Context, d document.File) (source.Span, error) {
	if d.Classification().Conflict {
		return source.Span{End: len(d.Artifact().Content())}, nil
	}

	return source.Span{}, nil
}

func artifactEmbeddedNUL(_ context.Context, d document.File) (source.Span, error) {
	text := d.Artifact().Content()

	at := strings.IndexByte(text, 0)
	if at >= 0 && utf8.ValidString(text) && d.Classification().Basis != "signature" {
		return source.Span{Start: at, End: at + 1}, nil
	}

	return source.Span{}, nil
}

func artifactVariationPayload(ctx context.Context, d document.File) (source.Span, error) {
	spans, limited := securitytext.VariationCarriers(ctx, d.Artifact().Content())
	if len(spans) > 0 {
		return spans[0], ctx.Err()
	}

	if limited {
		return source.Span{}, errors.New("unicode carrier inspection limit")
	}

	return source.Span{}, ctx.Err()
}

func artifactUnicode(ctx context.Context, d document.File) (source.Span, error) {
	if d.Artifact().Metadata().Kind != "text" {
		return source.Span{}, nil
	}

	matched, err := suspiciousUnicode(ctx, d.Artifact().Content())
	if matched {
		return source.Span{End: len(d.Artifact().Content())}, err
	}

	return source.Span{}, err
}

func artifactReconstructionLimit(_ context.Context, d document.File) (source.Span, error) {
	if reconstructionLimited(strings.ToLower(d.Artifact().Metadata().Path), d) {
		return source.Span{End: len(d.Artifact().Content())}, nil
	}

	return source.Span{}, nil
}

func artifactSeparatedInstruction(_ context.Context, d document.File) (source.Span, error) {
	if d.Artifact().Metadata().Kind != "text" {
		return source.Span{}, nil
	}

	if at := separatedInstruction.FindStringIndex(d.Artifact().Content()); at != nil {
		return source.Span{Start: at[0], End: at[1]}, nil
	}

	return source.Span{}, nil
}

func artifactPythonBytecode(_ context.Context, d document.File) (source.Span, error) {
	name := strings.ToLower(d.Artifact().Metadata().Path)

	matched := strings.HasSuffix(name, ".pyc") || strings.HasSuffix(name, ".pyo")
	for part := range strings.SplitSeq(name, "/") {
		matched = matched || part == "__pycache__"
	}

	if matched {
		return source.Span{End: len(d.Artifact().Content())}, nil
	}

	return source.Span{}, nil
}

func reconstructionLimited(name string, d document.File) bool {
	if ext := path.Ext(name); ext == ".md" || ext == ".markdown" || ext == ".txt" {
		for _, diag := range d.Diagnostics() {
			if diag.Code == "security_reconstruction_limit" {
				return true
			}
		}
	}

	return false
}

func suspiciousUnicode(ctx context.Context, text string) (bool, error) {
	controls, total := 0, 0

	for at, r := range text {
		if at%1024 == 0 && ctx.Err() != nil {
			return false, ctx.Err()
		}

		total++

		if unicode.Is(unicode.Cf, r) && !emojiCarrierExempt(text, at, at+utf8.RuneLen(r)) {
			controls++
		}
	}

	if total > 0 && controls*100 >= total {
		return true, nil
	}

	return slices.ContainsFunc(strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) }), confusingIdentifier), nil
}

func artifactIntegrityRules() []Analyzer {
	return []Analyzer{integrityCheck{id: ruleAE2}, integrityCheck{id: ruleAE3}, integrityCheck{id: ruleAE4}, integrityCheck{id: ruleAE5}, integrityCheck{id: ruleAE6}, integrityCheck{id: ruleSC8}, integrityCheck{id: ruleAE7}}
}
