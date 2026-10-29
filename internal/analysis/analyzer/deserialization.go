// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified Go implementation of SkillSpector DS1-DS4. Fenced units retain
// original source spans; language hints are candidates, never trust boundaries.

package analyzer

import (
	"context"
	"regexp"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only language and command classification shared by scans.
var deserializationLanguages = map[string]map[string]bool{
	language.PHP:  {language.PHP: true},
	language.Ruby: {language.Ruby: true},
	language.JavaScript: {
		language.JavaScript: true,
		language.TypeScript: true,
	},
}

type deserialization struct {
	id, title, language string
	patterns            []*regexp.Regexp
}

func DeserializationPatternRules() []Analyzer {
	makeRule := func(id, title, language string, expressions ...string) Analyzer {
		a := deserialization{id: id, title: title, language: language}
		for _, e := range expressions {
			a.patterns = append(a.patterns, regexp.MustCompile("(?i)"+e))
		}

		return a
	}

	return []Analyzer{
		makeRule(ruleDS1, "PHP object deserialization", language.PHP, `\bunserialize\s*\(`),
		makeRule(ruleDS2, "Ruby Marshal deserialization", language.Ruby, `\bMarshal\s*\.\s*(?:load|restore)\b`),
		makeRule(ruleDS3, "Unsafe Ruby YAML/Oj deserialization", language.Ruby, `\b(?:YAML|Psych|Oj)\s*\.\s*load\s*\(`),
		makeRule(ruleDS4, "Unsafe JavaScript deserialization", language.JavaScript, `require\(\s*['"](?:node-serialize|serialize-to-js)['"]\s*\)`, `\bfuncster\b`, `\.unserialize\s*\(`),
	}
}

func (a deserialization) Rule() report.Rule {
	severity := report.High
	if a.id == ruleDS3 {
		severity = report.Medium
	}

	return report.Rule{
		ID:          rulePrefixNVIDIA + a.id,
		Version:     "1",
		Title:       a.title,
		Description: a.title,
		Severity:    severity,
		Category:    "insecure-deserialization",
		Method:      "language-gated-pattern",
		Limitation:  "Adapted SkillSpector DS1-DS4 signatures on candidate language units; not proof of untrusted input, exploitability or runtime execution. Quoted/commented code can match. No general PHP/Ruby/JS data flow.",
	}
}

func (deserialization) AppliesTo(document.File) bool { return true }

func (a deserialization) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	out := Result{}
	collected := collectMatches(&out, budget)

	for _, u := range d.Units() {
		if !deserializationLanguages[a.language][u.Language] {
			continue
		}

		for _, p := range a.patterns {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}

			for _, loc := range p.FindAllStringIndex(u.View.Text(), budget+1) {
				at, e := u.View.Original(source.Span{Start: loc[0], End: loc[1]})
				if e != nil {
					return out, e
				}

				if !collected.span(at.Start, at.End) {
					return out, nil
				}
			}
		}
	}

	return out, ctx.Err()
}
