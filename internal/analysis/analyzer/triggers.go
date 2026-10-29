// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted from static_patterns_supply_chain.py: _analyze_triggers and its
// constants. Uses decoded structured fields, bounded work and physical evidence.

package analyzer

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

var (

	//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
	builtinTriggers = stringSet("help search find run test build deploy install create delete update list show get set open close start stop restart status log debug commit push pull merge branch checkout rebase diff blame stash tag release version lint format fix refactor review explain chat ask edit write read save load copy move")

	//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
	broadTriggers = stringSet("the a an is it do go make thing stuff code file data text work good bad yes no ok please thanks hi hello hey")

	//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
	baitingTriggers = []*regexp.Regexp{
		regexp.MustCompile(`^(?:anything|everything|whatever|always|any\s+(?:question|request|task|input))$`),
		regexp.MustCompile(`^(?:when(?:ever)?|if|every\s+time)\s+(?:the\s+)?user\s+(?:says?|asks?|types?|sends?)\s+(?:anything|something|a\s+message)$`),
		regexp.MustCompile(`^(?:all|any|every)\s+(?:messages?|inputs?|requests?|queries?|questions?)$`),
	}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var triggerMatchers = map[string]func(string) bool{
	ruleNVTR1M: matchesBroadTrigger,
	ruleNVTR2M: matchesCommandTrigger,
	ruleNVTR3M: matchesBaitingTrigger,
}

type triggerCheck struct{ id string }

func ActivationRules() []Analyzer {
	return []Analyzer{triggerCheck{id: ruleNVTR1M}, triggerCheck{id: ruleNVTR2M}, triggerCheck{id: ruleNVTR3M}}
}

func (a triggerCheck) Rule() report.Rule {
	titles := map[string]string{
		ruleNVTR1M: "Overly broad declared trigger",
		ruleNVTR2M: "Declared trigger shadows a common command",
		ruleNVTR3M: "Generic baiting trigger declaration",
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       titles[a.id],
		Description: titles[a.id],
		Severity:    report.Medium,
		Category:    "trigger-abuse",
		Method:      "structured-trigger-analysis",
		Limitation:  "Adapted upstream TR1-TR3 for root decoded triggers arrays. Declaration or a configuration example does not prove activation by any harness. Short legitimate triggers may match; aliases, nested schemas and unparsed metadata are not inferred.",
	}
}

func (a triggerCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if t, ok := u.Tree.(parse.JSONTree); ok && t.Root != nil && t.Root.Get("triggers") != nil {
			return true
		}
	}

	return false
}

func (a triggerCheck) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	out := Result{}
	collected := collectMatches(&out, budget)
	ops := 0

	for u := range parsedUnits[parse.JSONTree](f) {
		list := u.tree.Root.GetOrEmpty("triggers")
		if list.Kind != jsonconfig.KindArray {
			continue
		}

		for _, n := range list.Elements {
			if err := ctx.Err(); err != nil {
				return out, err
			}

			ops++
			if ops > 32768 {
				out.Truncated = true
				return out, nil
			}

			text, ok := n.Text()
			if !ok {
				continue
			}

			text = strings.ToLower(strings.TrimSpace(text))
			if !a.matchesTrigger(text) {
				continue
			}

			if more, _ := collected.addMapped(u.View, n.Span); !more {
				return out, nil
			}
		}
	}

	return out, ctx.Err()
}

func (a triggerCheck) matchesTrigger(text string) bool {
	match, known := triggerMatchers[a.id]
	return text != "" && known && match(text)
}

func matchesBroadTrigger(text string) bool {
	return len(strings.Fields(text)) == 1 && broadTriggers[text] || utf8.RuneCountInString(text) <= 2
}

func matchesCommandTrigger(text string) bool {
	words := strings.Fields(text)
	return builtinTriggers[text] || len(words) > 0 && len(words) <= 2 && builtinTriggers[words[0]]
}

func matchesBaitingTrigger(text string) bool {
	for _, pattern := range baitingTriggers {
		if pattern.MatchString(text) {
			return true
		}
	}

	return false
}
