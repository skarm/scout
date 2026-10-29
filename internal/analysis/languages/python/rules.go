// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"context"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

type pythonCheck struct {
	id    string
	facts map[string]*pythonFacts
}

func Rules() []analyzer {
	pythonRuleIDs := [...]string{ruleAST1, ruleAST2, ruleAST3, ruleAST4, ruleAST5, ruleAST6, ruleAST7, ruleAST8, ruleAST9, ruleAST10, ruleTT1, ruleTT2, ruleTT3, ruleTT4, ruleTT5, ruleTT6}

	out := make([]analyzer, 0, len(pythonRuleIDs))
	for _, id := range pythonRuleIDs {
		out = append(out, pythonCheck{id: id})
	}

	return out
}

func (a pythonCheck) Rule() report.Rule {
	title := map[string]string{
		ruleAST1: "Python exec call",
		ruleAST2: "Python eval call",
		ruleAST3: "Python dynamic import",
		ruleAST4: "Python subprocess call",
		ruleAST5: "Python OS execution call",
		ruleAST6: "Python compile call",
		ruleAST7: "Python dynamic attribute lookup",
		ruleAST8: "Python nested decoding/import/execution chain",
		ruleAST9: "Python reflective execution handle",
		ruleTT1:  "Python direct source-to-sink flow",
		ruleTT2:  "Python source-to-sink flow through variables",
		ruleTT3:  "Python environment data reaches network output",
		ruleTT4:  "Python file data reaches network output",
		ruleTT5:  "Python external input reaches code execution",
	}[a.id]
	if a.id == ruleAST10 {
		title = "Python unsafe deserialization"
	}

	if a.id == ruleTT6 {
		title = "Python external or file input reaches unsafe deserialization"
	}

	sev := report.Medium

	switch a.id {
	case ruleAST1, ruleAST2, ruleAST5, ruleAST8, ruleAST9, ruleTT1, ruleTT3, ruleTT4, ruleTT5, ruleTT6:
		sev = report.High
	case ruleAST7:
		sev = report.Low
	}

	return report.Rule{
		ID:          rulePrefixPython + a.id,
		Version:     "8",
		Title:       title,
		Description: title,
		Severity:    sev,
		Category:    "python-execution-and-dataflow",
		Method:      "python-ast-go-analysis",
		Limitation:  "Embedded Tree-sitter Python CST projected into bounded Go IR; not CPython AST. Selected aliases, assignments, branches, same-file functions, methods, instance fields and C3 inheritance are modeled. No execution, cross-file/general type inference or proof of intent. Recursive/dynamic calls and complex control flow remain incomplete. Environment values need not be secrets; annotation evaluation timing is unknown.",
	}
}

func (pythonCheck) AppliesTo(f document.File) bool {
	for _, u := range f.Units() {
		if _, ok := u.Tree.(parse.PythonTree); ok {
			return true
		}
	}

	return false
}

func (a pythonCheck) Find(ctx context.Context, f document.File, budget int) (result, error) {
	facts := a.facts[f.Artifact().Metadata().Path]
	if facts == nil {
		facts = collectPython(ctx, f, []string{a.id}, budget)
	}

	return facts.result(a.id, budget)
}
