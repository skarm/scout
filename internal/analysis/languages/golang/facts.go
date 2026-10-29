package golang

import (
	"context"
	"errors"
	"go/ast"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
)

type goObservationWalk struct {
	ctx      context.Context
	unit     document.GoUnit
	selected []goCheck
	facts    *check.FileLanguageFacts
	imports  goScope
	err      error
}

func Collect(ctx context.Context, doc document.File, facts *check.FileLanguageFacts) {
	selected := make([]goCheck, 0)

	for kind := goShell; kind <= goDirectHTTP; kind++ {
		a := goCheck{kind: kind}
		if facts.Rules[a.Rule().ID] != nil {
			selected = append(selected, a)
		}
	}

	if len(selected) == 0 {
		return
	}

	for _, unit := range doc.GoUnits() {
		if unit.Tree == nil {
			continue
		}

		walk := goObservationWalk{
			ctx:      ctx,
			unit:     unit,
			selected: selected,
			facts:    facts,
			imports:  importNames(unit.Tree, unit.Bindings),
		}
		ast.Inspect(unit.Tree, walk.visit)

		if walk.err != nil {
			finishGoFacts(facts, selected, walk.err)
			break
		}
	}

	finishGoFacts(facts, selected, ctx.Err())
}

func finishGoFacts(facts *check.FileLanguageFacts, selected []goCheck, err error) {
	for _, a := range selected {
		facts.Rules[a.Rule().ID].Finish(err, false)
	}
}

func (w *goObservationWalk) visit(n ast.Node) bool {
	if n == nil || w.err != nil {
		return false
	}

	if w.ctx.Err() != nil {
		w.err = w.ctx.Err()
		return false
	}

	if !analysisbudget.Consume(w.ctx, 1) {
		w.err = errors.New("go analysis operation budget exceeded")
		return false
	}

	call, ok := n.(*ast.CallExpr)
	if !ok || !completeCall(w.unit, call) {
		return true
	}

	w.observe(call)

	return true
}

func (w *goObservationWalk) observe(call *ast.CallExpr) {
	for _, a := range w.selected {
		output := w.facts.Rules[a.Rule().ID]
		if output.Done() {
			continue
		}

		origin, matched := a.matchCall(call, w.imports)
		if !matched {
			continue
		}

		var (
			result result
			err    error
		)
		appendGoMatch(w.unit, call, origin, 1, &result, &err)

		if err != nil {
			output.Finish(err, false)
			continue
		}

		for _, match := range result.Matches {
			output.Add(match)
		}
	}
}
