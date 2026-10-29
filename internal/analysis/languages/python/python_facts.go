package python

import (
	"errors"

	"github.com/skarm/scout/internal/analysis/check"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/source"
)

// pythonFacts records observations while one walker evaluates the Python unit.
// After finish, concurrent rule consumers only replay immutable event streams.
type pythonFacts struct {
	outputs map[string]*pythonRuleFacts
}

type pythonRuleFacts struct {
	*check.Facts
	seen map[[2]int]bool
}

func newPythonFacts(ids []string, limit int) *pythonFacts {
	limits := make(map[string]int, len(ids))
	for _, id := range ids {
		limits[id] = limit
	}

	return newPythonFactsWithin(limits)
}

func newPythonFactsWithin(limits map[string]int) *pythonFacts {
	facts := &pythonFacts{outputs: make(map[string]*pythonRuleFacts, len(limits))}
	for id, limit := range limits {
		facts.outputs[id] = &pythonRuleFacts{Facts: check.NewFacts(limit), seen: make(map[[2]int]bool)}
	}

	return facts
}

func (facts *pythonFacts) beginUnit() {
	for _, rule := range facts.outputs {
		clear(rule.seen)
	}
}

func (facts *pythonFacts) emit(id string, node *frontend.Node, origin *pyOrigin, unit document.Unit) {
	rule := facts.outputs[id]
	if rule == nil || rule.Done() || node == nil || node.Start >= node.End {
		return
	}

	key := [2]int{node.Start, node.End}
	if rule.seen[key] {
		return
	}
	// Do not map a candidate that this rule would never have reached under its
	// collection budget. A later malformed span must not replace truncation.
	if !rule.Admit() {
		return
	}

	match, err := mapPythonFact(node, origin, unit)
	if err != nil {
		rule.Finish(err, false)
		return
	}

	rule.seen[key] = true
	rule.Add(match)
}

func (facts *pythonFacts) exhausted() bool {
	for _, rule := range facts.outputs {
		if !rule.Done() {
			return false
		}
	}

	return true
}

func (facts *pythonFacts) finish(err error, truncated bool) {
	for _, rule := range facts.outputs {
		rule.Finish(err, truncated)
	}
}

func (facts *pythonFacts) result(id string, budget int) (result, error) {
	rule := facts.outputs[id]
	if rule == nil {
		return result{}, nil
	}

	return rule.Result(budget)
}

func mapPythonFact(node *frontend.Node, origin *pyOrigin, unit document.Unit) (match, error) {
	span, err := unit.View.Original(source.Span{Start: node.Start, End: node.End})
	if err != nil {
		return match{}, errors.New("python source mapping failed")
	}

	match := match{Start: span.Start, End: span.End}
	if origin == nil {
		return match, nil
	}

	match.Trace, err = pythonFactTrace(node, origin, unit.View)

	return match, err
}

func pythonFactTrace(node *frontend.Node, origin *pyOrigin, view source.View) ([]trace, error) {
	trace := make([]trace, 0, len(origin.steps)+2)

	first, err := mapPythonTrace("source", source.Span{Start: origin.start, End: origin.end}, view)
	if err != nil {
		return nil, err
	}

	trace = append(trace, first)

	for _, step := range origin.steps {
		mapped, err := mapPythonTrace("transform", step, view)
		if err != nil {
			return nil, err
		}

		trace = append(trace, mapped)
	}

	last, err := mapPythonTrace("sink", source.Span{Start: node.Start, End: node.End}, view)
	if err != nil {
		return nil, err
	}

	return append(trace, last), nil
}

func mapPythonTrace(role string, span source.Span, view source.View) (trace, error) {
	mapped, err := view.Original(span)
	if err != nil {
		return trace{}, errors.New("python trace mapping failed")
	}

	return trace{Role: role, Start: mapped.Start, End: mapped.End}, nil
}
