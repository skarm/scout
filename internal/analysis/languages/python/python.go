// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified bounded, non-executing Python analysis.

package python

import (
	"context"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/source"
)

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var pyFlowRules = map[[2]string]string{
	{"network", "environment"}: ruleTT3, {"network", "file"}: ruleTT4,
	{"exec", "network"}: ruleTT5, {"exec", "input"}: ruleTT5,
	{"deserialization", "network"}: ruleTT6, {"deserialization", "input"}: ruleTT6, {"deserialization", "file"}: ruleTT6,
}

type pyOrigin struct {
	kind       string
	start, end int
	steps      []source.Span
}

type pyWalker struct {
	ctx        context.Context
	ops        int
	unit       document.Unit
	facts      *pythonFacts
	err        error
	truncated  bool
	frames     []*pyFrame
	active     map[*pyFunction]bool
	calls      int
	limited    bool
	chainCalls map[*frontend.Node]bool
}

func (w *pyWalker) charge(depth int) bool {
	w.ops++
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return false
	}

	if w.ops > 100000 || depth > 64 || !analysisbudget.Consume(w.ctx, 1) {
		w.err = w.ctx.Err()
		w.truncated = w.err == nil

		return false
	}

	return w.err == nil && !w.truncated && !w.facts.exhausted()
}

func (w *pyWalker) emit(id string, n *frontend.Node, o *pyOrigin) {
	w.facts.emit(id, n, o, w.unit)
}

func (w *pyWalker) flow(n *frontend.Node, v pyValue, sink string) {
	for _, o := range v.origins {
		w.emit(pyFlowRule(o, sink), n, &o)
	}
}

func pyFlowRule(o pyOrigin, sink string) string {
	if id := pyFlowRules[[2]string{sink, o.kind}]; id != "" {
		return id
	}

	if len(o.steps) > 0 {
		return ruleTT2
	}

	return ruleTT1
}

func joinPy(vs ...pyValue) pyValue {
	r := pyValue{}
	seen := map[[2]int]bool{}

	for _, v := range vs {
		for _, o := range v.origins {
			k := [2]int{o.start, o.end}
			if seen[k] {
				continue
			}

			seen[k] = true

			if len(r.origins) < 4 {
				r.origins = append(r.origins, o)
			}
		}
	}

	return r
}

func transformed(v pyValue, n *frontend.Node) pyValue {
	if n == nil {
		return v
	}

	r := v

	r.origins = append([]pyOrigin(nil), v.origins...)
	for i := range r.origins {
		p := r.origins[i]

		p.steps = append([]source.Span(nil), p.steps...)
		if len(p.steps) < 5 {
			p.steps = append(p.steps, source.Span{Start: n.Start, End: n.End})
		}

		r.origins[i] = p
	}

	return r
}

func origin(kind string, n *frontend.Node) pyValue {
	return pyValue{origins: []pyOrigin{{kind: kind, start: n.Start, end: n.End}}}
}

func nodeLiteral(n *frontend.Node) (string, bool) {
	if n == nil || n.Kind() != frontend.Constant {
		return "", false
	}

	return n.Field(frontend.FieldValue).Text()
}
