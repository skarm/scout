package engine

import (
	"container/heap"
	"sort"

	"github.com/skarm/scout/internal/analysis/findingorder"

	"github.com/skarm/scout/report"
)

// findingCollector owns retention across every producer. The heap root is the
// least important retained finding, so later evidence can displace it.
type findingCollector struct {
	limit   int
	items   findingHeap
	indices map[string]int
	omitted map[string]int
}

type findingHeap struct {
	values []report.Finding
	owner  *findingCollector
}

func newFindingCollector(limit int) *findingCollector {
	c := &findingCollector{limit: limit, indices: make(map[string]int), omitted: make(map[string]int)}
	c.items.owner = c

	return c
}

func (h *findingHeap) Len() int           { return len(h.values) }
func (h *findingHeap) Less(i, j int) bool { return findingorder.Before(h.values[j], h.values[i]) }
func (h *findingHeap) Swap(i, j int) {
	h.values[i], h.values[j] = h.values[j], h.values[i]
	h.owner.indices[h.values[i].ID] = i
	h.owner.indices[h.values[j].ID] = j
}

func (h *findingHeap) Push(value any) {
	switch f := value.(type) {
	case report.Finding:
		h.owner.indices[f.ID] = len(h.values)
		h.values = append(h.values, f)
	default:
		panic("finding heap only accepts report.Finding")
	}
}

func (h *findingHeap) Pop() any {
	n := len(h.values) - 1
	f := h.values[n]
	delete(h.owner.indices, f.ID)
	h.values[n] = report.Finding{}
	h.values = h.values[:n]

	return f
}

func (c *findingCollector) add(f report.Finding) {
	if _, exists := c.indices[f.ID]; exists {
		return
	}

	if c.items.Len() < c.limit {
		heap.Push(&c.items, f)
		return
	}

	if findingorder.Before(f, c.items.values[0]) {
		old := c.items.values[0]
		heap.Pop(&c.items)
		c.omitted[old.Location.Path]++
		heap.Push(&c.items, f)

		return
	}

	c.omitted[f.Location.Path]++
}

func (c *findingCollector) finish(r *report.Analysis, fileIndex map[string]int) {
	r.Findings = c.items.values
	sort.Slice(r.Findings, func(i, j int) bool { return findingorder.Before(r.Findings[i], r.Findings[j]) })

	if len(c.omitted) == 0 {
		return
	}

	r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
		Code:         "finding_limit",
		Message:      "Report finding budget exhausted; highest-severity observations retained.",
		AffectsScope: true,
	})

	for path := range c.omitted {
		if i, ok := fileIndex[path]; ok {
			r.Coverage.Files[i].Gaps = append(r.Coverage.Files[i].Gaps, "report_finding_limit")
		}
	}
}
