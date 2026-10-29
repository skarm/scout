package scout

import (
	"container/heap"

	"github.com/skarm/scout/internal/analysis/findingorder"
	"github.com/skarm/scout/report"
)

type (
	findingPosition struct{ target, finding int }
	runFindingHeap  struct {
		run       *report.Run
		positions []findingPosition
	}
)

func (h *runFindingHeap) Len() int           { return len(h.positions) }
func (h *runFindingHeap) Less(i, j int) bool { return h.before(h.positions[j], h.positions[i]) }
func (h *runFindingHeap) Swap(i, j int) {
	h.positions[i], h.positions[j] = h.positions[j], h.positions[i]
}

func (h *runFindingHeap) Push(v any) {
	//nolint:forcetypeassert // The private heap accepts only findingPosition through container/heap.Interface.
	h.positions = append(h.positions, v.(findingPosition))
}

func (h *runFindingHeap) Pop() any {
	n := len(h.positions) - 1
	p := h.positions[n]
	h.positions = h.positions[:n]

	return p
}

func (h *runFindingHeap) before(a, b findingPosition) bool {
	// Comparison policy evaluates the candidate. Retain its observations before
	// older-version evidence, while recording any omitted before evidence as a gap.
	if h.run.Operation == report.CompareOperation && a.target != b.target {
		return a.target > b.target
	}

	af, bf := h.run.Targets[a.target].Analysis.Findings[a.finding], h.run.Targets[b.target].Analysis.Findings[b.finding]
	if af.Severity == bf.Severity && a.target != b.target {
		return a.target < b.target
	}

	return findingorder.Before(af, bf)
}

// Each target already retains at most K candidates. The second reduction needs
// only K positions and applies the retention budget to the entire public Run.
func retainRunFindings(run *report.Run, limit int) {
	kept := selectRunFindings(run, limit)
	for i := range run.Targets {
		retainTargetFindings(&run.Targets[i], i, kept)
	}
}

func selectRunFindings(run *report.Run, limit int) map[findingPosition]bool {
	h := &runFindingHeap{run: run}
	for i, target := range run.Targets {
		for j := range target.Analysis.Findings {
			p := findingPosition{target: i, finding: j}

			if h.Len() < limit {
				heap.Push(h, p)
			} else if h.before(p, h.positions[0]) {
				h.positions[0] = p
				heap.Fix(h, 0)
			}
		}
	}

	kept := make(map[findingPosition]bool, h.Len())
	for _, p := range h.positions {
		kept[p] = true
	}

	return kept
}

func retainTargetFindings(target *report.TargetResult, i int, kept map[findingPosition]bool) {
	findings := target.Analysis.Findings
	retained := findings[:0]
	omitted := map[string]bool{}

	for j, f := range findings {
		if kept[findingPosition{target: i, finding: j}] {
			retained = append(retained, f)
		} else {
			omitted[f.Location.Path] = true
		}
	}

	if len(omitted) == 0 {
		return
	}

	clear(findings[len(retained):])
	target.Analysis.Findings = retained

	recordRunRetentionGap(target, omitted)
}

func recordRunRetentionGap(target *report.TargetResult, omitted map[string]bool) {
	if target.State == report.RunComplete {
		target.State = report.RunIncomplete
	}

	if target.Analysis.Coverage.Completeness == report.Complete {
		target.Analysis.Coverage.Completeness = report.Partial
	}

	target.Analysis.Diagnostics = append(target.Analysis.Diagnostics, report.Diagnostic{
		Code:         "run_finding_limit",
		Message:      "Additional findings omitted at the shared run retention budget.",
		AffectsScope: true,
	})
	for j := range target.Analysis.Coverage.Files {
		file := &target.Analysis.Coverage.Files[j]
		if omitted[file.Path] {
			file.Completeness = report.Partial
			file.Gaps = append(file.Gaps, "report_finding_limit")
		}
	}
}
