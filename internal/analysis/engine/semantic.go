package engine

import (
	"slices"
	"sort"

	"github.com/skarm/scout/report"
)

// Propagate task failures to the corresponding file scopes. The semantic child
// ledger remains authoritative; this view must not show successful per-file
// coverage when the requested semantic pass failed for that file.
func semanticFileCoverage(r *report.Analysis) {
	if !r.Semantic.Enabled {
		return
	}

	byPath := map[string]*report.FileCoverage{}
	for i := range r.Coverage.Files {
		byPath[r.Coverage.Files[i].Path] = &r.Coverage.Files[i]
	}

	checks := semanticCheckStatuses(r.Semantic)

	for path, modes := range checks {
		if fc := byPath[path]; fc != nil {
			for id, status := range modes {
				fc.Checks = append(fc.Checks, report.FileCheck{AnalyzerID: id, Status: status})
				if status != report.OutcomeCompleted {
					fc.Gaps = append(fc.Gaps, id+":"+status)
				}
			}
		}
	}

	applySemanticGaps(r, byPath)
	sortFileCoverage(r.Coverage.Files)
}

func sortFileCoverage(files []report.FileCoverage) {
	for i := range files {
		fc := &files[i]
		sort.Slice(fc.Checks, func(i, j int) bool { return fc.Checks[i].AnalyzerID < fc.Checks[j].AnalyzerID })
		slices.Sort(fc.Gaps)
		fc.Gaps = slices.Compact(fc.Gaps)
	}
}

func semanticStatusRank(status string) int {
	switch status {
	case report.OutcomeCompleted:
		return 0
	case report.OutcomePartial:
		return 1
	default:
		return 2
	}
}

func applySemanticGaps(r *report.Analysis, byPath map[string]*report.FileCoverage) {
	proposals := make(map[string]report.SemanticProposal, len(r.Semantic.Proposals))
	for _, p := range r.Semantic.Proposals {
		proposals[p.ID] = p
	}

	for _, gap := range r.Semantic.Gaps {
		if p, ok := proposals[gap.ProposalID]; ok {
			for _, e := range p.Evidence {
				if fc := byPath[e.Path]; fc != nil {
					fc.Gaps = append(fc.Gaps, "semantic:"+gap.Code)
				}
			}
		}

		if fc := byPath[gap.Path]; fc != nil {
			fc.Gaps = append(fc.Gaps, "semantic:"+gap.Code)
		}
	}
}

func semanticCheckStatuses(semantic report.SemanticReport) map[string]map[string]string {
	outcomes := map[string]report.SemanticOutcome{}
	for _, o := range semantic.Outcomes {
		outcomes[o.TaskID] = o
	}

	checks := map[string]map[string]string{}

	for _, task := range semantic.Tasks {
		status := report.OutcomeMissing
		if o, ok := outcomes[task.ID]; ok {
			status = o.Status
		}

		for _, input := range task.Inputs {
			path := input.Source.Path
			if checks[path] == nil {
				checks[path] = map[string]string{}
			}

			id := "semantic_" + task.Mode + "_v" + semantic.ProtocolVersion

			old, ok := checks[path][id]
			if !ok || semanticStatusRank(status) > semanticStatusRank(old) {
				checks[path][id] = status
			}
		}
	}

	return checks
}
