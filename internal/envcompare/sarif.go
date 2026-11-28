package envcompare

import (
	"io"

	"github.com/skarm/scout/report"
)

func (r Comparison) writeSARIF(w io.Writer) error {
	roots := make([]report.SnapshotSARIFRoot, 0, len(r.Roots))
	for _, root := range r.Roots {
		roots = append(roots, report.SnapshotSARIFRoot{
			ID: root.ID, Change: root.Change, BeforePath: root.BeforePath, AfterPath: root.AfterPath,
			Document: root.Report,
		})
	}

	return report.WriteSnapshotComparisonSARIF(w, roots, map[string]any{
		"schema": r.Schema, "before_sha256": r.Before, "after_sha256": r.After,
		"decision": r.Decision, "exit_code": r.Code, "relationships": r.Relationships,
		"previous_environment": r.PreviousEnvironment, "environment": r.Environment,
	})
}
