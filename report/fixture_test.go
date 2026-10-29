package report_test

import (
	"io"

	"github.com/skarm/scout/report"
)

func sampleDocument(analysis report.Analysis) (report.Document, error) {
	run, err := report.SealRun(report.Run{
		Operation: report.ScanOperation,
		State:     report.RunComplete,
		Targets: []report.TargetResult{{
			ID:       "fixture",
			Index:    0,
			State:    report.RunComplete,
			Analysis: analysis,
		}},
	})
	if err != nil {
		return report.Document{}, err
	}
	return report.NewDocument(run, report.Evaluation{
		Decision:     report.Block,
		RunDigest:    run.Digest,
		PolicyDigest: "fixture-policy",
	}), nil
}

func writeFixture(w io.Writer, format string, analysis report.Analysis) error {
	if format == "terminal" {
		format = "text"
	}
	document, err := sampleDocument(analysis)
	if err != nil {
		return err
	}
	return report.Write(w, report.Format(format), document)
}
