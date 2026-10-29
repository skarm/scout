//nolint:testpackage // Exercises private implementation details and local test fixtures.
package extract

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

func TestDataURIParsingRetainsIndependentCandidatesAndRejectsEmptyBodies(t *testing.T) {
	for _, tc := range []struct {
		text    string
		objects int
		invalid bool
	}{
		{text: "x data:bad header;base64,SGk= y data:text/plain;base64,T0s=", objects: 1, invalid: false},
		{text: "x data:missing-marker y data:text/plain;base64,T0s=", objects: 1, invalid: false},
		{text: "x data:text/plain;base64,", objects: 0, invalid: true},
		{text: "x data:text/plain;base64,T0s= y data:application/json;base64,e30=", objects: 2, invalid: false},
	} {
		result, err := Expand(context.Background(), []artifact.File{artifact.NewFile("input.txt", []byte(tc.text), false)}, report.DefaultExtractionLimits())
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, object := range result.Report.Objects {
			if object.ParentPath == "input.txt" && object.ExtractorID == "base64" {
				count++
			}
		}
		invalid := false
		for _, d := range result.Diagnostics {
			if d.Code == "extraction_invalid_or_unsupported" && d.Path == "input.txt" {
				invalid = true
			}
		}
		if count != tc.objects || invalid != tc.invalid {
			t.Fatal(tc, result.Report, result.Diagnostics)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	op := operation{b: &builder{ctx: ctx}}
	if err := extractDataURIs(&op, "data:text/plain;base64,T0s="); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
