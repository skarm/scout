package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skarm/scout/report"
)

func TestBinaryTraceCoordinatesSurviveRendering(t *testing.T) {
	for _, derived := range []bool{false, true} {
		name := "captured"
		path := "payload.bin"
		if derived {
			name, path = "derived", "scout-object://example/payload.bin"
		}
		t.Run(name, func(t *testing.T) {
			analysis := sample()
			file := report.File{Path: path, Kind: "binary", Size: 32, Status: report.CaptureCaptured}
			if derived {
				analysis.Extraction.Objects = []report.DerivedObject{{File: file}}
			} else {
				analysis.Artifact.Files = append(analysis.Artifact.Files, file)
			}
			analysis.Findings[0].Trace = []report.TraceStep{{Role: "source", Location: report.Location{
				Path: path, Coordinates: "bytes", ByteStart: 4, ByteEnd: 20, Derived: derived,
			}}}

			t.Run("sarif", func(t *testing.T) {
				var out bytes.Buffer
				if err := writeFixture(&out, "sarif", analysis); err != nil {
					t.Fatal(err)
				}
				var log map[string]any
				if err := json.Unmarshal(out.Bytes(), &log); err != nil {
					t.Fatal(err)
				}
				run := log["runs"].([]any)[0].(map[string]any)
				result := run["results"].([]any)[0].(map[string]any)
				flow := result["codeFlows"].([]any)[0].(map[string]any)
				thread := flow["threadFlows"].([]any)[0].(map[string]any)
				step := thread["locations"].([]any)[0].(map[string]any)
				assertSARIFRegion(t, step["location"], map[string]any{
					"byteOffset": float64(4), "byteLength": float64(16),
				})
			})
			t.Run("text", func(t *testing.T) {
				var out bytes.Buffer
				if err := writeFixture(&out, "terminal", analysis); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "source: \""+path+"\" bytes[4:20]") {
					t.Fatalf("binary trace lost its byte range: %s", out.String())
				}
				if strings.Contains(out.String(), "\""+path+"\":0:0") {
					t.Fatal("binary trace fabricated text coordinates")
				}
			})
		})
	}
}
