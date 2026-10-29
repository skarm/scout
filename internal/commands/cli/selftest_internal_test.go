// Exercises private implementation details and package fixtures.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/nativecheck"
)

func TestSelftestTextAndJSONPreserveChecksAndSurfaceWriteFailures(t *testing.T) {
	result := nativecheck.Report{
		Passed:   true,
		Version:  "fixture",
		Platform: "test/test",
		Checks: []nativecheck.Check{{
			ID:     "python-tree",
			Status: "passed",
			Reason: "confirmed",
		}},
	}
	var output bytes.Buffer
	if err := writeSelftest(&output, result, "text"); err != nil || !strings.Contains(output.String(), "python-tree") || !strings.Contains(output.String(), "passed") {
		t.Fatalf("text check omitted: %s %v", &output, err)
	}
	output.Reset()
	if err := writeSelftest(&output, result, "json"); err != nil {
		t.Fatal(err)
	}
	var decoded nativecheck.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatal("JSON report changed")
	}
	for _, remaining := range []int{0, 1} {
		if err := writeSelftest(&selftestFaultWriter{remaining: remaining}, result, "text"); err == nil {
			t.Fatal("text writer failure was ignored")
		}
	}
}

type selftestFaultWriter struct{ remaining int }

func (w *selftestFaultWriter) Write(data []byte) (int, error) {
	if w.remaining == 0 {
		return 0, errors.New("fixture stream failed")
	}
	w.remaining--
	return len(data), nil
}
