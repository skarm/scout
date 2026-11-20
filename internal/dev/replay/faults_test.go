package replay //nolint:testpackage // Exercises private replay fault classification and accounting.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/report"
)

func TestCaptureUnicodeFilenamesArePreserved(t *testing.T) {
	for _, tc := range []struct{ encoded, want string }{
		{encoded: `"paired-\ud83d\ude42.txt"`, want: "paired-🙂.txt"},
		{encoded: `"literal-�.txt"`, want: "literal-�.txt"},
		{encoded: `"escaped-\ufffd.txt"`, want: "escaped-�.txt"},
	} {
		t.Run(tc.encoded, func(t *testing.T) {
			data := `{"id":"` + strings.Repeat("a", 64) + `","files":[{"name":` + tc.encoded + `,"data":"b2s="}]}`
			got, err := decodeRecord([]byte(data), scout.DefaultOptions().Limits)
			if err != nil || got.rejection != "" || len(got.files) != 1 || got.files[0].name != tc.want {
				t.Fatalf("filename did not survive decoding: %+v, %v", got, err)
			}
		})
	}
}

func TestReplayFaultPriorityKeepsCoverageGapsDistinctFromExecutionFaults(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     report.State
		digest    string
		targets   int
		scanErr   error
		cancelled bool
		want      string
	}{
		{
			name:      "deliberate_gap",
			state:     report.RunIncomplete,
			digest:    "binding",
			targets:   1,
			scanErr:   scout.ErrIncomplete,
			cancelled: false,
			want:      "",
		},
		{
			name:      "cancelled",
			state:     report.RunCancelled,
			digest:    "binding",
			targets:   1,
			scanErr:   nil,
			cancelled: false,
			want:      "replay_deadline",
		},
		{
			name:      "deadline",
			state:     report.RunIncomplete,
			digest:    "binding",
			targets:   1,
			scanErr:   scout.ErrIncomplete,
			cancelled: true,
			want:      "replay_deadline",
		},
		{
			name:      "complete_before_cancel",
			state:     report.RunComplete,
			digest:    "binding",
			targets:   1,
			scanErr:   nil,
			cancelled: true,
			want:      "",
		},
		{
			name:      "missing_binding",
			state:     report.RunComplete,
			digest:    "",
			targets:   1,
			scanErr:   nil,
			cancelled: false,
			want:      "replay_runtime_error",
		},
		{
			name:      "missing_target",
			state:     report.RunComplete,
			digest:    "binding",
			targets:   0,
			scanErr:   nil,
			cancelled: false,
			want:      "replay_runtime_error",
		},
		{
			name:      "execution_error",
			state:     report.RunComplete,
			digest:    "binding",
			targets:   1,
			scanErr:   errors.New("fixture failure"),
			cancelled: false,
			want:      "replay_runtime_error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			answer := result{State: tc.state}
			acceptFaults(&answer, ctx, report.Run{
				State:   tc.state,
				Digest:  tc.digest,
				Targets: make([]report.TargetResult, tc.targets),
			}, tc.scanErr)
			if answer.Error != tc.want {
				t.Fatal(answer)
			}
			if tc.want == "replay_runtime_error" && answer.State != report.RunFailed {
				t.Fatal("runtime fault retained successful state", answer)
			}
		})
	}
}
