package integrations_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func TestHostDiagnosticsUseTheActualGoReportContract(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required to verify the shared host adapter")
	}
	options := scout.DefaultOptions()
	options.Profile, options.Checks = scout.Custom, &scout.Checks{}
	options.Limits.Capture.MaxFileBytes, options.Limits.Capture.MaxTotalBytes, options.Limits.Capture.MaxArchiveBytes = 1, 1, 1
	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	run, _ := scanner.Scan(context.Background(), scout.Reader("inert.txt", strings.NewReader("ordinary inert text")))
	gate, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.Write(&out, report.JSON, report.NewDocument(run, gate.Evaluate(run, time.Now()))); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "partial.json")
	if err := os.WriteFile(fixture, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, "--test", "diagnostics_test.mjs")
	command.Env = append(os.Environ(), "SCOUT_DIAGNOSTICS_FIXTURE="+fixture)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual Go report did not preserve diagnostic scope: %v\n%s", err, output)
	}
}
