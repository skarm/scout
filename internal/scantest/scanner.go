// Package scantest provides fixture construction around the public APIs. It
// never repairs reports, suppresses errors or computes a second policy/delta.
package scantest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const (
	High = report.High
)

var ErrIncomplete = scout.ErrIncomplete

type Rule = report.Rule

type Config struct {
	Scanner scout.Options
	Gate    policy.Options
}

type Scanner struct {
	runtime *scout.Scanner
	gate    *policy.Gate
	pin     scout.RemotePin
}

// Result exposes observations next to the actual versioned report. Analysis is
// a convenience for assertions; JSON always encodes Document's real wire shape.
type Result struct {
	report.Analysis
	report.Document
}

type CompareOptions = scout.CompareOptions

// DefaultConfig selects builtins and the explicit historical fixture gate. The
// production default profile and gate are tested separately through the public APIs.
func DefaultConfig() Config {
	options := scout.DefaultOptions()
	options.Profile = scout.Custom
	options.Checks = &scout.Checks{}

	return Config{Scanner: options, Gate: policy.Options{FailAt: report.High, ReviewBelowThreshold: true}}
}

func FullConfig() Config {
	config := DefaultConfig()
	*config.Scanner.Checks = scout.Checks{Patterns: true, Python: true, YAML: true, TOML: true, YARA: true}

	return config
}

func New(config Config, owner ...testing.TB) (*Scanner, error) {
	options := config.Scanner

	pin := scout.RemotePin{}
	if options.Download != nil {
		pin = scout.RemotePin{Revision: options.Download.Revision, SHA256: options.Download.ExpectedSHA256}
	}

	gate, err := policy.New(config.Gate)
	if err != nil {
		return nil, err
	}

	scanner, err := scout.New(context.Background(), options)
	if err != nil {
		return nil, err
	}

	fixture := &Scanner{runtime: scanner, gate: gate, pin: pin}

	if len(owner) > 0 {
		owner[0].Cleanup(func() { _ = fixture.Close() })
	}

	return fixture, nil
}

func DefaultCompareOptions() scout.CompareOptions { return scout.DefaultCompareOptions() }

func ExitCode(result Result) int                  { return policy.Code(result.Document) }
func UpdateExitCode(document report.Document) int { return policy.Code(document) }
func Rules(all bool) []report.Rule                { return scout.Rules(all) }

// DecodeJSON accepts only a validated single-target v1 report. No flat-report
// fallback, policy fabrication or re-encoding into a different schema occurs.
func DecodeJSON(data []byte, destination *Result) error {
	var document report.Document
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}

	if err := document.Validate(); err != nil {
		return err
	}

	if len(document.Run.Targets) != 1 {
		return errors.New("fixture requires one target")
	}

	*destination = Result{Analysis: document.Run.Targets[0].Analysis, Document: document}

	return nil
}

func (s *Scanner) Close() error                          { return s.runtime.Close() }
func (s *Scanner) InspectionPlan() report.InspectionPlan { return s.runtime.InspectionPlan() }

func (s *Scanner) Scan(ctx context.Context, target string) (Result, error) {
	input := scout.Path(target)
	if fetch.IsRemote(target) {
		var err error

		input, err = scout.Remote(target, s.pin)
		if err != nil {
			return Result{}, err
		}
	}

	run, err := s.runtime.Scan(ctx, input)

	return s.single(run), err
}

func (s *Scanner) ScanBytes(ctx context.Context, name string, data []byte) (Result, error) {
	run, err := s.runtime.Scan(ctx, scout.Reader(name, bytes.NewReader(data)))
	return s.single(run), err
}

func (s *Scanner) ScanBatch(ctx context.Context, targets []string) (report.Document, error) {
	inputs := make([]scout.Target, len(targets))
	for i, target := range targets {
		inputs[i] = scout.Path(target)
	}

	run, err := s.runtime.ScanMany(ctx, inputs)

	return s.document(run), err
}

func (s *Scanner) Compare(ctx context.Context, before, after string, options scout.CompareOptions) (report.Document, error) {
	run, err := s.runtime.Compare(ctx, scout.Path(before), scout.Path(after), options)
	return s.document(run), err
}

func (s *Scanner) single(run report.Run) Result {
	result := Result{Document: s.document(run)}
	if len(run.Targets) == 1 {
		result.Analysis = run.Targets[0].Analysis
	}

	return result
}

func (s *Scanner) document(run report.Run) report.Document {
	return report.NewDocument(run, s.gate.Evaluate(run, time.Now()))
}

func (r Result) MarshalJSON() ([]byte, error) { return json.Marshal(r.Document) }
