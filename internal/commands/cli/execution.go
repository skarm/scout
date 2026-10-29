package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

func scanCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	r, err := parseRequest("scan", args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	targets, err := r.scanTargets(stdin)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	return executeRequest(ctx, r, targets, report.ScanOperation, stdout, stderr)
}

func compareCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	r, err := parseRequest("compare", args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	if err := r.validateComparison(); err != nil {
		return usageError(stderr, err.Error())
	}

	return executeRequest(ctx, r, []scout.Target{scout.Path(r.targets[0]), scout.Path(r.targets[1])}, report.CompareOperation, stdout, stderr)
}

func requestError(err error, stderr io.Writer) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}

	return usageError(stderr, err.Error())
}

func (r *request) scanTargets(stdin io.Reader) ([]scout.Target, error) {
	if r.input != "" {
		target, err := r.stdinTarget(stdin)
		if err != nil {
			return nil, err
		}

		return []scout.Target{target}, nil
	}

	if r.name != "" || len(r.targets) == 0 || len(r.targets) > 32 {
		return nil, errors.New("scan requires 1..32 targets")
	}

	targets := make([]scout.Target, len(r.targets))
	for i, name := range r.targets {
		target, err := r.scanTarget(name)
		if err != nil {
			return nil, err
		}

		targets[i] = target
	}

	return targets, nil
}

func (r *request) localInputs() []string {
	var inputs []string

	for _, name := range r.targets {
		if !fetch.IsRemote(name) {
			inputs = append(inputs, name)
		}
	}

	return inputs
}

func (r *request) loadTrusted() error {
	inputs := r.localInputs()
	// Recheck the config boundary after all targets have been parsed.
	if r.configPath != "" {
		if _, err := readTrusted(r.configPath, inputs, 256<<10); err != nil {
			return errors.New("config must be outside every input")
		}
	}

	if err := r.loadBaseline(inputs); err != nil {
		return err
	}

	return r.loadTrustedServices(inputs)
}

func (r *request) loadBaseline(inputs []string) error {
	if r.settings.BaselinePath != "" {
		data, err := readTrusted(r.settings.BaselinePath, inputs, baseline.MaxBytes)
		if err != nil {
			return errors.New("cannot read operator baseline")
		}

		d, err := baseline.Parse(data)
		if err != nil {
			return err
		}

		r.settings.Policy.Approvals = &d
	}

	return nil
}

func (r *request) loadTrustedServices(inputs []string) error {
	if r.settings.ExtraRulesPath != "" {
		data, err := readTrusted(r.settings.ExtraRulesPath, inputs, 256<<10)
		if err != nil {
			return errors.New("cannot read extra rules")
		}

		r.settings.Scanner.Signatures.ExtraRules = data
	}

	if r.settings.OSVCachePath != "" {
		data, err := readTrusted(r.settings.OSVCachePath, inputs, 8<<20)
		if err != nil {
			return errors.New("cannot read vulnerability cache")
		}

		if r.settings.Scanner.Vulnerabilities == nil {
			return errors.New("cache requires vulnerability service")
		}

		r.settings.Scanner.Vulnerabilities.Offline = data
	}

	return nil
}

func (r *request) publishRun(ctx context.Context, outputs []destination, operation report.Operation, run report.Run, gate *policy.Gate, stdout, stderr io.Writer) int {
	if run.Digest == "" {
		r.publishProblem(ctx, outputs, operation, report.Problem{Code: "execution_failed", Phase: "execute"}, stdout, stderr)
		return 2
	}

	d := report.NewDocument(run, gate.Evaluate(run, time.Now().UTC()))

	prepared, err := report.Prepare(d)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "report preparation failed:", err)
		return 2
	}
	// A cancelled scan still publishes its partial evidence under a separate,
	// bounded publication context. It does not resume analysis or service calls.
	publish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err = r.publish(publish, outputs, prepared, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "report publication failed:", err)
		return 2
	}

	return policy.PreparedCode(prepared)
}

func (r *request) publishProblem(ctx context.Context, outputs []destination, operation report.Operation, problem report.Problem, stdout, stderr io.Writer) {
	publish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err := r.publishFailure(publish, outputs, operation, problem, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "report publication failed:", err)
	}
}

func (r *request) scanTarget(name string) (scout.Target, error) {
	if !fetch.IsRemote(name) {
		return scout.Path(name), nil
	}

	pin := r.settings.RemotePins[name]
	if r.revision != "" {
		pin.Revision = r.revision
	}

	if r.sha256 != "" {
		pin.SHA256 = r.sha256
	}

	return scout.Remote(name, pin)
}

func (r *request) validateComparison() error {
	if len(r.targets) != 2 || r.input != "" || r.name != "" || r.grants.Download || r.revision != "" || r.sha256 != "" {
		return errors.New("compare requires two local inputs")
	}

	if err := (report.UpdateOptions{MaxChanges: r.compare.MaxChanges}).Validate(); err != nil {
		return err
	}

	if slices.ContainsFunc(r.targets, fetch.IsRemote) {
		return errors.New("comparison inputs must be local")
	}

	return nil
}

func (r *request) stdinTarget(stdin io.Reader) (scout.Target, error) {
	if r.input != "-" || r.name == "" || len(r.targets) != 0 {
		return scout.Target{}, errors.New("stdin requires --input - --name and no positional targets")
	}

	return stdinReaderTarget(r.name, stdin), nil
}

func executeRequest(ctx context.Context, r request, targets []scout.Target, operation report.Operation, stdout, stderr io.Writer) int {
	outputs, err := r.outputs()
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err = r.loadTrusted(); err != nil {
		return usageError(stderr, err.Error())
	}

	gate, err := policy.New(r.settings.Policy)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	scanner, err := scout.New(ctx, r.settings.Scanner)
	if err != nil {
		if errors.Is(err, scout.ErrInvalidOptions) {
			return usageError(stderr, err.Error())
		}

		_, _ = fmt.Fprintln(stderr, "scanner initialization failed:", err)
		r.publishProblem(ctx, outputs, operation, report.Problem{Code: "initialization_failed", Phase: "initialize"}, stdout, stderr)

		return 2
	}
	// Scanner.Close currently releases owned resources without returning errors.
	defer func() { _ = scanner.Close() }()

	var run report.Run
	if operation == report.CompareOperation {
		run, err = scanner.Compare(ctx, targets[0], targets[1], r.compare)
	} else {
		run, err = scanner.ScanMany(ctx, targets)
	}

	if err != nil {
		_, _ = fmt.Fprintln(stderr, "inspection incomplete:", err)
	}

	return r.publishRun(ctx, outputs, operation, run, gate, stdout, stderr)
}
