package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

type baselineArguments struct{ operation, from, destination, reason, expiry string }

func configCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		return usageError(stderr, "config validate required")
	}

	r, err := parseRequest("config validate", args[1:], stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	if err := r.validateConfigCommand(); err != nil {
		return usageError(stderr, err.Error())
	}

	s, err := scout.New(ctx, r.settings.Scanner)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	// Scanner.Close currently releases owned resources without returning errors.
	defer func() { _ = s.Close() }()

	if json.NewEncoder(stdout).Encode(s.InspectionPlan()) != nil {
		return 2
	}

	return 0
}

func parseBaselineArguments(args []string, stderr io.Writer) (baselineArguments, error) {
	if len(args) == 0 || args[0] != "create" && args[0] != "approve" {
		return baselineArguments{}, errors.New("baseline create or approve required")
	}

	fs := flag.NewFlagSet("baseline "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "validated scout.report/v1 JSON for create; baseline JSON for approve")
	destination := fs.String("output", "", "operator baseline destination")
	reason := fs.String("reason", "", "operator justification")

	expiry := fs.String("expires", "", "future RFC3339 expiry")
	if err := fs.Parse(args[1:]); err != nil {
		return baselineArguments{}, err
	}

	if fs.NArg() != 0 || *from == "" || *destination == "" {
		return baselineArguments{}, errors.New("baseline requires --from and --output")
	}

	return baselineArguments{
		operation:   args[0],
		from:        *from,
		destination: *destination,
		reason:      *reason,
		expiry:      *expiry,
	}, nil
}

func baselineCommand(ctx context.Context, args []string, stderr io.Writer) int {
	options, err := parseBaselineArguments(args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	raw, err := readTrusted(options.from, nil, 16<<20)
	if err != nil {
		return usageError(stderr, "cannot read baseline source")
	}

	expires, err := time.Parse(time.RFC3339, options.expiry)
	if err != nil || !expires.After(time.Now()) {
		return usageError(stderr, "future --expires required")
	}

	d, err := editBaseline(raw, options, expires)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	data, err := baseline.Marshal(d)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	err = output.Write(ctx, options.destination, []string{options.from}, func(w io.Writer) error { return writeBaselineBytes(w, data) })
	if err != nil {
		return usageError(stderr, err.Error())
	}

	return 0
}

func editBaseline(raw []byte, options baselineArguments, expires time.Time) (baseline.Document, error) {
	var d baseline.Document

	if options.operation == "create" {
		var doc report.Document
		if json.Unmarshal(raw, &doc) != nil || doc.Validate() != nil || len(doc.Run.Targets) != 1 {
			return d, errors.New("one validated target report required")
		}

		return baseline.Create(doc.Run.Targets[0].Analysis, options.reason, expires, false)
	}

	d, err := baseline.Parse(raw)
	if err != nil {
		return d, err
	}

	for i := range d.Entries {
		d.Entries[i].Approved = true
		d.Entries[i].Reason = options.reason
		d.Entries[i].Expires = expires.Format(time.RFC3339)
	}

	return d, nil
}

func writeBaselineBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}

	return err
}

func (r *request) validateConfigCommand() error {
	if len(r.targets) != 0 || r.input != "" {
		return errors.New("config validate has no targets")
	}

	if err := r.loadTrusted(); err != nil {
		return err
	}

	if _, err := policy.New(r.settings.Policy); err != nil {
		return err
	}

	return nil
}
