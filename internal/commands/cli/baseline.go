package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/skarm/scout/baseline"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

type baselineArguments struct {
	operation, from, destination, reason, expiry string
	fingerprints                                 repeated
	dryRun                                       bool
}

type baselineChange struct {
	Index  int             `json:"entry_index"`
	Before *baseline.Entry `json:"before,omitempty"`
	After  baseline.Entry  `json:"after"`
}

func parseBaselineArguments(args []string, stderr io.Writer) (baselineArguments, error) {
	if len(args) == 0 || args[0] != "create" && args[0] != "approve" && args[0] != "renew" {
		return baselineArguments{}, errors.New("baseline create, approve or renew required")
	}

	a := baselineArguments{operation: args[0]}
	fs := flag.NewFlagSet("baseline "+a.operation, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.from, "from", "", "validated scout.report/v1 JSON for create; baseline JSON for approve/renew")
	fs.StringVar(&a.destination, "output", "", "operator baseline destination; optional with --dry-run")
	fs.StringVar(&a.reason, "reason", "", "operator justification; renew preserves the reason when omitted")
	fs.StringVar(&a.expiry, "expires", "", "future RFC3339 expiry; renew must extend the selected expiry")
	fs.Var(&a.fingerprints, "fingerprint", "select an exact finding fingerprint for approve/renew; repeatable; omitted selects all")
	fs.BoolVar(&a.dryRun, "dry-run", false, "print a JSON change preview without writing a baseline")

	if err := fs.Parse(args[1:]); err != nil {
		return a, err
	}

	if fs.NArg() != 0 || a.from == "" || a.destination == "" && !a.dryRun {
		return a, errors.New("baseline requires --from and either --output or --dry-run")
	}

	if a.operation == "create" && len(a.fingerprints) != 0 {
		return a, errors.New("--fingerprint requires approve or renew")
	}

	seen := make(map[string]bool, len(a.fingerprints))
	for _, fingerprint := range a.fingerprints {
		if !textmatch.LowerHex(fingerprint, 64) || seen[fingerprint] {
			return a, errors.New("--fingerprint requires unique lowercase SHA-256 fingerprints")
		}

		seen[fingerprint] = true
	}

	return a, nil
}

func baselineCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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

	d, changes, err := editBaseline(raw, options, expires)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	data, err := baseline.Marshal(d)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := ctx.Err(); err != nil {
		return usageError(stderr, err.Error())
	}

	if options.dryRun {
		if options.destination != "" {
			if _, err := output.Validate(options.destination, []string{options.from}); err != nil {
				return usageError(stderr, err.Error())
			}
		}

		return writeBaselinePreview(stdout, options.operation, changes)
	}

	err = output.Write(ctx, options.destination, []string{options.from}, func(w io.Writer) error { return writeBaselineBytes(w, data) })
	if err != nil {
		return usageError(stderr, err.Error())
	}

	return 0
}

func editBaseline(raw []byte, options baselineArguments, expires time.Time) (baseline.Document, []baselineChange, error) {
	if options.operation == "create" {
		return createBaseline(raw, options, expires)
	}

	d, err := baseline.Parse(raw)
	if err != nil {
		return d, nil, err
	}

	selected := make(map[string]bool, len(options.fingerprints))
	for _, fingerprint := range options.fingerprints {
		selected[fingerprint] = false
	}

	changes := []baselineChange{}

	for i, before := range d.Entries {
		if _, matches := selected[before.Fingerprint]; !matches && len(selected) != 0 {
			continue
		}

		if len(selected) != 0 {
			selected[before.Fingerprint] = true
		}

		if options.operation == "renew" && !before.Approved && len(selected) == 0 {
			continue
		}

		after, err := editBaselineEntry(before, options, expires)
		if err != nil {
			return d, nil, err
		}

		d.Entries[i] = after
		if after != before {
			changes = append(changes, baselineChange{Index: i, Before: &before, After: after})
		}
	}

	for _, matched := range selected {
		if !matched {
			return d, nil, errors.New("selected fingerprint is not present in the baseline")
		}
	}

	if options.operation == "renew" && len(changes) == 0 {
		return d, nil, errors.New("renew requires at least one approved entry")
	}

	return d, changes, nil
}

func editBaselineEntry(entry baseline.Entry, options baselineArguments, expires time.Time) (baseline.Entry, error) {
	if options.operation == "renew" {
		previous, _ := time.Parse(time.RFC3339, entry.Expires) // Validated by baseline.Parse.
		if !entry.Approved || !expires.After(previous) {
			return entry, errors.New("renew only extends already approved entries")
		}
	} else {
		entry.Approved = true
	}

	if options.reason != "" || options.operation == "approve" {
		entry.Reason = options.reason
	}

	entry.Expires = expires.Format(time.RFC3339)

	return entry, nil
}

func createBaseline(raw []byte, options baselineArguments, expires time.Time) (baseline.Document, []baselineChange, error) {
	var doc report.Document
	if json.Unmarshal(raw, &doc) != nil || doc.Validate() != nil || len(doc.Run.Targets) != 1 {
		return baseline.Document{}, nil, errors.New("one validated target report required")
	}

	d, err := baseline.Create(doc.Run.Targets[0].Analysis, options.reason, expires, false)

	changes := make([]baselineChange, len(d.Entries))
	for i, entry := range d.Entries {
		changes[i] = baselineChange{Index: i, After: entry}
	}

	return d, changes, err
}

func writeBaselinePreview(w io.Writer, operation string, changes []baselineChange) int {
	preview := struct {
		Schema    string           `json:"schema"`
		Operation string           `json:"operation"`
		Changes   []baselineChange `json:"changes"`
	}{Schema: "scout.baseline-preview/v1", Operation: operation, Changes: changes}
	if json.NewEncoder(w).Encode(preview) != nil {
		return 2
	}

	return 0
}

func writeBaselineBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}

	return err
}
