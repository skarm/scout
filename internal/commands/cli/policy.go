package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	configfile "github.com/skarm/scout/internal/commands/config"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const maxShadowReportBytes = 64 << 20

func policyCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "shadow" {
		return usageError(stderr, "policy requires shadow")
	}

	fs := flag.NewFlagSet("policy shadow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("report", "", "required saved scout.report/v1 JSON")
	currentPath := fs.String("current", "", "required current scout.config/v1 JSON")
	trialPath := fs.String("trial", "", "required trial scout.config/v1 JSON")
	format := fs.String("format", "text", "output format: text or json")
	at := fs.String("at", "", "approval evaluation time as RFC3339 (default: now)")

	if err := parseFlags(fs, args[1:]); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 0 || *source == "" || *currentPath == "" || *trialPath == "" || *format != "text" && *format != "json" {
		return usageError(stderr, "policy shadow requires --report FILE --current FILE --trial FILE and --format text|json")
	}

	now := time.Now().UTC()

	if *at != "" {
		var err error

		now, err = time.Parse(time.RFC3339Nano, *at)
		if err != nil || now.IsZero() {
			return usageError(stderr, "--at requires an RFC3339 evaluation time")
		}
	}

	if err := ctx.Err(); err != nil {
		return usageError(stderr, err.Error())
	}

	document, err := readPolicyReport(*source)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	current, err := readShadowGate(*currentPath, *source)
	if err != nil {
		return usageError(stderr, "current policy: "+err.Error())
	}

	trial, err := readShadowGate(*trialPath, *source)
	if err != nil {
		return usageError(stderr, "trial policy: "+err.Error())
	}

	result, err := policy.Compare(document.Run, current, trial, now)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := ctx.Err(); err != nil {
		return usageError(stderr, err.Error())
	}

	if err := writePolicyShadow(stdout, *format, result); err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot write policy shadow report")
		return 2
	}

	return 0
}

func readPolicyReport(path string) (report.Document, error) {
	raw, err := readTrusted(path, nil, maxShadowReportBytes)
	if err != nil {
		return report.Document{}, errors.New("cannot read saved policy report input")
	}

	if err := uniqueJSON(raw); err != nil {
		return report.Document{}, fmt.Errorf("invalid saved policy report input: %w", err)
	}

	var document report.Document

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&document) != nil || document.Validate() != nil {
		return report.Document{}, errors.New("valid scout.report/v1 JSON required")
	}

	document.Run.Operation = document.Operation

	return document, nil
}

func readShadowGate(path, source string) (*policy.Gate, error) {
	inputs := []string{source}

	raw, err := readTrusted(path, inputs, maxConfigBytes)
	if err != nil {
		return nil, errors.New("cannot read operator configuration outside the saved report")
	}

	options, baselinePath, err := configfile.ParsePolicy(raw)
	if err != nil {
		return nil, err
	}

	options.Approvals, err = loadOperatorBaseline(baselinePath, inputs)
	if err != nil {
		return nil, err
	}

	return policy.New(options)
}

func writePolicyShadow(w io.Writer, format string, result policy.ShadowResult) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(result)
	}

	var out strings.Builder

	fmt.Fprintf(&out, "Policy shadow for run %s (%s) at %s\n", result.RunDigest, result.RunState, result.EvaluatedAt)
	fmt.Fprintf(&out, "Current: %s (admission exit %d), %s; reasons: %q\n", result.Current.Decision, result.Current.ExitCode, result.Current.PolicyDigest, result.Current.Reasons)
	fmt.Fprintf(&out, "Trial:   %s (admission exit %d), %s; reasons: %q\n", result.Trial.Decision, result.Trial.ExitCode, result.Trial.PolicyDigest, result.Trial.Reasons)
	fmt.Fprintf(&out, "Finding changes: %d\n", len(result.FindingChanges))

	for _, change := range result.FindingChanges {
		fmt.Fprintf(&out, "- %q (%q), target %q, %q bytes %d..%d: %s -> %s\n",
			change.RuleID, change.Severity, change.TargetID, change.Location.Path,
			change.Location.ByteStart, change.Location.ByteEnd, change.Current, change.Trial)
	}

	fmt.Fprintf(&out, "Manifest signal changes: %d\n", len(result.ManifestSignalChanges))

	for _, change := range result.ManifestSignalChanges {
		fmt.Fprintf(&out, "- %q (%q), field %q: %s -> %s\n", change.RuleID, change.Severity, change.Field, change.Current, change.Trial)
	}

	_, err := io.WriteString(w, out.String())

	return err
}
