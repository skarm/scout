package cli

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/report"
)

type destination struct {
	format report.Format
	path   string
}

func cliFormat(value string) (report.Format, error) {
	if value == "terminal" {
		value = "text"
	}

	return report.ParseFormat(value)
}

func (r *request) protectedInputs() []string {
	inputs := r.localInputs()
	for _, name := range []string{r.configPath, r.settings.BaselinePath, r.settings.ExtraRulesPath, r.settings.OSVCachePath} {
		if name != "" {
			inputs = append(inputs, name)
		}
	}

	return inputs
}

func (r *request) outputs() ([]destination, error) {
	format, err := cliFormat(r.format)
	if err != nil {
		return nil, err
	}

	outputs := []destination{{format: format, path: r.output}}
	for _, entry := range r.reports {
		kind, path, ok := strings.Cut(entry, "=")
		if !ok || path == "" {
			return nil, errors.New("report must be format=path")
		}

		format, err := cliFormat(kind)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, destination{format: format, path: path})
	}

	return resolveOutputs(outputs, r.protectedInputs())
}

func (r *request) publish(ctx context.Context, outputs []destination, doc report.PreparedDocument, stdout io.Writer) error {
	// The immutable document was validated before publication. Each destination
	// is independently atomic; several files are not a filesystem transaction.
	return r.publishOutputs(ctx, outputs, stdout, doc.Write)
}

func (r *request) publishFailure(ctx context.Context, outputs []destination, operation report.Operation, problem report.Problem, stdout io.Writer) error {
	return r.publishOutputs(ctx, outputs, stdout, func(w io.Writer, format report.Format) error {
		return report.WriteFailure(w, format, operation, problem)
	})
}

func (r *request) publishOutputs(ctx context.Context, outputs []destination, stdout io.Writer, render func(io.Writer, report.Format) error) error {
	var failures []error

	for _, out := range outputs {
		write := func(w io.Writer) error { return render(w, out.format) }

		var err error
		if out.path == "" {
			err = write(stdout)
		} else {
			err = output.Write(ctx, out.path, r.protectedInputs(), write)
		}

		if err != nil {
			failures = append(failures, err)
		}
	}

	return errors.Join(failures...)
}

func resolveOutputs(outputs []destination, inputs []string) ([]destination, error) {
	seen := map[string]bool{}

	for i := range outputs {
		if outputs[i].path == "" {
			continue
		}

		path, err := output.Validate(outputs[i].path, inputs)
		if err != nil {
			return nil, err
		}

		if seen[path] {
			return nil, errors.New("report destinations must be distinct")
		}

		seen[path] = true
		outputs[i].path = path
	}

	return outputs, nil
}
