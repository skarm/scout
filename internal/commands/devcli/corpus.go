package devcli

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"time"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/commands/output"
	"github.com/skarm/scout/internal/dev/evaluation"
)

func corpusCommand(ctx context.Context, args []string, out, diag io.Writer) int {
	if len(args) != 0 && args[0] == "review-template" {
		return corpusReviewTemplate(ctx, args[1:], out, diag)
	}

	if len(args) == 0 || args[0] != "collect" {
		return failure(diag, errors.New("corpus collect or review-template required"))
	}

	fs := flag.NewFlagSet("corpus collect", flag.ContinueOnError)
	fs.SetOutput(diag)
	manifestPath := fs.String("manifest", "", "explicit scout.corpus-sources/v1 JSON with source provenance and file SHA-256 pins")
	destination := fs.String("output", "", "corpus destination outside source files; omitted writes JSON to stdout")
	allowDownload := fs.Bool("allow-download", false, "authorize the manifest's pinned HTTPS file downloads")

	timeout := fs.Duration("timeout", 2*time.Minute, "whole collection deadline; maximum 10m")
	if err := fs.Parse(args[1:]); err != nil {
		return failure(diag, err)
	}

	if fs.NArg() != 0 || *manifestPath == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		return failure(diag, errors.New("corpus collect requires --manifest and a bounded timeout"))
	}

	call, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	raw, err := readEvaluationFile(call, *manifestPath, evaluation.MaxCollectionManifestBytes)
	if err != nil {
		return failure(diag, err)
	}

	manifest, err := evaluation.ParseCollectionManifest(raw)
	if err != nil {
		return failure(diag, err)
	}

	download := fetch.DefaultOptions()
	download.Enabled = *allowDownload

	data, inputs, err := evaluation.Collect(call, manifest, filepath.Dir(*manifestPath), download)
	if err != nil {
		return failure(diag, err)
	}

	inputs = append(inputs, *manifestPath)

	if err := writeCorpusArtifact(call, *destination, inputs, data, out); err != nil {
		return failure(diag, err)
	}

	return 0
}

func corpusReviewTemplate(ctx context.Context, args []string, out, diag io.Writer) int {
	fs := flag.NewFlagSet("corpus review-template", flag.ContinueOnError)
	fs.SetOutput(diag)
	source := fs.String("corpus", "", "exact schema-2 corpus whose cases will be reviewed")

	destination := fs.String("output", "", "pending review destination outside the corpus; omitted writes JSON to stdout")
	if err := fs.Parse(args); err != nil {
		return failure(diag, err)
	}

	if fs.NArg() != 0 || *source == "" {
		return failure(diag, errors.New("corpus review-template requires --corpus"))
	}

	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, err := readEvaluationFile(call, *source, evaluation.MaxCorpusBytes)
	if err != nil {
		return failure(diag, err)
	}

	template, err := evaluation.LabelReviewTemplate(data)
	if err != nil {
		return failure(diag, err)
	}

	if err := writeCorpusArtifact(call, *destination, []string{*source}, template, out); err != nil {
		return failure(diag, err)
	}

	return 0
}

func writeCorpusArtifact(ctx context.Context, destination string, inputs []string, data []byte, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	write := func(w io.Writer) error {
		n, err := w.Write(data)
		if err == nil && n != len(data) {
			return io.ErrShortWrite
		}

		return err
	}
	if destination == "" {
		return write(out)
	}

	return output.Write(ctx, destination, inputs, write)
}
