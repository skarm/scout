package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/skarm/scout/internal/capture/envsnapshot"
	"github.com/skarm/scout/report"
)

func (r *request) publishCaptureFailure(ctx context.Context, mode string, outputs []destination, err error, stdout, stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "environment capture failed:", err)

	var problem *envsnapshot.CaptureError
	if !errors.As(err, &problem) {
		problem = &envsnapshot.CaptureError{Code: "capture_failed", Detail: err.Error()}
	}

	doc := struct {
		Schema    string                    `json:"schema"`
		Operation string                    `json:"operation"`
		Problem   *envsnapshot.CaptureError `json:"problem"`
		Code      int                       `json:"exit_code"`
	}{"scout.environment-snapshot-error/v1", mode, problem, 2}

	jsonOutputs := slices.DeleteFunc(slices.Clone(outputs), func(out destination) bool { return out.format != report.JSON })

	publish, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportPublicationTimeout)
	defer cancel()

	if err := r.publishOutputs(publish, jsonOutputs, stdout, func(w io.Writer, _ report.Format) error {
		return json.NewEncoder(w).Encode(doc)
	}); err != nil {
		_, _ = fmt.Fprintln(stderr, "capture error publication failed:", err)
	}

	return 2
}
