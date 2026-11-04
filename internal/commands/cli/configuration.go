package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/skarm/scout"
	"github.com/skarm/scout/policy"
)

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
