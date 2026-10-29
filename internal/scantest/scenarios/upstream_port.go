package scenarios

import (
	"context"
	"errors"
	"testing"

	"github.com/skarm/scout/internal/scantest"
)

func PortRules(t *testing.T, name, text string) (result scantest.Result, err error) {
	t.Helper()

	cfg := scantest.DefaultConfig()
	cfg.Scanner.Checks.Patterns = true

	s, err := scantest.New(cfg)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, s.Close()) }()

	return s.ScanBytes(context.Background(), name, []byte(text))
}

func HasPortRule(r scantest.Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}

	return false
}
