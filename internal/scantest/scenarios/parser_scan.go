package scenarios

import (
	"testing"

	"github.com/skarm/scout/internal/scantest"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func ParserConfig(t *testing.T) scantest.Config {
	t.Helper()

	c := scantest.DefaultConfig()

	if !frontend.BackendFor("python").Available || !frontend.BackendFor("toml").Available {
		t.Skip("native/config parsers not linked in this core-only build")
	}

	c.Scanner.Checks.Python = true
	c.Scanner.Checks.TOML = true

	return c
}
