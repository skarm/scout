package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/skarm/scout/internal/commands/cli"
	"github.com/skarm/scout/internal/nativecontract"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
)

func TestSelftestCLI(t *testing.T) {
	var out, errout bytes.Buffer
	code := cli.Run(context.Background(), []string{"selftest", "--format", "json"}, &out, &errout)
	var r nativecontract.Report
	if e := json.Unmarshal(out.Bytes(), &r); e != nil {
		t.Fatal(e, out.String(), errout.String())
	}
	full := frontend.BackendFor("python").Available && frontend.BackendFor("yaml").Available && frontend.BackendFor("toml").Available && signatures.Backend().Available
	if (code == 0) != full || r.Passed != full || errout.Len() != 0 {
		t.Fatal(code, r, errout.String())
	}
}

func TestSelftestRejectsTargetsAndInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"selftest", "target.py"}, {"selftest", "--format", "sarif"}, {"selftest", "--timeout", "0"}, {"selftest", "--python-interpreter", "/usr/bin/python"}} {
		var o, e bytes.Buffer
		if got := cli.Run(context.Background(), args, &o, &e); got != 2 {
			t.Fatal(args, got)
		}
	}
}
