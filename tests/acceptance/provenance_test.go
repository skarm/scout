//go:build acceptance

package scout_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/dev/provenance"
)

const (
	capturePath   = "testdata/acceptance/upstream-inputs.jsonl.gz"
	captureSHA    = "d91462dbe6513a9a43ab2e91849a93db0c06dd3f21ef63dd47708050a4c3f299"
	captureIDsSHA = "8822cc765d0341faef0fcaeb583b8e147ed1527030f417976c24af870241cb2f"
)

func TestCurrentAcceptance(t *testing.T) {
	manifest, err := provenance.Read("../..", "testdata/provenance/scout-current-review.json")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Summary.Inputs != 14930 {
		t.Fatal("acceptance dropped captured inputs")
	}
	if manifest.Summary.RuntimeErrors != 0 {
		t.Fatal("acceptance contains runtime failures")
	}
	if manifest.Input.Path != capturePath || manifest.Input.SHA256 != captureSHA || manifest.InputIDsSHA256 != captureIDsSHA {
		t.Fatal("acceptance differs from trusted capture pins")
	}
	// Exact source hashes bind the measured build to this checkout. A new tag or
	// commit can change the verifier's identifier without changing those sources.
	if err := provenance.Verify(context.Background(), "../..", manifest, provenance.Verification{
		Version:   manifest.Version,
		InputMode: provenance.InputFile,
	}); err != nil {
		t.Fatal(err)
	}
}
