package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"

	"github.com/skarm/scout/internal/distribution/attestation"
)

func attestationCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-attestation", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("public-key", "", "explicit trusted PKIX public key PEM outside inspected inputs")
	envelope := fs.String("envelope", "", "DSSE envelope or OMS bundle")
	artifact := fs.String("artifact", "", "regular artifact file whose exact bytes must match the signed subject")

	subject := fs.String("subject", "", "exact signed subject name")
	if err := fs.Parse(args); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 0 || *key == "" || *envelope == "" || *artifact == "" || *subject == "" {
		return usageError(stderr, "--public-key, --envelope, --artifact and --subject are required")
	}

	trusted, err := readTrusted(*key, []string{*envelope, *artifact}, 64<<10)
	if err != nil {
		return usageError(stderr, "cannot read explicit trusted key outside inputs")
	}

	raw, err := readTrusted(*envelope, nil, 256<<10)
	if err != nil {
		return usageError(stderr, "cannot read envelope")
	}

	bytes, err := readTrusted(*artifact, nil, 32<<20)
	if err != nil {
		return usageError(stderr, "cannot read artifact bytes")
	}

	hash := sha256.Sum256(bytes)

	result, err := attestation.Verify(ctx, trusted, raw, attestation.Artifact{
		Name:   *subject,
		SHA256: hex.EncodeToString(hash[:]),
	})
	if err != nil {
		return usageError(stderr, err.Error())
	}

	if err := writeOperatorJSON(ctx, "", nil, result, stdout); err != nil {
		return 2
	}

	if !result.Verified {
		return 1
	}

	return 0
}
