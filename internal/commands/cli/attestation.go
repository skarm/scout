package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"

	"github.com/skarm/scout/internal/distribution/attestation"
)

const (
	flagArtifact  = "artifact"
	flagEnvelope  = "envelope"
	flagPublicKey = "public-key"
	flagSubject   = "subject"
)

const (
	maxAttestationEnvelopeFileBytes = 256 << 10
	maxAttestationArtifactFileBytes = 32 << 20
)

func attestationCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		return usageError(stderr, "attestation verify required")
	}

	fs := flag.NewFlagSet("attestation verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String(flagPublicKey, "", "explicit trusted PKIX public key PEM outside inspected inputs")
	envelope := fs.String(flagEnvelope, "", "DSSE envelope or OMS bundle")
	artifact := fs.String(flagArtifact, "", "regular artifact file whose exact bytes must match the signed subject")

	subject := fs.String(flagSubject, "", "exact signed subject name")
	if err := parseFlags(fs, args[1:]); err != nil {
		return requestError(err, stderr)
	}

	if fs.NArg() != 0 || *key == "" || *envelope == "" || *artifact == "" || *subject == "" {
		return usageError(stderr, "--public-key, --envelope, --artifact and --subject are required")
	}

	trusted, err := readTrusted(*key, []string{*envelope, *artifact}, attestation.MaxTrustedKeyBytes)
	if err != nil {
		return usageError(stderr, "cannot read explicit trusted key outside inputs")
	}

	raw, err := readTrusted(*envelope, nil, maxAttestationEnvelopeFileBytes)
	if err != nil {
		return usageError(stderr, "cannot read envelope")
	}

	bytes, err := readTrusted(*artifact, nil, maxAttestationArtifactFileBytes)
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
