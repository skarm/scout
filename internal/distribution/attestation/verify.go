// Package attestation verifies a DSSE in-toto statement with an explicitly
// trusted operator public key and a specific artifact digest. It does not infer
// trust from bundled certificates, key IDs, transparency logs or registry claims.
package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type (
	Artifact struct{ Name, SHA256 string }
	result   struct {
		Schema            string `json:"schema"`
		Verified          bool   `json:"verified"`
		Code              string `json:"code"`
		KeySHA256         string `json:"key_sha256,omitempty"`
		PayloadSHA256     string `json:"payload_sha256,omitempty"`
		ArtifactSHA256    string `json:"artifact_sha256"`
		SubjectNameSHA256 string `json:"subject_name_sha256"`
	}
)

type signedEnvelope struct {
	payload, pae []byte
	signatures   [][]byte
}

func Verify(ctx context.Context, trustedKey, envelope []byte, artifact Artifact) (result, error) {
	out := result{
		Schema:            "scout.attestation/v1",
		Code:              "invalid_input",
		ArtifactSHA256:    artifact.SHA256,
		SubjectNameSHA256: digest([]byte(artifact.Name)),
	}
	if ctx == nil || len(trustedKey) > 64<<10 || artifact.Name == "" || len(artifact.Name) > 4096 || len(artifact.SHA256) != 64 {
		return out, errors.New("invalid attestation input")
	}

	if _, err := hex.DecodeString(artifact.SHA256); err != nil || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
		return out, errors.New("invalid artifact digest")
	}

	key, der, err := parseKey(trustedKey)
	if err != nil {
		return out, err
	}

	out.KeySHA256 = digest(der)

	envelopeData, err := parseEnvelope(ctx, envelope)
	if err != nil {
		return out, err
	}

	out.PayloadSHA256 = digest(envelopeData.payload)
	valid := false

	for _, sig := range envelopeData.signatures {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		valid = verifySignature(key, envelopeData.pae, sig) || valid
	}

	if !valid {
		out.Code = "signature_mismatch"
		return out, nil
	}

	matched, err := matchesSubject(ctx, envelopeData.payload, artifact)
	if err != nil {
		return out, err
	}

	if !matched {
		out.Code = "subject_mismatch"
		return out, nil
	}

	out.Verified = true
	out.Code = "verified_explicit_key_and_artifact"

	return out, nil
}

func parseEnvelope(ctx context.Context, envelope []byte) (signedEnvelope, error) {
	var out signedEnvelope

	root, err := jsonconfig.Parse(ctx, string(envelope))
	if err != nil {
		return out, errors.New("invalid attestation envelope")
	}

	if nested := root.Get("dsseEnvelope"); nested != nil {
		root = nested
	}

	kind, ok := root.Get("payloadType").Text()
	if !ok || kind != "application/vnd.in-toto+json" {
		return out, errors.New("unsupported attestation payload type")
	}

	encoded, ok := root.Get("payload").Text()
	if !ok {
		return out, errors.New("attestation payload required")
	}

	out.payload, err = decode(encoded)
	if err != nil || len(out.payload) > jsonconfig.MaxBytes {
		return out, errors.New("invalid attestation payload")
	}

	signatures := root.Get("signatures")
	if signatures == nil || signatures.Kind != jsonconfig.KindArray || len(signatures.Elements) < 1 || len(signatures.Elements) > 64 {
		return out, errors.New("invalid attestation signature inventory")
	}

	for _, entry := range signatures.Elements {
		encoded, ok := entry.Get("sig").Text()
		if !ok {
			return out, errors.New("invalid attestation signature")
		}

		sig, err := decode(encoded)
		if err != nil || len(sig) > 8192 {
			return out, errors.New("invalid attestation signature encoding")
		}

		out.signatures = append(out.signatures, sig)
	}

	out.pae = []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(kind), kind, len(out.payload), out.payload))

	return out, nil
}

func matchesSubject(ctx context.Context, payload []byte, artifact Artifact) (bool, error) {
	statement, err := jsonconfig.Parse(ctx, string(payload))
	if err != nil {
		return false, errors.New("invalid signed statement")
	}

	kind, ok := statement.Get("_type").Text()
	if !ok || kind != "https://in-toto.io/Statement/v1" && kind != "https://in-toto.io/Statement/v0.1" {
		return false, errors.New("unsupported signed statement")
	}

	subjects := statement.Get("subject")
	if subjects == nil || subjects.Kind != jsonconfig.KindArray || len(subjects.Elements) > 256 {
		return false, errors.New("invalid signed subjects")
	}

	matches := 0

	for _, subject := range subjects.Elements {
		name, _ := subject.Get("name").Text()
		hash, _ := subject.Get("digest").Get("sha256").Text()

		if name != artifact.Name {
			continue
		}

		if hash != artifact.SHA256 {
			return false, nil
		}

		matches++
	}

	return matches == 1, nil
}

func parseKey(data []byte) (crypto.PublicKey, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) > 0 || block.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("one explicit PKIX public key PEM required")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("invalid public key")
	}

	switch key := key.(type) {
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize {
			return key, block.Bytes, nil
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().Name == "P-256" {
			return key, block.Bytes, nil
		}
	case *rsa.PublicKey:
		if key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 65537 {
			return key, block.Bytes, nil
		}
	}

	return nil, nil, errors.New("supported keys: Ed25519, P-256 ECDSA ASN.1 or RSA-PSS SHA-256")
}

func verifySignature(key crypto.PublicKey, body, sig []byte) bool {
	hash := sha256.Sum256(body)

	switch key := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(key, body, sig)
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, hash[:], sig)
	case *rsa.PublicKey:
		return rsa.VerifyPSS(key, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}

	return false
}

func decode(text string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict()} {
		if data, err := encoding.DecodeString(text); err == nil {
			return data, nil
		}
	}

	return nil, errors.New("invalid base64")
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
