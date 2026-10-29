package attestation_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/distribution/attestation"
)

func TestExplicitKeyAndArtifactBinding(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact, envelope, trusted := signedEnvelope(t, key)
	result, err := attestation.Verify(context.Background(), trusted, envelope, artifact)
	if err != nil || !result.Verified || result.KeySHA256 == "" || result.PayloadSHA256 == "" {
		t.Fatalf("%+v %v", result, err)
	}
	artifact.SHA256 = strings.Repeat("a", 64)
	result, err = attestation.Verify(context.Background(), trusted, envelope, artifact)
	if err != nil || result.Verified || result.Code != "subject_mismatch" {
		t.Fatalf("unrelated artifact trusted: %+v %v", result, err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, _, wrong := signedEnvelope(t, other)
	artifact, _, _ = signedEnvelope(t, key)
	result, err = attestation.Verify(context.Background(), wrong, envelope, artifact)
	if err != nil || result.Verified || result.Code != "signature_mismatch" {
		t.Fatalf("untrusted signer accepted: %+v %v", result, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["payloadType"] = "application/json"
	invalid, _ := json.Marshal(decoded)
	if _, err := attestation.Verify(context.Background(), trusted, invalid, artifact); err == nil {
		t.Fatal("payload type was not bound")
	}
	duplicate := strings.Replace(string(envelope), `"payloadType":`, `"payloadType":"application/json","payloadType":`, 1)
	if _, err := attestation.Verify(context.Background(), trusted, []byte(duplicate), artifact); err == nil {
		t.Fatal("ambiguous envelope accepted")
	}
	decoded["payloadType"] = "application/vnd.in-toto+json"
	decoded["payload"] = base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`))
	invalid, _ = json.Marshal(decoded)
	result, err = attestation.Verify(context.Background(), trusted, invalid, artifact)
	if err != nil || result.Verified {
		t.Fatal("mutated signed payload trusted")
	}
}

func TestSupportedAlgorithmsAndOMSWrapper(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{ec, rsaKey} {
		artifact, envelope, trusted := signedEnvelope(t, key)
		wrapped := append([]byte(`{"verificationMaterial":{"untrusted":"ignored"},"dsseEnvelope":`), envelope...)
		wrapped = append(wrapped, '}')
		r, err := attestation.Verify(context.Background(), trusted, wrapped, artifact)
		if err != nil || !r.Verified {
			t.Fatalf("%T failed: %+v %v", key, r, err)
		}
	}
}

func signedEnvelope(t *testing.T, key crypto.Signer) (attestation.Artifact, []byte, []byte) {
	t.Helper()
	sum := sha256.Sum256([]byte("inert artifact bytes"))
	hash := hex.EncodeToString(sum[:])
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"bundle.zip","digest":{"sha256":"` + hash + `"}}],"predicateType":"https://example.invalid/test"}`)
	kind := "application/vnd.in-toto+json"
	// Construct the verifier's input from the DSSE protocol, independently of
	// the product implementation. Key IDs are intentionally irrelevant hints.
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(kind), kind, len(payload)))
	pae = append(pae, payload...)
	message := pae
	var options crypto.SignerOpts = crypto.Hash(0)
	if _, ok := key.(ed25519.PrivateKey); !ok {
		hash := sha256.Sum256(pae)
		message = hash[:]
		options = crypto.SHA256
	}
	if _, ok := key.(*rsa.PrivateKey); ok {
		options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	}
	sig, err := key.Sign(rand.Reader, message, options)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{
		"payloadType": kind,
		"payload":     base64.RawURLEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{
			"keyid": "not-trusted-by-the-verifier",
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return attestation.Artifact{Name: "bundle.zip", SHA256: hash}, envelope, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}
