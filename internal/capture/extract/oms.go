package extract

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

type omsProjector struct {
	operation *operation
	count     int
}

// OMS projection is inspection of untrusted signed-container claims. Parsing a
// certificate or payload never establishes a trusted signer or valid signature.
func extractOMSCertificates(o *operation) error {
	root, err := jsonconfig.Parse(o.b.ctx, o.parent.file.Content())
	if err != nil {
		return errFormat
	}

	if root.Get("dsseEnvelope") == nil {
		return errFormat
	}

	material := root.Get("verificationMaterial")
	if material == nil || material.Kind != jsonconfig.KindObject {
		return errFormat
	}

	projector := omsProjector{operation: o}

	return projector.walk(material)
}

func (p *omsProjector) walk(n *jsonconfig.Node) error {
	if err := p.operation.entry(); err != nil {
		return err
	}

	if n == nil {
		return nil
	}

	for _, member := range n.Members {
		if member.Value.Kind == jsonconfig.KindString && (member.Key == "rawBytes" || member.Key == "verifier" || member.Key == "canonicalizedBody") {
			if err := p.field(member.Key, member.Value.String); err != nil {
				return err
			}
		} else if err := p.walk(member.Value); err != nil {
			return err
		}
	}

	for _, entry := range n.Elements {
		if err := p.walk(entry); err != nil {
			return err
		}
	}

	return nil
}

func (p *omsProjector) field(key, value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if strings.HasPrefix(value, "-----BEGIN ") {
		decoded = []byte(value)
		err = nil
	}

	if err != nil {
		return errFormat
	}

	if key == "canonicalizedBody" {
		body, err := jsonconfig.Parse(p.operation.b.ctx, string(decoded))
		if err != nil {
			return errFormat
		}

		return p.walk(body)
	}

	if block, _ := pem.Decode(decoded); block != nil {
		decoded = block.Bytes
	}

	return p.certificate(decoded)
}

func (p *omsProjector) certificate(decoded []byte) error {
	certificate, err := x509.ParseCertificate(decoded)
	if err != nil {
		return errFormat
	}

	p.count++
	if p.count > 64 {
		return errBudget
	}

	claims := map[string]any{
		"untrusted_subject":         certificate.Subject.String(),
		"untrusted_issuer":          certificate.Issuer.String(),
		"untrusted_dns_names":       certificate.DNSNames,
		"untrusted_email_addresses": certificate.EmailAddresses,
	}

	var uris []string
	for _, u := range certificate.URIs {
		uris = append(uris, u.String())
	}

	claims["untrusted_uris"] = uris

	data, err := json.Marshal(claims)
	if err != nil {
		return errFormat
	}

	return p.operation.text(fmt.Sprintf("certificate-claims-%d.json", p.count), string(data), nil)
}

func omsCandidate(name, text string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".oms.sig") || strings.Contains(text, `"dsseEnvelope"`)
}
