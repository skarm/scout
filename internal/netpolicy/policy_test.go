//nolint:testpackage // Exercises private implementation details and package fixtures.
package netpolicy

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAddressPolicyAndExplicitLoopback(t *testing.T) {
	for _, raw := range []string{"invalid", "10.0.0.1", "::ffff:10.0.0.1", "169.254.169.254", "127.0.0.1", "::1", "fe80::1%zone", "100.64.0.1", "192.88.99.1", "2001::1", "3fff::1", "64:ff9b::a00:1", "2001:db8::1"} {
		address, _ := netip.ParseAddr(raw)
		if PermittedIP(address, false) {
			t.Fatalf("allowed %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !PermittedIP(netip.MustParseAddr(raw), false) {
			t.Fatalf("rejected %s", raw)
		}
	}
	if !PermittedIP(netip.MustParseAddr("::1"), true) || PermittedIP(netip.MustParseAddr("10.0.0.1"), true) {
		t.Fatal("loopback permission broadened")
	}
}

func TestURLPolicyRejectsMetadataAndInvalidPorts(t *testing.T) {
	policy := URLPolicy{MaxBytes: 2048, RequirePath: true}
	for _, raw := range []string{"", "https://8.8.8.8", "https://user:SECRET@8.8.8.8/v1", "https://8.8.8.8/v1?token=SECRET", "https://8.8.8.8/v1?", "https://8.8.8.8/v1#fragment", "https://8.8.8.8/v%31", "https://8.8.8.8:000/v1", "https://8.8.8.8:65536/v1", "https://10.0.0.1/v1", "http://8.8.8.8/v1"} {
		if _, err := ParseURL(raw, policy); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://8.8.8.8/v1", "https://8.8.8.8:000443/v1"} {
		if _, err := ParseURL(raw, policy); err != nil {
			t.Fatal(err)
		}
	}
	policy.AllowLoopback = true
	if _, err := ParseURL("http://127.0.0.1/v1", policy); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseURL("http://localhost/v1", policy); err == nil {
		t.Fatal("HTTP hostname inferred loopback permission")
	}
	policy.MaxBytes = 5
	if _, err := ParseURL("https://8.8.8.8/v1", policy); err == nil {
		t.Fatal("byte limit ignored")
	}
}

func TestDialRejectsNumericPrivateAddressBeforeConnecting(t *testing.T) {
	// A nil actual dialer would panic if rejection happened after connecting.
	_, err := (dialer{}).dial(context.Background(), "tcp", "10.0.0.1:443")
	if policyError, ok := errors.AsType[*Error](err); !ok || policyError.Code != "address_not_permitted" {
		t.Fatal(err)
	}
	if _, err := (dialer{}).dial(context.Background(), "tcp", "invalid-address"); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestTransportOwnsTrustPoolAndDisablesAmbientRouting(t *testing.T) {
	roots := x509.NewCertPool()
	transport := Transport(time.Second, false, roots)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.TLSClientConfig.RootCAs == roots || !transport.TLSClientConfig.RootCAs.Equal(roots) {
		t.Fatal("transport shares trust state or ambient routing")
	}
}

func TestResolverAdmitsOnlyActualAnswersAndHandlesCancellation(t *testing.T) {
	ips, err := resolvedAddresses(t.Context(), "localhost")
	if err != nil || len(ips) == 0 {
		t.Fatal(ips, err)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			t.Fatal("localhost resolved outside loopback", ip)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolvedAddresses(ctx, "cancelled.example.invalid"); err == nil {
		t.Fatal("cancelled resolution accepted")
	}
}

func TestDeprecatedIPv6SiteLocalIsDeniedByEveryBoundary(t *testing.T) {
	for _, raw := range []string{"fec0::", "fec0::1", "fed0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		for _, loopback := range []bool{false, true} {
			address := netip.MustParseAddr(raw)
			if PermittedIP(address, loopback) {
				t.Errorf("site-local address admitted: %s loopback=%t", raw, loopback)
				continue
			}
			if _, err := ParseURL("https://["+raw+"]/v1", URLPolicy{MaxBytes: 2048, AllowLoopback: loopback}); err == nil {
				t.Fatalf("URL policy admitted %s", raw)
			}
			// A nil actual dialer proves rejection precedes any connection attempt.
			_, err := (dialer{allowLoopback: loopback}).dial(context.Background(), "tcp", net.JoinHostPort(raw, "443"))
			if policyError, ok := errors.AsType[*Error](err); !ok || policyError.Code != "address_not_permitted" {
				t.Fatalf("dial policy admitted %s: %v", raw, err)
			}
		}
	}
}
