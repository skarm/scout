// Package netpolicy owns the address, URL and DNS rules shared by explicit
// outbound transports. Protocols retain their own credentials and payloads.
package netpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//nolint:gochecknoglobals // Read-only denied network prefixes shared by every network boundary.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("fec0::/10"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

type Error struct{ Code string }

type URLPolicy struct {
	MaxBytes                   int
	AllowLoopback, RequirePath bool
}

type dialer struct {
	dialer        *net.Dialer
	allowLoopback bool
}

func PermittedIP(address netip.Addr, allowLoopback bool) bool {
	a := address.Unmap()
	if !a.IsValid() || a.Zone() != "" {
		return false
	}

	if a.IsLoopback() {
		return allowLoopback
	}

	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return false
	}

	for _, prefix := range deniedPrefixes {
		if prefix.Contains(a) {
			return false
		}
	}

	return true
}

func ParseURL(raw string, policy URLPolicy) (*url.URL, error) {
	if len(raw) > policy.MaxBytes {
		return nil, fail("invalid_url")
	}

	u, err := url.Parse(raw)
	if err != nil || !validURLShape(u, policy.RequirePath) {
		return nil, fail("invalid_url")
	}

	if err := validateAddress(u, policy.AllowLoopback); err != nil {
		return nil, err
	}

	return u, nil
}

// Transport checks every DNS answer and then dials a checked numeric address;
// no second DNS lookup can select a different address. Ambient proxies and
// compression are disabled. The caller supplies its own redirect policy.
func Transport(timeout time.Duration, allowLoopback bool, roots *x509.CertPool) *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if roots != nil {
		tlsConfig.RootCAs = roots.Clone()
	}

	d := dialer{dialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}, allowLoopback: allowLoopback}

	return &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsConfig,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    timeout,
		ForceAttemptHTTP2:      false,
		DialContext:            d.dial,
	}
}

func (e *Error) Error() string { return "network policy: " + e.Code }
func fail(code string) error   { return &Error{Code: code} }

func validateAddress(u *url.URL, allowLoopback bool) error {
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, "%\\\x00\r\n") {
		return fail("invalid_url")
	}

	ip, iperr := netip.ParseAddr(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && allowLoopback && iperr == nil && ip.Unmap().IsLoopback()) {
		return fail("https_required")
	}

	if iperr == nil && !PermittedIP(ip, allowLoopback) {
		return fail("address_not_permitted")
	}

	return validatePort(u.Port())
}

func validatePort(port string) error {
	if port != "" {
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return fail("invalid_port")
		}
	}

	return nil
}

func validURLShape(u *url.URL, requirePath bool) bool {
	return u != nil && u.Host != "" && u.Opaque == "" && withoutURLMetadata(u) && u.RawPath == "" && (!requirePath || u.Path != "")
}

func withoutURLMetadata(u *url.URL) bool {
	return u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == ""
}

func (d dialer) dial(ctx context.Context, _ string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fail("invalid_address")
	}

	ips, err := resolvedAddresses(ctx, host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if !PermittedIP(ip, d.allowLoopback) {
			return nil, fail("address_not_permitted")
		}
	}

	for _, ip := range ips {
		connection, err := d.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return connection, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fail("connection_failed")
}

func resolvedAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 || len(ips) > 64 {
		return nil, fail("dns_failed")
	}

	return ips, nil
}
