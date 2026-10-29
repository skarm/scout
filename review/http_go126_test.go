//go:build !go1.27

package review_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"
)

// Go 1.26 supports the same CA/hostname checks using a loopback fixture.
func localTLSDialer(t *testing.T, certificate tls.Certificate) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	server := httptest.NewUnstartedServer(tlsFixtureHandler(t))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
}
