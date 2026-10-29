//go:build go1.27

package review_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func localTLSDialer(t *testing.T, certificate tls.Certificate) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	server := httptest.NewTestServer(t, tlsFixtureHandler(t))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	fixture := server.Client().Transport.(*http.Transport)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := fixture.DialTLSContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// No handshake has run. Return the underlying in-memory connection so
		// the provider's original transport performs its own TLS verification.
		return conn.(*tls.Conn).NetConn(), nil
	}
}
