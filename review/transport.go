package review

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/skarm/scout/internal/netpolicy"
)

// readResponse owns the transport contract for every provider protocol. Provider
// decoders only receive a bounded, uncompressed JSON response with status 200.
func (p *HTTPProvider) readResponse(ctx context.Context, req *http.Request) ([]byte, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, responseFailure(ctx, err)
	}
	// Closing a read-only response releases the connection; read/header errors
	// remain the transport result even if cleanup also fails.
	defer func() { _ = resp.Body.Close() }()

	if err := validateResponseHeaders(resp, p.maxBytes); err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(p.maxBytes)+1))
	if err != nil {
		return nil, transportError("response_read_failed")
	}

	if len(raw) > p.maxBytes {
		return nil, transportError("response_limit")
	}

	return raw, nil
}

func responseFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if typed, ok := errors.AsType[*TransportError](err); ok {
		return typed
	}

	if typed, ok := errors.AsType[*netpolicy.Error](err); ok {
		return transportError(typed.Code)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	return transportError("http_failed")
}

func validateResponseHeaders(resp *http.Response, maxBytes int) error {
	if resp.StatusCode != http.StatusOK {
		return &TransportError{Code: "http_status", Status: resp.StatusCode}
	}

	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return transportError("content_type")
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return transportError("content_encoding")
	}

	if resp.ContentLength > int64(maxBytes) {
		return transportError("response_limit")
	}

	return nil
}
