package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/skarm/scout/internal/netpolicy"
)

// Download and exact API queries share transport admission and bounded reads.
// Their callers retain the separate payload/checksum and API response policies.
func downloadResponse(ctx context.Context, req *http.Request, options Options) ([]byte, error) {
	client, transport := newClient(options)
	defer transport.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return nil, requestFailure(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }() // Read/admission errors determine the response; closing only releases the transport.

	if err := validateResponseHeaders(resp, options.MaxBytes); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, options.MaxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}

		return nil, fail("body_read_failed")
	}

	if int64(len(data)) > options.MaxBytes {
		return nil, fail("byte_limit")
	}

	return data, nil
}

func requestFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if typed, ok := errors.AsType[*Error](err); ok {
		return typed
	}

	if typed, ok := errors.AsType[*netpolicy.Error](err); ok {
		return fail(typed.Code)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	return fail("request_failed")
}

func validateResponseHeaders(resp *http.Response, maxBytes int64) error {
	if resp.StatusCode != http.StatusOK {
		return fail("http_status")
	}

	if !netpolicy.IdentityContentEncoding(resp.Header) {
		return fail("content_encoding_refused")
	}

	if resp.ContentLength > maxBytes {
		return fail("byte_limit")
	}

	return nil
}
