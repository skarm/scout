package fetch

import (
	"bytes"
	"context"
	"net/http"
)

// PostJSON makes an explicitly authorized API call with the same DNS/address,
// redirect, TLS and response bounds as the downloader. It never sends credentials
// or inherits proxies. Callers MUST separately obtain permission to send the body.
func PostJSON(ctx context.Context, endpoint string, body []byte, o Options) ([]byte, error) {
	if ctx == nil {
		return nil, fail("nil_context")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := o.validateAPIRequest(len(body)); err != nil {
		return nil, err
	}

	u, err := parseURL(endpoint, o.AllowLoopback)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fail("invalid_request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")

	data, err := downloadResponse(ctx, req, o)
	if err != nil {
		return nil, err
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

func (o Options) validateAPIRequest(bodyBytes int) error {
	if err := o.Validate(); err != nil {
		return err
	}

	if !o.Enabled {
		return fail("network_permission_required")
	}

	if o.Revision != "" || o.ExpectedSHA256 != "" {
		return fail("download_options_not_applicable")
	}

	if bodyBytes > 256<<10 {
		return fail("request_byte_limit")
	}

	return nil
}
