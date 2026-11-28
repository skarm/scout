package fetch

import (
	"bytes"
	"context"
	"net/http"

	"github.com/skarm/scout/internal/netpolicy"
)

const (
	codeDownloadOptionsNotApplicable = "download_options_not_applicable"
	codeRequestByteLimit             = "request_byte_limit"
)

const (
	maxAPIRequestBytes = 256 << 10
)

// PostJSON makes an explicitly authorized API call with the same DNS/address,
// redirect, TLS and response bounds as the downloader. It never sends credentials
// or inherits proxies. Callers MUST separately obtain permission to send the body.
func PostJSON(ctx context.Context, endpoint string, body []byte, o Options) ([]byte, error) {
	if ctx == nil {
		return nil, fail(codeNilContext)
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
		return nil, fail(codeInvalidRequest)
	}

	req.Header.Set(netpolicy.HeaderContentType, netpolicy.JSONMediaType)
	req.Header.Set(netpolicy.HeaderAccept, netpolicy.JSONMediaType)
	req.Header.Set(netpolicy.HeaderAcceptEncoding, netpolicy.IdentityEncoding)

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
		return fail(codeNetworkPermissionRequired)
	}

	if o.Git || o.GitAuth != nil || o.Revision != "" || o.ExpectedSHA256 != "" {
		return fail(codeDownloadOptionsNotApplicable)
	}

	if bodyBytes > maxAPIRequestBytes {
		return fail(codeRequestByteLimit)
	}

	return nil
}
