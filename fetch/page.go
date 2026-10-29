package fetch

import (
	"context"
	"net/http"
	"net/url"
)

// GetPage requests a bounded JSON API page. The endpoint is operator-owned;
// the only server-controlled query value is an encoded pagination cursor.
// It uses the same no-redirect, no-proxy and checked-DNS transport as Get.
func GetPage(ctx context.Context, endpoint, cursor string, o Options) ([]byte, error) {
	if ctx == nil {
		return nil, fail("nil_context")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := o.validateAPIRequest(0); err != nil {
		return nil, err
	}

	if len(cursor) > 2048 {
		return nil, fail("cursor_limit")
	}

	u, err := parseURL(endpoint, o.AllowLoopback)
	if err != nil {
		return nil, err
	}

	if cursor != "" {
		u.RawQuery = url.Values{"cursor": {cursor}}.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fail("invalid_request")
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")

	return downloadResponse(ctx, req, o)
}
