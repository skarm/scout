package review

import (
	"net/http"
	"time"
)

func SignBedrockForTest(r *http.Request, body []byte, o MessagesOptions, now time.Time) {
	signBedrock(r, body, o, now)
}

func HTTPClientForTest(p *HTTPProvider) *http.Client { return p.client }

func MessagesHTTPClientForTest(p *MessagesProvider) *http.Client { return p.base.client }
