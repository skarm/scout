package review

import (
	"net/http"
	"time"
)

func SignBedrockForTest(r *http.Request, body []byte, o MessagesOptions, now time.Time) {
	signBedrock(r, body, o, now)
}
