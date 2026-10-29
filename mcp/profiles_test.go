package mcp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/mcp"
	"github.com/skarm/scout/report"
)

func TestMCPOperatorProfileCannotBeDowngradedByTool(t *testing.T) {
	scanner, err := scout.New(context.Background(), scout.DefaultOptions())
	if !frontend.BackendFor("python").Available {
		if err == nil {
			if err := scanner.Close(); err != nil {
				t.Error(err)
			}
			t.Fatal("unavailable standard profile accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Error(err)
		}
	}()
	server, err := mcp.New(scanner, defaultGate(t), mcp.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	upload := base64.StdEncoding.EncodeToString([]byte("plain text"))
	call := func(id int, extra string) string {
		args := `{"name":"readme.txt","data_base64":"` + upload + `"` + extra + `}`
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "scan_skill",
				"arguments": json.RawMessage(args),
			},
		})
		return string(b)
	}
	input := strings.Join([]string{initMessage, readyMessage, call(2, ""), call(3, `,"profile":"basic"`)}, "\n") + "\n"
	var out bytes.Buffer
	if err := server.Serve(context.Background(), io.NopCloser(strings.NewReader(input)), &out); err != nil {
		t.Fatal(err)
	}
	for line := range bytes.SplitSeq(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
		var r struct {
			ID     int `json:"id"`
			Result struct {
				IsError bool            `json:"isError"`
				Report  report.Document `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r.ID == 2 && r.Result.Report.Run.Plan.Name != "standard" {
			t.Fatal("operator profile lost", out.String())
		}
		if r.ID == 3 && !r.Result.IsError {
			t.Fatal("tool changed trusted profile", out.String())
		}
	}
}
