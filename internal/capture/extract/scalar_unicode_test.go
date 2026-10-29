package extract_test

import (
	"context"
	"testing"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/extract"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

func TestJSONTreeAndStreamShareScalarUnicodeContract(t *testing.T) {
	for _, tc := range []struct {
		name, token, decoded string
		invalid              bool
	}{
		{name: "empty", token: `""`, decoded: "", invalid: false},
		{name: "nul", token: `"\u0000"`, decoded: "\x00", invalid: false},
		{name: "surrogate-pair", token: `"\ud800\udc00"`, decoded: "𐀀", invalid: false},
		{name: "maximum-pair", token: `"\udbff\udfff"`, decoded: "\U0010ffff", invalid: false},
		{name: "replacement-literal", token: `"�"`, decoded: "�", invalid: false},
		{name: "replacement-escape", token: `"\ufffd"`, decoded: "�", invalid: false},
		{name: "escaped-backslash", token: `"\\ud800"`, decoded: `\ud800`, invalid: false},
		{name: "high-surrogate", token: `"\ud800"`, decoded: "", invalid: true},
		{name: "low-surrogate", token: `"\udfff"`, decoded: "", invalid: true},
		{name: "wrong-pair", token: `"\ud800\u0061"`, decoded: "", invalid: true},
		{name: "raw-invalid-utf8", token: "\"\xff\"", decoded: "", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `["retained-prefix",` + tc.token + `]`
			_, treeErr := jsonconfig.Parse(context.Background(), text)
			if (treeErr != nil) != tc.invalid {
				t.Fatalf("tree Unicode contract changed: %v", treeErr)
			}
			result, err := extract.Expand(context.Background(), []artifact.File{artifact.NewFile("tokens.json", []byte(text), false)}, report.DefaultExtractionLimits())
			if err != nil {
				t.Fatal(err)
			}
			wantCount, wantStatus := 2, "completed"
			if tc.invalid {
				wantCount, wantStatus = 1, "failed"
			}
			if len(result.Files) != wantCount || result.Files[0].Content() != "retained-prefix" || len(result.Report.Steps) != 1 || result.Report.Steps[0].Status != wantStatus {
				t.Fatalf("stream lost validated prefix or accepted invalid scalar: %+v", result.Report)
			}
			if !tc.invalid && result.Files[1].Content() != tc.decoded {
				t.Fatalf("decoded scalar changed: got %q want %q", result.Files[1].Content(), tc.decoded)
			}
		})
	}
}
