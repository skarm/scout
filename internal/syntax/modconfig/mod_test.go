package modconfig_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/modconfig"
)

func TestParser(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
		{name: "valid", text: "module example.com/skill\ngo 1.23\nrequire example.com/dependency v1.2.3\n", code: ""},
		{name: "quoted", text: "module example.com/skill\nrequire \"example.com/dependency\" v1.2.3\n", code: ""},
		{
			name: "duplicate",
			text: "module example.com/skill\nrequire example.com/dependency v1.0.0\nrequire example.com/dependency v1.1.0\n",
			code: "duplicate_requirement",
		},
		{
			name: "duplicate-replace",
			text: "module example.com/skill\nreplace example.com/dependency => ../one\nreplace example.com/dependency => ../two\n",
			code: "duplicate_replacement",
		},
		{name: "missing-module", text: "go 1.23\n", code: "missing_module"},
		{name: "unknown", text: "module example.com/skill\nSENTINEL unknown\n", code: "syntax_error"},
		{name: "null", text: "module example.com/skill\x00", code: "invalid_encoding"},
		{name: "limit", text: strings.Repeat("x", modconfig.MaxBytes+1), code: "byte_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := modconfig.Parse(context.Background(), tc.text)
			var e *modconfig.Error
			if tc.code == "" {
				if err != nil || f == nil {
					t.Fatal(err)
				}
			} else if !errors.As(err, &e) || e.Code != tc.code || f != nil {
				t.Fatalf("f=%v err=%v", f, err)
			}
			if strings.Contains(strings.TrimSpace(stringError(err)), "SENTINEL") {
				t.Fatal("source leak")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := modconfig.Parse(ctx, "module x"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzGoMod(f *testing.F) {
	f.Add("module example.com/skill\nrequire example.com/d v1.2.3\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 32<<10 {
			return
		}
		m, err := modconfig.Parse(context.Background(), s)
		if err == nil && m == nil {
			t.Fatal("nil parsed tree")
		}
	})
}

func stringError(e error) string {
	if e != nil {
		return e.Error()
	}
	return ""
}
