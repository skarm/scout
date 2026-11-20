package modconfig_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/modconfig"
)

func TestParseModuleAndRequirement(t *testing.T) {
	for _, tc := range []struct{ name, requirement string }{
		{name: "unquoted", requirement: "example.com/dependency"},
		{name: "quoted", requirement: `"example.com/dependency"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := modconfig.Parse(t.Context(), "module example.com/skill\ngo 1.23\nrequire "+tc.requirement+" v1.2.3\n")
			if err != nil || f == nil {
				t.Fatalf("Parse() = %v, %v; want a module file", f, err)
			}
			if f.Module == nil || f.Module.Mod.Path != "example.com/skill" {
				t.Errorf("module = %+v; want example.com/skill", f.Module)
			}
			if f.Go == nil || f.Go.Version != "1.23" {
				t.Errorf("go directive = %+v; want 1.23", f.Go)
			}
			if len(f.Require) != 1 {
				t.Fatalf("requirement count = %d; want 1", len(f.Require))
			}
			if got := f.Require[0].Mod; got.Path != "example.com/dependency" || got.Version != "v1.2.3" {
				t.Errorf("requirement = %+v; want example.com/dependency v1.2.3", got)
			}
		})
	}
}

func TestParseRejectsInvalidModuleFiles(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
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
			f, err := modconfig.Parse(t.Context(), tc.text)
			var e *modconfig.Error
			if !errors.As(err, &e) || e.Code != tc.code || f != nil {
				t.Fatalf("Parse() = %v, %v; want nil and *modconfig.Error with code %q", f, err, tc.code)
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Errorf("Parse() error contains source text: %v", err)
			}
		})
	}
}

func TestParseCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if f, err := modconfig.Parse(ctx, "module example.com/skill\n"); f != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Parse() = %v, %v; want nil and context.Canceled", f, err)
	}
}

func FuzzGoMod(f *testing.F) {
	f.Add("module example.com/skill\nrequire example.com/d v1.2.3\n")
	f.Add("module example.com/skill\nrequire example.com/d v1.2.3\nrequire example.com/d v1.2.4\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 32<<10 {
			return
		}
		m, err := modconfig.Parse(t.Context(), s)
		if err != nil {
			if m != nil {
				t.Fatalf("Parse() returned a partial module file with error %v", err)
			}
			return
		}
		if m == nil || m.Module == nil {
			t.Fatal("Parse() succeeded without a module directive")
		}
		formatted, err := m.Format()
		if err != nil {
			t.Fatalf("format parsed module file: %v", err)
		}
		if len(formatted) > modconfig.MaxBytes {
			return
		}
		reparsed, err := modconfig.Parse(t.Context(), string(formatted))
		if err != nil || reparsed == nil {
			t.Fatalf("parse formatted module file: tree=%v err=%v", reparsed, err)
		}
		again, err := reparsed.Format()
		if err != nil || !bytes.Equal(again, formatted) {
			t.Fatalf("formatting after reparse = %q, %v; want %q, nil", again, err, formatted)
		}
	})
}
