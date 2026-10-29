package parse

import (
	"context"

	"github.com/skarm/scout/internal/buildinfo"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/syntax/sqlsyntax"
)

const scriptAdapterVersion = "1"

type (
	scriptBackend struct{ language string }
	sqlBackend    struct{}
)

func languageBackends() []Backend {
	out := []Backend{goBackend{}, shellBackend{}, jsonBackend{}, goModBackend{}, sqlBackend{}}
	if scriptsyntax.Available() {
		out = append(out, scriptBackend{language: language.JavaScript}, scriptBackend{language: language.TypeScript})
	}

	return out
}

func (b scriptBackend) Descriptor() Descriptor {
	version := buildinfo.ModuleVersion("github.com/tree-sitter/tree-sitter-" + b.language)

	return Descriptor{
		ID:        "tree-sitter-" + b.language,
		Language:  b.language,
		Version:   version + "-adapter" + scriptAdapterVersion,
		UnitBytes: scriptsyntax.MaxBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (b scriptBackend) Parse(ctx context.Context, v source.View) (any, error) {
	return scriptsyntax.Parse(ctx, b.language, v.Text())
}

func (sqlBackend) Descriptor() Descriptor {
	return Descriptor{
		ID:        "sql-bounded-tokens",
		Language:  language.SQL,
		Version:   "1",
		UnitBytes: sqlsyntax.MaxBytes,
		ScanBytes: MaxScanBytes,
	}
}

func (sqlBackend) Parse(ctx context.Context, v source.View) (any, error) {
	tree, err := sqlsyntax.Parse(ctx, v.Text())
	if err == nil && tree.Limited {
		err = &Failure{Category: "unsupported_syntax"}
	}

	return tree, err
}
