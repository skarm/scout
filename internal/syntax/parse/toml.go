package parse

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
)

// NativeTOML provides the bounded TOML fallback for recognized host config
// files in builds without an operator-selected TOML frontend.
func NativeTOML() Backend { return nativeTOMLBackend{} }

type nativeTOMLBackend struct{}

func (nativeTOMLBackend) Descriptor() Descriptor {
	return Descriptor{ID: "native-toml", Language: language.TOML, Version: "1", UnitBytes: jsonconfig.MaxBytes, ScanBytes: MaxScanBytes}
}

func (nativeTOMLBackend) Parse(ctx context.Context, view source.View) (any, error) {
	root, err := jsonconfig.ParseTOML(ctx, view.Text())
	if err != nil {
		if failure, ok := errors.AsType[*jsonconfig.Error](err); ok && strings.HasSuffix(failure.Code, "_limit") {
			return nil, &Failure{Category: CodeLimit}
		}

		return nil, err
	}

	return JSONTree{Root: root, Format: language.TOML}, nil
}
