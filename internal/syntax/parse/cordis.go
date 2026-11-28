package parse

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/source"
)

// CordisYAML provides passive parsing of recognized DeepSeek Harness files.
func CordisYAML() Backend { return cordisYAMLBackend{} }

type cordisYAMLBackend struct{}

func (cordisYAMLBackend) Descriptor() Descriptor {
	return Descriptor{ID: "cordis-yaml", Language: language.YAML, Version: "1", UnitBytes: jsonconfig.MaxBytes, ScanBytes: MaxScanBytes}
}

func (cordisYAMLBackend) Parse(ctx context.Context, view source.View) (any, error) {
	root, err := jsonconfig.ParseCordisYAML(ctx, view.Text())
	if err != nil {
		if failure, ok := errors.AsType[*jsonconfig.Error](err); ok && strings.HasSuffix(failure.Code, "_limit") {
			return nil, &Failure{Category: CodeLimit}
		}

		return nil, err
	}

	return JSONTree{Root: root, Format: language.YAML}, nil
}
