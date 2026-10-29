//go:build coreonly || !cgo

package signatures

import (
	"context"
	"errors"
)

func Backend() Capability {
	return Capability{
		Name:           "yara-x",
		BindingVersion: "not-linked",
		NativeVersion:  "not-linked",
		Available:      false,
		Reason:         "coreonly build or CGO disabled; no substitute engine",
	}
}

func compileRules(context.Context, string) (compiledEngine, error) {
	return nil, errors.New("YARA-X is not linked")
}
