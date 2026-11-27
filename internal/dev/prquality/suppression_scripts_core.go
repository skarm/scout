//go:build coreonly || !cgo

package main

import (
	"context"
	"errors"
)

func scanScriptSuppressionSyntax(context.Context, string, []byte) (suppressionSyntax, error) {
	return suppressionSyntax{}, errors.New("JavaScript, TypeScript and Python lint directive analysis requires CGO and native parsers")
}
