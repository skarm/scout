//go:build !coreonly && !cgo

package frontend

import (
	"context"
)

func pythonAvailable() bool { return false }
func parsePython(context.Context, string) (*Node, error) {
	return nil, &Failure{Category: "unavailable"}
}
