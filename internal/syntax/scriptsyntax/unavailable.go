//go:build coreonly || !cgo

package scriptsyntax

import (
	"context"
	"errors"
)

func Available() bool { return false }

func parse(context.Context, string, string) (Tree, error) {
	return Tree{}, errors.New("script backend unavailable")
}
