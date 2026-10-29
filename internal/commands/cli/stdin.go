package cli

import (
	"context"
	"io"
	"os"

	"github.com/skarm/scout"
)

// CLI scan exclusively reads stdin for this operation; ownership stays with
// the caller. Waiting for readable bytes must participate in its context.
type stdinFile struct{ file *os.File }

func stdinReaderTarget(name string, input io.Reader) scout.Target {
	if file, ok := input.(*os.File); ok {
		return scout.ReaderContext(name, stdinFile{file: file})
	}

	return scout.Reader(name, input)
}

func (s stdinFile) ReadContext(ctx context.Context, p []byte) (int, error) {
	return readStdinFile(ctx, s.file, p)
}
