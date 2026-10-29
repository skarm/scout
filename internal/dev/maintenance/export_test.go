//go:build !coreonly && cgo

package maintenance

import (
	"context"
	"io"

	"github.com/skarm/scout/report"
)

// These bridges expose maintenance internals only in the native test binary.
func CheckKnowledgeRuntimeForTest(ctx context.Context, binary, output string, w io.Writer) error {
	root, err := projectRoot()
	if err != nil {
		return err
	}
	o := options{root: root, values: map[string]*string{"binary": &binary, "output": &output}}
	return checkKnowledgeRuntime(ctx, o, w)
}

func InvokeCLIForTest(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
	return invokeCLI(ctx, binary, args...)
}

func DecodeScoutDocumentForTest(data []byte) (report.Document, error) {
	return decodeScoutDocument(data)
}
