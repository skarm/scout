//go:build !coreonly && cgo

package maintenance

import (
	"context"
	"errors"
	"io"
)

type TestSiteForTest = testSite

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

func NormalizeScoutComparisonForTest(data []byte, code int) (int, error) {
	normalized, err := normalizeComparisonResult(object{}, "scout", processResult{Stdout: data, Code: code})
	if err != nil {
		return 0, err
	}
	findings, ok := normalized[findingsKey].([]object)
	if !ok {
		return 0, errors.New("comparison findings have an unexpected type")
	}
	return len(findings), nil
}

func ValidateScoutDocumentForTest(data []byte) error {
	_, err := decodeScoutDocument(data)
	return err
}

func LocateTestForTest(ctx context.Context, upstream, id string) (TestSiteForTest, error) {
	a := adjudicator{upstream: upstream, cachedSites: map[string]testSite{}}
	return a.locateTest(ctx, id)
}
