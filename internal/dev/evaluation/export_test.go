package evaluation

import (
	"context"
	"os"

	"github.com/skarm/scout/fetch"
)

func AddForTest(m *Metrics, r Result) { add(m, r) }
func FinishForTest(m *Metrics)        { finish(m) }

func VerifyFileMetadataForTest(file File, info os.FileInfo) error {
	return verifyFileMetadata(file, info)
}

func WritePackageFileForTest(name string, file File) error {
	return writePackageFile(name, file)
}

func VerifyPackageTreeForTest(ctx context.Context, root string, files []File) error {
	return verifyPackageTree(ctx, root, files)
}

func CollectFileForTest(ctx context.Context, file CollectionFile, download fetch.Options, limit int64) ([]byte, error) {
	data, _, err := collectFile(ctx, file, "", download, limit)
	return data, err
}
