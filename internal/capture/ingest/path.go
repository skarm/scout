package ingest

import "github.com/skarm/scout/internal/capture/archiveutil"

// ValidatePath applies the portable path policy shared by file capture and archives.
func ValidatePath(name string, maxBytes, maxDepth int) error {
	return archiveutil.ValidatePath(name, maxBytes, maxDepth)
}
